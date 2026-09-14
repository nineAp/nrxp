//! Оркестрация сессии: от хендшейка до пер-кадровой аутентификации.
//!
//! Файл связывает воедино [`ecdh`](super::ecdh) и [`hkdf`](super::hkdf) и делится
//! на две фазы, отражённые в коде комментариями-разделителями:
//!
//! 1. **Handshake / генерация ключей** ([`SaltPair`], [`SessionKeys`]).
//!    Стороны обмениваются солью и публичными ключами X25519 (внутри TLS-кадров
//!    `ClientHello`/`ServerHello`), затем независимо выводят один и тот же набор
//!    ключей: AEAD-ключ+IV на каждое направление и общий `auth_key`.
//!
//! 2. **Data phase / аутентификация кадров** ([`SessionAuth`]).
//!    Лёгкая копируемая структура с одним лишь `auth_key`, которую забирают
//!    кодеки. Считает и проверяет TOTP-подобный тег, привязанный ко времени, —
//!    защита от replay-атак на уровне DPI.
//!
//! ## Симметрия ролей
//!
//! Чтобы обе стороны вывели идентичные ключи, важен порядок конкатенации соли и
//! назначение направлений. Инициатор (клиент) и ответчик (сервер) собирают
//! «полную соль» в зеркальном порядке (см. [`SaltPair::get_total`]), а в
//! [`SessionKeys::generate_keys`] флаг `is_server` решает, какой из выведенных
//! ключей идёт на tx, а какой на rx.

use netrunner_logger::{AppError, ERR_NET_TLS_TAMPER};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use x25519_dalek::PublicKey;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{ecdh::ECDH, hkdf::HKDF, identity::Identity},
    net_consts::{AUTH_TIME_STEP, AUTH_WINDOW_SIZE},
    tlseng::ExtensionStack,
};

/// Доменный ярлык, который уходит в `ikm` вместе с результатами DH.
///
/// Гарантирует, что PRK схемы v3 (два DH) не может совпасть с PRK старой схемы
/// v2 (один DH) даже теоретически: у них разный входной материал по построению,
/// а не «просто разной длины».
const IKM_DOMAIN_V3: &[u8] = b"nrxp-v3-static-dh";

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use aead::{rand_core::RngCore, OsRng};

// ==========================================
// 1. HANDSHAKE (Генерация ключей)
// ==========================================

/// Пара солей сторон, используемая как salt в HKDF-Extract.
///
/// Каждая сторона генерирует случайную локальную соль и узнаёт удалённую из
/// хендшейка. Итоговая соль детерминированно собирается из обеих половин в
/// порядке, зависящем от роли (см. [`get_total`](SaltPair::get_total)), так что
/// клиент и сервер приходят к одному значению.
pub(crate) struct SaltPair {
    /// Своя случайная соль (32 байта), уходит удалённой стороне.
    local_salt: [u8; 32],
    /// Соль удалённой стороны; нули до вызова [`set_remote_salt`](SaltPair::set_remote_salt).
    remote_salt: [u8; 32],
    /// Роль: `true` у инициатора (клиента) — определяет порядок конкатенации.
    is_initiator: bool,
}

impl SaltPair {
    pub(crate) fn new(is_initiator: bool) -> Self {
        let mut local_salt = [0u8; 32];
        OsRng.fill_bytes(&mut local_salt);
        Self {
            local_salt,
            remote_salt: [0; 32],
            is_initiator,
        }
    }

    pub(crate) fn get_local(&self) -> [u8; 32] {
        self.local_salt
    }

    pub(crate) fn set_remote_salt(&mut self, salt: [u8; 32]) {
        self.remote_salt = salt
    }

    /// Собирает 64-байтовую «полную соль» для HKDF.
    ///
    /// Порядок зеркальный по ролям: инициатор кладёт `local || remote`, ответчик —
    /// `remote || local`. Благодаря этому обе стороны получают **одинаковый**
    /// буфер соли, хотя «локальное» и «удалённое» у них поменяны местами.
    pub(crate) fn get_total(&self) -> [u8; 64] {
        let mut salt = [0u8; 64];
        if self.is_initiator {
            salt[..32].copy_from_slice(&self.local_salt);
            salt[32..].copy_from_slice(&self.remote_salt);
            salt
        } else {
            salt[..32].copy_from_slice(&self.remote_salt);
            salt[32..].copy_from_slice(&self.local_salt);
            salt
        }
    }
}

/// `(tx_key, tx_iv, rx_key, rx_iv)` — выведенные AEAD-ключи уже с учётом роли
/// (клиент/сервер), готовые отдать напрямую в
/// [`ChaChaCipher::set_keys`](super::chacha::ChaChaCipher::set_keys).
type DirectionalAeadKeys = ([u8; 32], [u8; 12], [u8; 32], [u8; 12]);

/// Полное состояние криптографического хендшейка одной стороны.
///
/// Держит свою соль, эфемерный ECDH и — после [`update_keys`](SessionKeys::update_keys) —
/// выведенные ключи (см. [`DirectionalAeadKeys`]).
pub struct SessionKeys {
    /// Пара солей (локальная + удалённая) для HKDF.
    salt: SaltPair,
    /// Эфемерный ключ X25519; уничтожается сразу после вывода ключей сессии.
    ecdh: ECDH,
    /// Ключ для time-based аутентификации кадров (HMAC). Заполняется в HKDF-фазе.
    auth_key: [u8; 32],
    /// Выведенные AEAD-параметры `(tx_key, tx_iv, rx_key, rx_iv)`; `None` до хендшейка.
    current_aead: Option<DirectionalAeadKeys>,
    /// Долговременные учётные данные ноды (см. [`Identity`]). `None` — старая
    /// анонимная схема v2: нода без настроенных ключей или клиент, которому
    /// бэкенд их ещё не выдал.
    identity: Option<Identity>,
    /// Версия протокола, заявленная противоположной стороной. У клиента это
    /// его собственная заявленная версия (он и решает, по какой схеме идти), у
    /// сервера проставляется из `session_id[0]` разобранного `ClientHello`
    /// до вывода ключей — см. [`SessionKeys::set_peer_version`].
    peer_version: u8,
    /// `PRK` того же HKDF-extract, что породил `current_aead` (см.
    /// [`generate_keys`](Self::generate_keys)). `None` до хендшейка.
    ///
    /// Единственный потребитель — [`crate::crypto::datagram_keys`]: UDP-нога
    /// не гоняет второй хендшейк, а выводит свой ключевой материал из этого
    /// же секрета по отдельным HKDF-меткам. Хранить именно `PRK`, а не
    /// исходный `ikm`/ECDH-секрет — важно для forward secrecy: `ikm`
    /// уничтожается сразу после [`generate_keys`], а `PRK` — уже необратимая
    /// (в криптографическом смысле) функция от него, как и любой другой
    /// производный ключ сессии, которые точно так же живут до `Drop`.
    datagram_root: Option<Zeroizing<[u8; 32]>>,
}

impl SessionKeys {
    /// Старая анонимная схема (протокол v2): без учётных данных ноды.
    pub(crate) fn new(is_initiator: bool) -> Self {
        Self {
            salt: SaltPair::new(is_initiator),
            ecdh: ECDH::new(),
            auth_key: [0u8; 32],
            current_aead: None,
            identity: None,
            peer_version: crate::net_consts::PROTOCOL_VERSION_ANONYMOUS,
            datagram_root: None,
        }
    }

    /// Аутентифицированная схема (протокол v3): в хендшейк входят секрет ноды
    /// (тег `ClientHello`) и её статический ключ (второй DH).
    pub(crate) fn with_identity(is_initiator: bool, identity: Identity) -> Self {
        // Не `..Self::new(is_initiator)`: functional record update вытаскивает
        // поля из временного значения, а у типа с `Drop` (см. impl ниже —
        // затирание ключей) это запрещено (E0509). Присваиваем поверх.
        let mut keys = Self::new(is_initiator);
        keys.identity = Some(identity);
        keys.peer_version = crate::net_consts::PROTOCOL_VERSION;
        keys
    }

    /// Версия протокола, которую эта сторона заявляет в `session_id[0]`.
    ///
    /// Клиент **без** учётных данных обязан заявлять v2: иначе нода станет
    /// проверять у него ключевой тег, которого он посчитать не может.
    pub(crate) fn claimed_version(&self) -> u8 {
        if self.identity.is_some() {
            crate::net_consts::PROTOCOL_VERSION
        } else {
            crate::net_consts::PROTOCOL_VERSION_ANONYMOUS
        }
    }

    /// Сервер: зафиксировать версию, заявленную клиентом, до вывода ключей.
    pub(crate) fn set_peer_version(&mut self, version: u8) {
        self.peer_version = version;
    }

    /// Идти ли по схеме v3 (второй DH + ключевой тег хендшейка).
    ///
    /// Обе стороны должны ответить на это одинаково, иначе они выведут разные
    /// ключи и сессия умрёт на первом же кадре. Условие поэтому симметричное:
    /// учётные данные есть **и** пир заявил версию не ниже
    /// [`MIN_VERSION_FOR_STATIC_DH`](crate::net_consts::MIN_VERSION_FOR_STATIC_DH).
    pub(crate) fn uses_static_dh(&self) -> bool {
        self.identity.is_some() && self.peer_version >= crate::net_consts::MIN_VERSION_FOR_STATIC_DH
    }

    /// Отвергать ли пира, пришедшего по старой анонимной схеме.
    ///
    /// Пока нода не в strict-режиме, downgrade остаётся возможен: активный
    /// посредник переписывает `session_id[0]` на 2, и хендшейк идёт по схеме
    /// без аутентификации. Строгий режим — обязательный финальный шаг
    /// раскатки, а не опция.
    pub(crate) fn rejects_anonymous(&self) -> bool {
        self.identity.as_ref().is_some_and(Identity::strict)
    }

    /// Тег для `session_id` своего `ClientHello` (только клиент).
    ///
    /// В схеме v3 считается на ключе ноды и привязан к этому конкретному
    /// соединению; в v2 — старый безключевой тег от времени.
    pub(crate) fn handshake_tag(&self, random: &[u8; 32]) -> [u8; 16] {
        match &self.identity {
            Some(id) => SessionAuth::new(*id.secret())
                .generate_handshake_tag(random, &self.public_key_bytes()),
            None => SessionAuth::new(self.auth_key).generate_current_tag(),
        }
    }

    /// Проверка тега из `ClientHello` (только сервер), до вывода ключей.
    ///
    /// Криптографии тяжелее HMAC здесь нет намеренно: тег проверяется на каждом
    /// входящем `ClientHello`, в том числе на пробах сканеров, и X25519 в этой
    /// точке был бы бесплатным DoS-усилителем.
    pub(crate) fn verify_handshake_tag(
        &self,
        received_tag: &[u8; 16],
        random: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> bool {
        if self.uses_static_dh() {
            let Some(id) = &self.identity else {
                return false;
            };
            SessionAuth::new(*id.secret()).verify_handshake_tag(received_tag, random, peer_public)
        } else if self.rejects_anonymous() {
            false
        } else {
            SessionAuth::new(self.auth_key).verify_tag(received_tag)
        }
    }

    pub(crate) fn get_aead_parameters(&self) -> ([u8; 32], [u8; 12], [u8; 32], [u8; 12]) {
        self.current_aead
            .expect("Keys not generated yet. Call update_keys first.")
    }

    pub fn get_auth_key(&self) -> [u8; 32] {
        self.auth_key
    }

    /// `true` — эта сторона инициатор (клиент) хендшейка.
    ///
    /// Нужен [`crate::crypto::datagram_keys`], который так же, как
    /// [`generate_keys`](Self::generate_keys) здесь, разводит `client_*`/
    /// `server_*` метки HKDF по ролям на tx/rx.
    pub(crate) fn is_initiator(&self) -> bool {
        self.salt.is_initiator
    }

    /// Копия `PRK`, из которого выведен `current_aead` (см.
    /// [`datagram_root`](Self::datagram_root) на поле). Паникует, если вызвана
    /// до хендшейка — тот же контракт, что у [`get_aead_parameters`](Self::get_aead_parameters).
    pub(crate) fn datagram_root(&self) -> [u8; 32] {
        let root: &Zeroizing<[u8; 32]> = self
            .datagram_root
            .as_ref()
            .expect("Keys not generated yet. Call update_keys first.");
        let bytes: [u8; 32] = **root;
        bytes
    }

    /// Завершает хендшейк: принимает удалённую соль и публичный ключ из
    /// TLS-расширений, выводит все ключи сессии.
    ///
    /// Публичный ключ X25519 извлекается из расширения KeyShare (`0x0033`).
    /// Парсинг асимметричен: у сервера (`is_server`) `ClientHello` содержит список
    /// именованных групп, поэтому ключ ищется по маркеру `00 1d 00 20` (X25519,
    /// 32 байта); у клиента `ServerHello` отдаёт ровно один ключ по фиксированному
    /// смещению. Любая аномалия (короткий буфер, нет KeyShare, нулевой ключ)
    /// трактуется как [`ERR_NET_TLS_TAMPER`] — признак вмешательства/несовместимости.
    #[allow(clippy::result_large_err)]
    pub(crate) fn update_keys(
        &mut self,
        salt: [u8; 32],
        extensions: &ExtensionStack,
        is_server: bool,
    ) -> Result<DirectionalAeadKeys, AppError> {
        self.salt.set_remote_salt(salt);

        netrunner_logger::debug!(
            remote_salt = %hex::encode(&salt[..8]),
            local_salt = %hex::encode(&self.salt.get_local()[..8]),
            total_salt = %hex::encode(&self.salt.get_total()[28..36]),
            "Updating keys with new salt"
        );

        let public_key = PublicKey::from(Self::extract_peer_public(extensions, is_server)?);
        self.generate_keys(&public_key, is_server)
    }

    /// Достаёт публичный ключ X25519 пира из расширения KeyShare (`0x0033`).
    ///
    /// Вынесено из [`update_keys`](SessionKeys::update_keys) отдельно, потому
    /// что серверу этот ключ нужен **раньше** вывода ключей: в схеме v3 он
    /// входит в тег `ClientHello`, а тег проверяется до любых DH. Операция
    /// чисто разборная — скан уже распарсенного [`ExtensionStack`], никакой
    /// криптографии, поэтому её безопасно делать на неаутентифицированном
    /// вводе.
    ///
    /// Парсинг асимметричен: у сервера `ClientHello` содержит список именованных
    /// групп, поэтому ключ ищется по маркеру `00 1d 00 20` (X25519, 32 байта);
    /// у клиента `ServerHello` отдаёт ровно один ключ по фиксированному смещению.
    #[allow(clippy::result_large_err)]
    pub(crate) fn extract_peer_public(
        extensions: &ExtensionStack,
        is_server: bool,
    ) -> Result<[u8; 32], AppError> {
        const EXT_KEY_SHARE: u16 = 0x0033;
        const GROUP_X25519: u16 = 0x001d;
        const X25519_LEN: usize = 32;

        let Some(dh_data) = extensions.find_by_type(EXT_KEY_SHARE) else {
            return Err(AppError::new(
                ERR_NET_TLS_TAMPER,
                "Ошибка маскировки",
                "No KeyShare extension found in handshake",
            ));
        };

        // Разбор по структуре, а не поиском байтовой сигнатуры.
        //
        // Раньше серверная ветка искала подстроку `00 1d 00 20` в произвольном
        // месте расширения. Пока `key_share` нёс единственную запись на 32
        // байта, это работало. С постквантовым профилем клиент кладёт туда ещё
        // 1216 байт балласта ML-KEM (см. `tlseng::mlkem`), и внутри них та же
        // четвёрка байт может встретиться случайно — примерно раз на 3,6 млн
        // хендшейков на узел. Последствие не «редкая ошибка», а вывод ключей
        // из мусора: сессия молча не собирается, а причина невоспроизводима.
        //
        // Формат (RFC 8446 §4.2.8): у клиента — `list_len(2)`, затем записи
        // `group(2) | key_len(2) | key`; у сервера — одна запись без внешней
        // длины списка.
        let mut key_bytes = [0u8; X25519_LEN];

        if is_server {
            if dh_data.len() < 2 {
                return Err(AppError::new(
                    ERR_NET_TLS_TAMPER,
                    "Ошибка маскировки",
                    format!("Client KeyShare too short: {}", dh_data.len()),
                ));
            }
            let list_len = u16::from_be_bytes([dh_data[0], dh_data[1]]) as usize;
            let Some(list) = dh_data.get(2..2 + list_len) else {
                return Err(AppError::new(
                    ERR_NET_TLS_TAMPER,
                    "Ошибка маскировки",
                    "KeyShare list_len exceeds extension body",
                ));
            };

            let mut off = 0usize;
            let mut found = false;
            while off + 4 <= list.len() {
                let group = u16::from_be_bytes([list[off], list[off + 1]]);
                let key_len = u16::from_be_bytes([list[off + 2], list[off + 3]]) as usize;
                off += 4;
                let Some(entry) = list.get(off..off + key_len) else {
                    break;
                };
                // GREASE-запись и постквантовый балласт проходят мимо: нас
                // интересует ровно x25519 нужной длины.
                if group == GROUP_X25519 && key_len == X25519_LEN {
                    key_bytes.copy_from_slice(entry);
                    found = true;
                    break;
                }
                off += key_len;
            }

            if !found {
                return Err(AppError::new(
                    ERR_NET_TLS_TAMPER,
                    "Ошибка маскировки",
                    "Could not find x25519 key in ClientHello",
                ));
            }
        } else {
            // ServerHello: ровно одна запись `group(2) | len(2) | key`.
            if dh_data.len() < 4 + X25519_LEN {
                return Err(AppError::new(
                    ERR_NET_TLS_TAMPER,
                    "Ошибка маскировки",
                    "Server KeyShare too short",
                ));
            }
            let key_len = u16::from_be_bytes([dh_data[2], dh_data[3]]) as usize;
            if key_len != X25519_LEN {
                return Err(AppError::new(
                    ERR_NET_TLS_TAMPER,
                    "Ошибка маскировки",
                    format!("Server KeyShare has unexpected key length {key_len}"),
                ));
            }
            key_bytes.copy_from_slice(&dh_data[4..4 + X25519_LEN]);
        }

        if key_bytes.iter().all(|&x| x == 0) {
            return Err(AppError::new(
                ERR_NET_TLS_TAMPER,
                "Ошибка шифрования",
                "Extracted remote public key is all ZEROS!",
            ));
        }

        Ok(key_bytes)
    }

    /// Низкоуровневый вывод ключей: ECDH → HKDF-Extract → пять HKDF-Expand.
    ///
    /// Из общего секрета и полной соли выводятся пять значений по фиксированным
    /// лейблам (`client_aead`, `client_iv`, `server_aead`, `server_iv`, `auth_key`).
    /// Затем `is_server` назначает направления: для сервера tx=`server_*`,
    /// rx=`client_*`, для клиента — наоборот. Так одна и та же пара ключей
    /// у клиента служит на запись, а у сервера — на чтение, и наоборот.
    ///
    /// ## Что именно уходит в `ikm` (v2 против v3)
    ///
    /// ```text
    /// v2:  ikm = DH(своя эфемерная, чужая эфемерная)
    /// v3:  ikm = DH(своя эфемерная, чужая эфемерная) ‖ static_dh ‖ "nrxp-v3-static-dh"
    /// ```
    ///
    /// Первый DH даёт forward secrecy, второй — аутентификацию: посчитать его
    /// может только владелец приватного статического ключа ноды. Посредник,
    /// подсунувший клиенту свою эфемерную пару, выведет другой `ikm` и другие
    /// ключи, поэтому первый же кадр у него не расшифруется. Именно этот второй
    /// DH и есть вся разница между «анонимным обменом ключами» и
    /// «аутентифицированным».
    ///
    /// Ни один из двух результатов не идёт в HKDF в одиночку: конкатенация
    /// обязательна, иначе выпадение любого из них осталось бы незамеченным.
    #[allow(clippy::result_large_err)]
    fn generate_keys(
        &mut self,
        public_key: &PublicKey,
        is_server: bool,
    ) -> Result<DirectionalAeadKeys, AppError> {
        let mut ephemeral_dh = self
            .ecdh
            .dh(public_key)
            .ok_or_else(|| AppError::new(ERR_NET_TLS_TAMPER, "Сбой", "No shared secret"))?;

        // `Zeroizing`, а не голый `Vec`: в `ikm` лежит сырой результат DH —
        // самый ценный материал всего хендшейка, из него выводится вообще всё
        // остальное. Утёкший `ikm` эквивалентен утёкшей сессии целиком, а
        // обычный `Vec` при drop только вернул бы страницы аллокатору.
        //
        // Ёмкость взята с запасом под оба слагаемых и домен, поэтому `Vec` не
        // реаллоцируется: иначе старый буфер с секретом остался бы в куче
        // нетронутым — `Zeroizing` затирает только текущий.
        let mut ikm = Zeroizing::new(Vec::with_capacity(64 + IKM_DOMAIN_V3.len()));
        ikm.extend_from_slice(&ephemeral_dh);
        ephemeral_dh.zeroize();

        if self.uses_static_dh() {
            let identity = self
                .identity
                .as_ref()
                .expect("uses_static_dh() implies identity is present");
            let mut static_dh = identity
                .static_dh(&self.ecdh, public_key)
                .ok_or_else(|| AppError::new(ERR_NET_TLS_TAMPER, "Сбой", "No static secret"))?;
            ikm.extend_from_slice(&static_dh);
            static_dh.zeroize();
            ikm.extend_from_slice(IKM_DOMAIN_V3);
        }

        // Forward secrecy: приватный эфемерный ключ больше не нужен ни одной
        // ветке — уничтожаем его здесь, а не «когда-нибудь на Drop».
        self.ecdh.burn();

        let (prk_bytes, hkdf) = HKDF::extract_key(&self.salt.get_total(), &ikm);
        // Датаграммная (UDP) нога выводит свой ключевой материал из этого же
        // PRK — см. `crypto::datagram_keys` — но делает это позже, чем живёт
        // `ikm`/`hkdf` этого вызова (та же причина, по которой tx/rx ключи
        // сессии выводятся здесь: `ikm` уничтожается сразу после). Храним
        // только 32-байтный `PRK`, а не сам `Hkdf<Sha256>` — из него в любой
        // момент восстанавливается `Hkdf::from_prk`, а обратного пути (достать
        // из готового `Hkdf` его входной `PRK`) в API крейта `hkdf` нет.
        self.datagram_root = Some(Zeroizing::new(prk_bytes));

        let mut c_key = HKDF::expand_key::<32>(&hkdf, b"client_aead")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;
        let mut c_iv = HKDF::expand_key::<12>(&hkdf, b"client_iv")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;
        let mut s_key = HKDF::expand_key::<32>(&hkdf, b"server_aead")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;
        let mut s_iv = HKDF::expand_key::<12>(&hkdf, b"server_iv")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;

        self.auth_key = HKDF::expand_key::<32>(&hkdf, b"auth_key")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;

        let keys = if is_server {
            (s_key, s_iv, c_key, c_iv)
        } else {
            (c_key, c_iv, s_key, s_iv)
        };

        // Локальные копии отработали: их значения уже лежат в `keys`. За копию,
        // уходящую наружу, отвечает вызывающий код (она попадает в
        // `ChaChaCipher`, который `ZeroizeOnDrop`); наша забота — не оставить
        // лишних копий здесь, на стеке.
        c_key.zeroize();
        c_iv.zeroize();
        s_key.zeroize();
        s_iv.zeroize();

        self.current_aead = Some(keys);
        Ok(keys)
    }

    pub(crate) fn local_salt(&self) -> [u8; 32] {
        self.salt.get_local()
    }

    pub(crate) fn public_key_bytes(&self) -> [u8; 32] {
        self.ecdh.public_key.to_bytes()
    }

    pub(crate) fn auth_key_fingerprint(&self) -> String {
        hex::encode(&self.auth_key[..4])
    }
}

/// Затирание ключевого материала при уничтожении сессии.
///
/// # Инвариант безопасности (НЕ ЛОМАТЬ)
///
/// `auth_key` и `current_aead` — выведенные ключи сессии. Без явного затирания
/// `drop` лишь освобождает память, и ключи остаются читаемыми до тех пор, пока
/// страницу кто-нибудь не переиспользует: они уезжают в core dump, в swap и в
/// снапшот виртуальной машины. Forward secrecy отвечает на вопрос «достанут
/// сервер завтра», а не «снимут дамп памяти сейчас» — это вторая половина.
///
/// Эфемерный ключ X25519 сюда не входит намеренно: он уничтожается раньше и
/// явно, в [`ECDH::burn`](super::ecdh::ECDH::burn) сразу после вывода ключей, а
/// `StaticSecret` у `x25519-dalek` сам по себе `ZeroizeOnDrop`.
///
/// Наличие `Drop` у этого типа запрещает functional record update — см.
/// [`SessionKeys::with_identity`].
impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        if let Some((tx_key, tx_iv, rx_key, rx_iv)) = self.current_aead.as_mut() {
            tx_key.zeroize();
            tx_iv.zeroize();
            rx_key.zeroize();
            rx_iv.zeroize();
        }
        // `Zeroizing<[u8; 32]>` already zeroizes itself on drop; dropping the
        // `Option` here is enough. Spelled out so the invariant above ("НЕ
        // ЛОМАТЬ") stays visibly true for every secret this struct carries,
        // not just the two it had before `datagram_root` existed.
        self.datagram_root = None;
    }
}

// ==========================================
// 2. DATA PHASE (Авторизация Кодека)
// ==========================================

/// Лёгкий копируемый «аутентификатор кадров», который забирают `RxCodec`/`TxCodec`
/// после хендшейка.
///
/// Реализует TOTP-подобную схему: тег кадра = первые 16 байт
/// `HMAC-SHA256(auth_key, current_time_step)`, где `step = unix_secs /
/// AUTH_TIME_STEP`. Тег меняется каждые `AUTH_TIME_STEP` секунд, поэтому
/// записанный ранее DPI-перехват нельзя «переиграть» позже — окно валидности
/// уезжает. Допуск на рассинхрон часов задаётся `AUTH_WINDOW_SIZE`.
/// Текущее unix-время в секундах — `std::time::SystemTime::now()` panics with
/// "time not implemented on this platform" on wasm32-unknown-unknown (no OS
/// clock syscall there), which is exactly the target `client-edge`
/// (Cloudflare Workers) builds for. `web-time` is an API-compatible drop-in
/// backed by JS `Date.now()` on that target only; native targets keep using
/// `std::time` unchanged.
#[cfg(target_arch = "wasm32")]
fn now_unix_secs() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(not(target_arch = "wasm32"))]
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        // NTP step-back can make this return Err; saturate to 0. Both call
        // sites tolerate this: generate_current_tag just produces a tag for
        // step 0, and verify_tag's window comparison will simply fail and
        // log AUTH MISMATCH rather than panicking.
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Copy)]
pub struct SessionAuth {
    auth_key: [u8; 32],
}

impl SessionAuth {
    pub fn new(auth_key: [u8; 32]) -> Self {
        Self { auth_key }
    }

    /// Чистая функция: тег для конкретного временного шага `step`.
    ///
    /// Вынесена отдельно, чтобы и генерация, и проверка считали тег одинаково.
    pub fn compute_tag(secret: &[u8], step: u64) -> [u8; 16] {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC error");
        mac.update(&step.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result[..16]);
        tag
    }

    /// Тег для текущего момента времени — кладётся в исходящий кадр.
    pub fn generate_current_tag(&self) -> [u8; 16] {
        let now = now_unix_secs();

        Self::compute_tag(&self.auth_key, now / AUTH_TIME_STEP)
    }

    /// Чистая функция: тег `ClientHello` для шага `step`, соли `random` и
    /// эфемерного публичного ключа клиента `peer_public`.
    ///
    /// Два отличия от пер-кадрового [`compute_tag`](SessionAuth::compute_tag),
    /// и оба существенные:
    ///
    /// 1. **Ключ — секрет ноды, а не `auth_key`.** На момент отправки
    ///    `ClientHello` ключей сессии ещё не существует: обмен ими только
    ///    начинается. Раньше в этой точке брался `auth_key`, который до
    ///    `update_keys` равен нулям, — тег получался чистой функцией времени,
    ///    одинаковой для всех развёртываний в мире, и вычислялся кем угодно без
    ///    единого секрета. Барьер на входе был нулевой.
    /// 2. **Привязка к соединению.** Под HMAC уходят соль и KeyShare клиента,
    ///    поэтому перехваченный тег нельзя вставить в чужой `ClientHello`: с
    ///    другим эфемерным ключом он не сойдётся. Тег «только от времени» был
    ///    валиден для любого отправителя все 300 секунд окна.
    ///
    /// Домен разделён префиксом: значение, посчитанное здесь, не может совпасть
    /// с пер-кадровым тегом на том же ключе и шаге.
    pub fn compute_handshake_tag(
        secret: &[u8],
        step: u64,
        random: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> [u8; 16] {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC error");
        mac.update(b"nrxp-handshake-v3");
        mac.update(&step.to_be_bytes());
        mac.update(random);
        mac.update(peer_public);
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result[..16]);
        tag
    }

    /// Тег `ClientHello` на текущий момент — кладётся в `session_id[16..32]`.
    pub fn generate_handshake_tag(&self, random: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 16] {
        let now = now_unix_secs();

        Self::compute_handshake_tag(&self.auth_key, now / AUTH_TIME_STEP, random, peer_public)
    }

    /// Проверяет тег `ClientHello` против того же окна `[step-W .. step+W]`.
    ///
    /// # Инвариант безопасности (НЕ ЛОМАТЬ)
    ///
    /// Тот же, что у [`verify_tag`](SessionAuth::verify_tag): цикл всегда
    /// прогоняет все `2*AUTH_WINDOW_SIZE + 1` кандидатов, сравнение идёт через
    /// [`subtle::ConstantTimeEq`], накопление результата — через [`Choice`], без
    /// раннего `break` и без единого ветвления по секрету. Здесь это важнее, чем
    /// в data-фазе: метод стоит на неаутентифицированном вводе и вызывается на
    /// каждой пробе сканера.
    pub fn verify_handshake_tag(
        &self,
        received_tag: &[u8; 16],
        random: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> bool {
        let current_step = now_unix_secs() / AUTH_TIME_STEP;

        let mut matched = Choice::from(0u8);
        for step in (current_step.saturating_sub(AUTH_WINDOW_SIZE))
            ..=(current_step.saturating_add(AUTH_WINDOW_SIZE))
        {
            let candidate = Self::compute_handshake_tag(&self.auth_key, step, random, peer_public);
            // Никакого раннего выхода: накапливаем результат по всем шагам.
            matched |= candidate[..].ct_eq(&received_tag[..]);
        }

        matched.unwrap_u8() == 1
    }

    /// Проверяет тег входящего кадра против окна `[step-W .. step+W]`.
    ///
    /// # Инвариант безопасности (НЕ ЛОМАТЬ)
    ///
    /// Цикл **всегда** прогоняет все `2*AUTH_WINDOW_SIZE + 1` кандидатов,
    /// сравнивает теги через [`subtle::ConstantTimeEq`] и запоминает совпавший
    /// шаг через [`ConditionallySelectable`] — без раннего `break` и без единого
    /// ветвления по результату сравнения внутри цикла. Длительность `verify_tag`
    /// не зависит от того, какой шаг (и совпал ли вообще) подошёл, иначе по
    /// таймингу можно подбирать тег.
    ///
    /// Раньше здесь стояло `if diff == 0 && matched_step.is_none()`. Полный
    /// прогон окна это сохраняло, но само `if` — уже ветвление по результату
    /// сравнения с секретом, а `is_none()` вдобавок давал short-circuit. Ровно
    /// та утечка, которую цикл был призван закрыть.
    pub fn verify_tag(&self, received_tag: &[u8; 16]) -> bool {
        let now = now_unix_secs();

        let current_step = now / AUTH_TIME_STEP;

        // Constant-time path: always evaluate ALL 2*AUTH_WINDOW_SIZE+1 candidates
        // so the loop duration doesn't leak which step (if any) matched.
        let mut matched = Choice::from(0u8);
        let mut matched_step = 0u64;
        for step in (current_step.saturating_sub(AUTH_WINDOW_SIZE))
            ..=(current_step.saturating_add(AUTH_WINDOW_SIZE))
        {
            let candidate = Self::compute_tag(&self.auth_key, step);
            let eq = candidate[..].ct_eq(&received_tag[..]);
            // Запоминаем ПЕРВЫЙ совпавший шаг, не ветвясь: `take` истинно только
            // если совпало сейчас и не совпадало ни на одном предыдущем шаге.
            // `conditional_select` — арифметика с масками, а не `if`.
            let take = eq & !matched;
            matched_step = u64::conditional_select(&matched_step, &step, take);
            matched |= eq;
        }

        // Здесь ветвиться уже можно: сам факт «тег валиден» — это возвращаемое
        // наружу значение, а не секрет. Внутри окна не осталось ни одного
        // ветвления, зависящего от того, какой именно шаг подошёл.
        if matched.unwrap_u8() == 1 {
            if matched_step != current_step {
                netrunner_logger::debug!(expected = %current_step, matched = %matched_step, "Auth tag valid with time offset");
            }
            true
        } else {
            netrunner_logger::warn!(
                current_step = %current_step,
                "AUTH MISMATCH: All tags rejected for current window"
            );
            false
        }
    }
}

// ==========================================
// 3. ТЕСТЫ ОКНА АУТЕНТИФИКАЦИИ
// ==========================================

/// # Чего эти тесты НЕ проверяют
///
/// Они фиксируют **семантику** окна: какие теги принимаются, какие нет. Доказать
/// постоянство времени они не могут в принципе — утечка живёт в машинном коде и
/// зависит от `-C opt-level`, версии LLVM и целевой архитектуры, а тест на Rust
/// наблюдает только поведение. Постоянство времени здесь обеспечивается
/// конструктивно (`subtle` ставит оптимизационные барьеры), а проверяется —
/// измерением на целевой платформе (`dudect`/`cachegrind` на aarch64 в релизной
/// сборке), а не отсюда.
#[cfg(test)]
mod tests {
    use super::*;

    /// Прогоняет замер и повторяет его, если шаг времени переехал прямо посреди
    /// прогона. `verify_tag` берёт время сама, поэтому на смене минуты граничные
    /// случаи `±AUTH_WINDOW_SIZE` иначе изредка флапали бы. Ассерты вынесены
    /// наружу намеренно: паника внутри замера лишила бы нас повтора.
    fn stable<T>(probe: impl Fn(u64) -> T) -> T {
        for _ in 0..8 {
            let before = now_unix_secs() / AUTH_TIME_STEP;
            let out = probe(before);
            if now_unix_secs() / AUTH_TIME_STEP == before {
                return out;
            }
        }
        panic!("шаг времени переезжал на каждой попытке — часы идут неправдоподобно быстро");
    }

    /// Все `2*AUTH_WINDOW_SIZE + 1` шагов окна принимаются: это и есть допуск на
    /// рассинхрон часов, ради которого окно существует.
    #[test]
    fn tag_is_accepted_across_the_whole_window() {
        let key = [7u8; 32];
        let auth = SessionAuth::new(key);

        let verdicts = stable(|step| {
            (0..=(2 * AUTH_WINDOW_SIZE))
                .map(|i| {
                    let candidate = step.saturating_sub(AUTH_WINDOW_SIZE) + i;
                    auth.verify_tag(&SessionAuth::compute_tag(&key, candidate))
                })
                .collect::<Vec<_>>()
        });

        assert!(
            verdicts.iter().all(|&ok| ok),
            "окно обязано принимать все 2W+1 шагов, получено: {verdicts:?}"
        );
    }

    /// Ровно за границей окна тег недействителен — иначе допуск на часы тихо
    /// превратился бы в бесконечное окно повтора.
    #[test]
    fn tag_is_rejected_just_outside_the_window() {
        let key = [9u8; 32];
        let auth = SessionAuth::new(key);

        let (too_old, too_new) = stable(|step| {
            (
                auth.verify_tag(&SessionAuth::compute_tag(
                    &key,
                    step.saturating_sub(AUTH_WINDOW_SIZE + 1),
                )),
                auth.verify_tag(&SessionAuth::compute_tag(&key, step + AUTH_WINDOW_SIZE + 1)),
            )
        });

        assert!(!too_old, "шаг -(W+1) обязан отвергаться");
        assert!(!too_new, "шаг +(W+1) обязан отвергаться");
    }

    /// Тег на чужом ключе не проходит ни на одном шаге окна.
    #[test]
    fn tag_computed_with_another_key_is_rejected() {
        let auth = SessionAuth::new([1u8; 32]);
        let accepted = stable(|step| auth.verify_tag(&SessionAuth::compute_tag(&[2u8; 32], step)));
        assert!(!accepted, "чужой ключ обязан отвергаться");
    }

    /// То же окно для тега `ClientHello` — метода, который стоит на
    /// неаутентифицированном вводе и вызывается на каждой пробе сканера.
    #[test]
    fn handshake_tag_is_accepted_across_the_whole_window() {
        let secret = [3u8; 32];
        let auth = SessionAuth::new(secret);
        let random = [4u8; 32];
        let peer_public = [5u8; 32];

        let verdicts = stable(|step| {
            (0..=(2 * AUTH_WINDOW_SIZE))
                .map(|i| {
                    let candidate = step.saturating_sub(AUTH_WINDOW_SIZE) + i;
                    auth.verify_handshake_tag(
                        &SessionAuth::compute_handshake_tag(
                            &secret,
                            candidate,
                            &random,
                            &peer_public,
                        ),
                        &random,
                        &peer_public,
                    )
                })
                .collect::<Vec<_>>()
        });

        assert!(
            verdicts.iter().all(|&ok| ok),
            "окно тега хендшейка обязано совпадать с окном кадра, получено: {verdicts:?}"
        );
    }

    /// Разделение доменов: на одном ключе и одном шаге пер-кадровый тег и тег
    /// хендшейка не должны совпадать, иначе один переиспользуется вместо другого.
    #[test]
    fn frame_and_handshake_tags_do_not_collide_on_the_same_key_and_step() {
        let secret = [6u8; 32];
        let step = 30_000_000u64;

        assert_ne!(
            SessionAuth::compute_tag(&secret, step),
            SessionAuth::compute_handshake_tag(&secret, step, &[0u8; 32], &[0u8; 32]),
        );
    }
}
