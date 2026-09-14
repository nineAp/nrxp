//! Долговременные учётные данные ноды: то, что делает хендшейк
//! аутентифицированным.
//!
//! До версии протокола 3 хендшейк был полностью анонимным: обе стороны
//! предъявляли только эфемерные ключи X25519, и ни у клиента, ни у сервера не
//! было ни одного байта, по которому можно отличить своего пира от чужого.
//! Отсюда две дыры, которые этот модуль закрывает.
//!
//! ## Два значения, две разные задачи
//!
//! | Значение | Кто знает | Что закрывает |
//! |---|---|---|
//! | `secret` (32 B) | нода **и все её клиенты** | барьер на входе: тег `ClientHello` перестаёт быть чистой функцией времени |
//! | `static` (X25519) | приват — только нода, паблик — клиенты | аутентификация сервера и активный MITM |
//!
//! Разделение принципиальное, и путать их нельзя. `secret` симметричный и
//! раздаётся каждому клиенту, поэтому он **не** защищает от MITM: любой
//! легитимный клиент этой ноды знает его и мог бы встать в разрыв. Его работа —
//! отсечь сканеры и DPI-пробы, у которых секрета нет вовсе. От MITM защищает
//! только статическая пара: приватная половина не покидает ноду, поэтому второй
//! DH (`DH(e_client, static_pub)`) не может посчитать никто, кроме неё.
//!
//! Оба значения заводятся в админке `netrunner-backend` (таблица `vpn_nodes`),
//! приватная половина едет на ноду провижинингом рядом с `PROXY_INTERNAL_SECRET`,
//! публичные — приложению в списке нод. Это разные секреты с разным уровнем
//! доступа: `PROXY_INTERNAL_SECRET` — креденшл control-plane, его клиентам
//! отдавать нельзя ни при каких обстоятельствах.
//!
//! ## Формат на входе
//!
//! Везде hex, ровно 64 символа на 32 байта — и в `.env` ноды, и в конфиге,
//! который приложение получает от бэкенда.

use netrunner_logger::{AppError, ERR_AUTH_FAILED};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::ecdh::ECDH;

/// Разбирает 32-байтовое значение из hex-строки конфига.
#[allow(clippy::result_large_err)]
fn parse_key_hex(what: &str, value: &str) -> Result<[u8; 32], AppError> {
    // Раскодированный секрет живёт здесь в открытом виде до конца функции.
    // `Zeroizing` затирает буфер на выходе по любой ветке, включая отказ по
    // длине ниже. Саму строку `value` мы не владеем — её затирает вызывающий
    // код (конфиг/`.env`), сюда она приходит уже разобранной.
    let raw = Zeroizing::new(hex::decode(value.trim()).map_err(|e| {
        AppError::new(
            ERR_AUTH_FAILED,
            "Ошибка конфигурации",
            format!("{what}: ожидался hex, {e}"),
        )
    })?);
    raw.as_slice().try_into().map_err(|_| {
        AppError::new(
            ERR_AUTH_FAILED,
            "Ошибка конфигурации",
            format!(
                "{what}: ожидалось 32 байта (64 hex-символа), получено {}",
                raw.len()
            ),
        )
    })
}

/// То, что знает **клиент** о своей ноде: общий секрет и публичный статический
/// ключ. Приходит от бэкенда в списке нод по уже аутентифицированному HTTPS —
/// это и есть корень доверия, из которого растёт аутентификация туннеля.
#[derive(Clone)]
pub struct PeerIdentity {
    secret: [u8; 32],
    static_public: PublicKey,
}

impl PeerIdentity {
    /// `secret_hex` — `nrxp_secret` ноды, `public_hex` — её `nrxp_static_public`.
    #[allow(clippy::result_large_err)]
    pub fn from_hex(secret_hex: &str, public_hex: &str) -> Result<Self, AppError> {
        Ok(Self {
            secret: parse_key_hex("nrxp_secret", secret_hex)?,
            static_public: PublicKey::from(parse_key_hex("nrxp_static_public", public_hex)?),
        })
    }
}

/// То, что знает о себе **нода**: тот же общий секрет и приватная половина
/// статической пары. Приватный ключ не выходит за пределы процесса: наружу
/// доступен только [`LocalIdentity::public_key_hex`], чтобы оператор мог
/// сверить развёрнутое с тем, что показывает админка.
#[derive(Clone)]
pub struct LocalIdentity {
    secret: [u8; 32],
    static_private: StaticSecret,
    strict: bool,
}

impl LocalIdentity {
    /// `secret_hex` — `PROXY_NRXP_SECRET`, `private_hex` — `PROXY_NRXP_PRIVATE_KEY`.
    ///
    /// `strict` (`PROXY_NRXP_STRICT`) решает судьбу клиентов, которые ещё не
    /// получили учётных данных от бэкенда и приходят со старой версией
    /// протокола: `false` — принимать их по-старому (нужно на время раскатки),
    /// `true` — отвергать. Пока `strict` выключен, активный MITM может просто
    /// переписать заявленную версию в `ClientHello` и увести соединение на
    /// старую схему, поэтому переходный режим обязан быть временным.
    #[allow(clippy::result_large_err)]
    pub fn from_hex(secret_hex: &str, private_hex: &str, strict: bool) -> Result<Self, AppError> {
        Ok(Self {
            secret: parse_key_hex("nrxp_secret", secret_hex)?,
            static_private: StaticSecret::from(parse_key_hex("nrxp_static_private", private_hex)?),
            strict,
        })
    }

    /// Публичная половина статической пары в hex — для лога при старте ноды.
    /// Оператор сверяет её с тем, что записано в админке для этой ноды: если
    /// значения разошлись (например, после ротации выкатили не тот `.env`),
    /// клиенты не подключатся, и лучше увидеть это в логе старта, чем в
    /// метрике неудачных хендшейков.
    pub fn public_key_hex(&self) -> String {
        hex::encode(PublicKey::from(&self.static_private).as_bytes())
    }
}

/// Учётные данные стороны хендшейка — ровно одна из двух ролей.
///
/// `None` вместо `Identity` в [`SessionKeys`](super::session::SessionKeys)
/// означает «работаем по старой, неаутентифицированной схеме v2»: так ведут
/// себя нода без настроенных ключей и клиент, которому бэкенд ещё не отдал
/// учётные данные этой ноды.
#[derive(Clone)]
pub enum Identity {
    /// Клиентская роль: знаем публичный статический ключ ноды.
    Peer(PeerIdentity),
    /// Серверная роль: держим приватный статический ключ ноды.
    Local(LocalIdentity),
}

/// Затирание общего секрета ноды при уничтожении.
///
/// `secret` — долговременный симметричный секрет: он не меняется от сессии к
/// сессии, поэтому его утечка из дампа памяти стоит дороже, чем утечка ключей
/// одной сессии, — она открывает барьер на входе для всей ноды до ротации.
/// `static_public` затирать нечего: это публичное значение.
impl Drop for PeerIdentity {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// То же для серверной половины.
///
/// `static_private` здесь не трогаем намеренно: `StaticSecret` у `x25519-dalek`
/// сам `ZeroizeOnDrop`, и его поле затрётся сразу после этого тела.
impl Drop for LocalIdentity {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Identity {
    /// Общий секрет ноды — ключ HMAC для тега в `session_id` (см.
    /// `SessionAuth::compute_handshake_tag`).
    pub(crate) fn secret(&self) -> &[u8; 32] {
        match self {
            Identity::Peer(p) => &p.secret,
            Identity::Local(l) => &l.secret,
        }
    }

    /// Второй DH хендшейка — тот, который и даёт аутентификацию.
    ///
    /// Роли зеркальны и дают одно и то же значение:
    /// - клиент считает `DH(своя эфемерная приватная, статическая публичная ноды)`;
    /// - нода считает `DH(своя статическая приватная, эфемерная публичная клиента)`.
    ///
    /// `None` только если эфемерный ключ уже сожжён ([`ECDH::burn`]).
    pub(crate) fn static_dh(&self, ecdh: &ECDH, peer_ephemeral: &PublicKey) -> Option<[u8; 32]> {
        match self {
            Identity::Peer(p) => ecdh.dh(&p.static_public),
            Identity::Local(l) => Some(*l.static_private.diffie_hellman(peer_ephemeral).as_bytes()),
        }
    }

    /// Отвергать ли клиентов со старой версией протокола (только серверная роль).
    pub(crate) fn strict(&self) -> bool {
        match self {
            Identity::Peer(_) => true,
            Identity::Local(l) => l.strict,
        }
    }
}
