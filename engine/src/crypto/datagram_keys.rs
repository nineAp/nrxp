//! Ключевой материал UDP-ноги: один общий "корень" на оба датаграммных
//! движка ([`crate::quiceng`], [`crate::webrtceng`]) и на голый UDP-фолбэк.
//!
//! ## Почему не второй хендшейк
//!
//! UDP-нога не проводит свой `ClientHello`/`ServerHello` — это была бы вторая
//! точка, которую можно фингерпринтить на этапе установки, и дублирование
//! уже пройденной аутентификации. Вместо этого она выводит свой ключевой
//! материал из **того же** секрета, что и уже установленная TCP-нога:
//! [`SessionKeys::datagram_root`](super::session::SessionKeys::datagram_root)
//! отдаёт `PRK` того же HKDF-extract, из которого получены её AEAD-ключи.
//!
//! ## Ratchet, а не статичный набор меток
//!
//! Наивная схема «HKDF-Expand(root, label || epoch_number)» тоже решает
//! проблему исчерпания nonce (см. [`crate::nrxp::datagram`] — там локальный
//! счётчик и так 64-битный и не исчерпывается практически никогда), но не
//! даёт ничего сверх этого: скомпрометировавший `root` читает вообще все
//! эпохи сразу, потому что все они — независимо адресуемые функции одного и
//! того же вечно живущего значения.
//!
//! Здесь вместо этого — однонаправленная KDF-цепочка (симметричная половина
//! double ratchet, без DH-компонента: свежий DH на каждую эпоху нам не нужен,
//! он уже был один раз в основном хендшейке). Каждый шаг [`KeyRatchet::advance`]
//! необратимо продвигает `chain` вперёд и затирает предыдущее значение —
//! компрометация ключей эпохи N не открывает трафик эпохи N-1, потому что
//! `chain_{N-1}` физически не существует уже в момент компрометации (затёрт),
//! а из `chain_N` его не восстановить (однонаправленность HKDF-Expand).
//!
//! Это не полная post-compromise security (компрометация `chain_N` всё ещё
//! открывает ВСЕ будущие эпохи, поскольку ratchet детерминирован и не мешает
//! новую энтропию на каждом шаге — для этого нужен был бы новый DH на каждую
//! эпоху), а именно та половина свойства, которую можно получить бесплатно
//! (без нового round-trip) поверх уже установленной сессии.

use zeroize::Zeroizing;

use crate::crypto::hkdf::HKDF;
use crate::crypto::session::SessionKeys;

/// Ключи одной эпохи ratchet'а, готовые к использованию AEAD-примитивом
/// [`crate::nrxp::datagram`]: `salt` играет ту же роль, что `base_iv` в
/// [`super::chacha::ChaChaStream`] — базовый nonce, XOR'имый со счётчиком.
pub(crate) struct DatagramEpochKeys {
    pub(crate) epoch_id: u8,
    pub(crate) key: [u8; 32],
    pub(crate) salt: [u8; 12],
}

/// Однонаправленная HKDF-цепочка для одного направления (c2s либо s2c).
struct KeyRatchet {
    chain: Zeroizing<[u8; 32]>,
    epoch_id: u8,
}

impl KeyRatchet {
    fn from_root(chain0: [u8; 32]) -> Self {
        Self {
            chain: Zeroizing::new(chain0),
            epoch_id: 0,
        }
    }

    /// Ключи текущей эпохи — без продвижения состояния. Вызывается сколько
    /// угодно раз на каждый исходящий/входящий пакет этой эпохи.
    fn current(&self) -> DatagramEpochKeys {
        Self::derive_epoch(&self.chain, self.epoch_id)
    }

    /// Ключи СЛЕДУЮЩЕЙ эпохи, если бы ratchet продвинулся — не продвигает его
    /// на самом деле. Нужен приёмной стороне: чтобы узнать, "правда ли этот
    /// пакет — начало новой эпохи", придётся попробовать её ключи, но
    /// коммитить продвижение состояния можно только ПОСЛЕ успешной AEAD-проверки
    /// (см. `DatagramRx` в [`crate::nrxp::datagram`]) — иначе один поддельный
    /// пакет с чужим/случайным содержимым сдвигал бы состояние вхолостую.
    fn peek_next(&self) -> DatagramEpochKeys {
        let next_chain = Self::step_chain(&self.chain);
        Self::derive_epoch(&next_chain, self.epoch_id.wrapping_add(1))
    }

    /// Необратимо продвигает цепочку на один шаг и возвращает ключи новой
    /// эпохи. Старое значение `chain` затирается при присваивании — на этом
    /// и держится однонаправленность (см. док модуля).
    fn advance(&mut self) -> DatagramEpochKeys {
        let next_chain = Self::step_chain(&self.chain);
        self.epoch_id = self.epoch_id.wrapping_add(1);
        self.chain = Zeroizing::new(next_chain);
        self.current()
    }

    fn derive_epoch(chain: &[u8; 32], epoch_id: u8) -> DatagramEpochKeys {
        let hk = HKDF::from_prk(chain);
        DatagramEpochKeys {
            epoch_id,
            key: HKDF::expand_key::<32>(&hk, b"dgram-epoch-key")
                .expect("fixed-length HKDF-expand cannot fail"),
            salt: HKDF::expand_key::<12>(&hk, b"dgram-epoch-salt")
                .expect("fixed-length HKDF-expand cannot fail"),
        }
    }

    fn step_chain(chain: &[u8; 32]) -> [u8; 32] {
        let hk = HKDF::from_prk(chain);
        HKDF::expand_key::<32>(&hk, b"dgram-epoch-next")
            .expect("fixed-length HKDF-expand cannot fail")
    }
}

/// Ключевой материал UDP-ноги целиком: токен для демультиплексирования на
/// сервере + по одной ratchet-цепочке на направление.
///
/// Выводится один раз при подъёме UDP-ноги (см.
/// [`derive`](Self::derive)); дальше `tx`/`rx` живут своей жизнью на
/// протяжении всей ноги, вплоть до её физической смерти — ровно то время
/// жизни, для которого написан [`crate::nrxp::datagram`].
pub(crate) struct DatagramKeyMaterial {
    leg_token: [u8; 16],
    tx: KeyRatchet,
    rx: KeyRatchet,
    /// Header-protection ключи для [`crate::quiceng`] — стабильны на всю
    /// жизнь ноги, В ОТЛИЧИЕ от `tx`/`rx` (которые ratchet-перевыпускаются).
    /// Это не упрощение — так же ведёт себя настоящий QUIC: RFC 9001 §6.1
    /// прямо говорит, что HP-ключ не меняется при key update, потому что
    /// каждый апдейт трогает лишь малую долю пакетов и постоянно менять ради
    /// нескольких байт заголовка бессмысленно. `webrtceng`/raw-UDP эти поля
    /// просто не читают — RTP-заголовок никак не защищается.
    hp_key_tx: [u8; 32],
    hp_key_rx: [u8; 32],
}

impl DatagramKeyMaterial {
    /// Выводит корень UDP-ноги из уже установленной сессии. Требует
    /// завершённого хендшейка (паникует иначе — тот же контракт, что у
    /// [`SessionKeys::datagram_root`]).
    pub(crate) fn derive(session_keys: &SessionKeys) -> Self {
        Self::derive_from_root(session_keys.datagram_root(), session_keys.is_initiator())
    }

    /// То же самое, но от уже извлечённых сырых байт корня — нужно там, где
    /// сам `SessionKeys` к моменту вызова уже не жив (например,
    /// `perform_handshake` возвращает `datagram_root` отдельным полем и
    /// дропает `SessionKeys` — см. `net::connection::connection`), а
    /// материал требуется вывести НЕСКОЛЬКО раз (по разу на
    /// [`crate::nrxp::datagram::DatagramTx`]/[`crate::nrxp::datagram::DatagramRx`],
    /// каждый из которых владеет своей копией целиком). `derive` выше — тонкая
    /// обёртка поверх этого метода.
    pub(crate) fn derive_from_root(root: [u8; 32], is_initiator: bool) -> Self {
        let hk = HKDF::from_prk(&root);

        let leg_token = HKDF::expand_key::<16>(&hk, b"dgram-leg-token")
            .expect("fixed-length HKDF-expand cannot fail");
        let c2s0 = HKDF::expand_key::<32>(&hk, b"dgram-chain-c2s")
            .expect("fixed-length HKDF-expand cannot fail");
        let s2c0 = HKDF::expand_key::<32>(&hk, b"dgram-chain-s2c")
            .expect("fixed-length HKDF-expand cannot fail");
        let hp_c2s = HKDF::expand_key::<32>(&hk, b"dgram-hp-c2s")
            .expect("fixed-length HKDF-expand cannot fail");
        let hp_s2c = HKDF::expand_key::<32>(&hk, b"dgram-hp-s2c")
            .expect("fixed-length HKDF-expand cannot fail");

        // Та же симметрия ролей, что в `SessionKeys::generate_keys`: клиент
        // шлёт по `c2s`-цепочке и слушает `s2c`, сервер — наоборот.
        let (tx0, rx0) = if is_initiator {
            (c2s0, s2c0)
        } else {
            (s2c0, c2s0)
        };
        let (hp_key_tx, hp_key_rx) = if is_initiator {
            (hp_c2s, hp_s2c)
        } else {
            (hp_s2c, hp_c2s)
        };

        Self {
            leg_token,
            tx: KeyRatchet::from_root(tx0),
            rx: KeyRatchet::from_root(rx0),
            hp_key_tx,
            hp_key_rx,
        }
    }

    /// Стабильный (не ratchet-перевыпускаемый) ключ header protection на
    /// исходящее направление — см. поле [`Self::hp_key_tx`].
    pub(crate) fn hp_key_tx(&self) -> [u8; 32] {
        self.hp_key_tx
    }

    /// Тот же ключ на входящее направление.
    pub(crate) fn hp_key_rx(&self) -> [u8; 32] {
        self.hp_key_rx
    }

    /// 16-байтный демультиплексирующий токен: на сервере — единственный
    /// способ найти сессию по входящей датаграмме до какой-либо
    /// расшифровки. Стабилен на всю жизнь ноги (ротация — не в этой правке,
    /// см. `docs/UDP_LEG_RESEARCH.md`, идея N).
    pub(crate) fn leg_token(&self) -> [u8; 16] {
        self.leg_token
    }

    pub(crate) fn tx_epoch_id(&self) -> u8 {
        self.tx.epoch_id
    }

    pub(crate) fn tx_current(&self) -> DatagramEpochKeys {
        self.tx.current()
    }

    pub(crate) fn tx_advance(&mut self) -> DatagramEpochKeys {
        self.tx.advance()
    }

    pub(crate) fn rx_epoch_id(&self) -> u8 {
        self.rx.epoch_id
    }

    pub(crate) fn rx_current(&self) -> DatagramEpochKeys {
        self.rx.current()
    }

    pub(crate) fn rx_peek_next(&self) -> DatagramEpochKeys {
        self.rx.peek_next()
    }

    pub(crate) fn rx_advance(&mut self) -> DatagramEpochKeys {
        self.rx.advance()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_server_pair() -> (SessionKeys, SessionKeys) {
        // Тот же способ провести хендшейк в тестах, что и
        // `edge::tests::edge_handshake_interops_with_real_server_side` —
        // настоящая серверная сторона протокола, не мок.
        use crate::bridge::TlsBridge;
        use crate::tlseng::{BrowserProfile, ServerProfile};

        let mut client = SessionKeys::new(true);
        let mut server = SessionKeys::new(false);

        let ch = TlsBridge::wrap_client_hello(&BrowserProfile::CHROME_140, "example.com", &client);
        let mut ch_buf = bytes::BytesMut::from(&ch[..]);
        let client_msg = TlsBridge::unpack_handshake(&mut ch_buf).unwrap().unwrap();

        let (sh, _peer_version) =
            TlsBridge::wrap_server_hello(&client_msg, &mut server, &ServerProfile::MODERN).unwrap();
        let mut sh_buf = bytes::BytesMut::from(&sh[..]);
        let server_msg = TlsBridge::unpack_handshake(&mut sh_buf).unwrap().unwrap();

        client
            .update_keys(server_msg.random(), server_msg.extensions(), false)
            .unwrap();

        (client, server)
    }

    #[test]
    fn client_and_server_derive_matching_leg_tokens_and_chains() {
        let (client, server) = client_server_pair();
        let client_mat = DatagramKeyMaterial::derive(&client);
        let server_mat = DatagramKeyMaterial::derive(&server);

        assert_eq!(client_mat.leg_token(), server_mat.leg_token());

        let c_tx = client_mat.tx_current();
        let s_rx = server_mat.rx_current();
        assert_eq!(c_tx.key, s_rx.key);
        assert_eq!(c_tx.salt, s_rx.salt);
        assert_eq!(c_tx.epoch_id, s_rx.epoch_id);

        let s_tx = server_mat.tx_current();
        let c_rx = client_mat.rx_current();
        assert_eq!(s_tx.key, c_rx.key);
        assert_eq!(s_tx.salt, c_rx.salt);
    }

    #[test]
    fn hp_keys_match_across_client_and_server_and_never_change() {
        let (client, server) = client_server_pair();
        let mut client_mat = DatagramKeyMaterial::derive(&client);
        let server_mat = DatagramKeyMaterial::derive(&server);

        assert_eq!(client_mat.hp_key_tx(), server_mat.hp_key_rx());
        assert_eq!(client_mat.hp_key_rx(), server_mat.hp_key_tx());

        // В отличие от tx/rx (ratchet), hp-ключи не двигаются при rekey.
        let before = client_mat.hp_key_tx();
        client_mat.tx_advance();
        assert_eq!(client_mat.hp_key_tx(), before);
    }

    #[test]
    fn advance_matches_the_others_peek_next_before_it_commits() {
        let (client, server) = client_server_pair();
        let mut client_mat = DatagramKeyMaterial::derive(&client);
        let server_mat = DatagramKeyMaterial::derive(&server);

        // Сервер "подглядывает" следующую эпоху клиентской c2s-цепочки без
        // продвижения своего состояния...
        let peeked = server_mat.rx_peek_next();
        // ...клиент реально продвигает свою tx-цепочку...
        let advanced = client_mat.tx_advance();
        // ...оба должны получить один и тот же результат.
        assert_eq!(peeked.epoch_id, advanced.epoch_id);
        assert_eq!(peeked.key, advanced.key);
        assert_eq!(peeked.salt, advanced.salt);
    }

    #[test]
    fn ratchet_is_one_way() {
        let (client, _server) = client_server_pair();
        let mut mat = DatagramKeyMaterial::derive(&client);
        let epoch0 = mat.tx_current();
        let epoch1 = mat.tx_advance();

        assert_ne!(
            epoch0.key, epoch1.key,
            "разные эпохи обязаны иметь разные ключи"
        );
        assert_ne!(epoch0.epoch_id, epoch1.epoch_id);
        // Не проверяем "epoch0 невосстановим из epoch1" напрямую (это
        // свойство HKDF, не тестируемое юнит-тестом), но фиксируем, что API
        // вообще не даёт пути назад: `KeyRatchet` не хранит прошлые `chain`.
    }

    #[test]
    fn different_sessions_never_share_a_leg_token() {
        let (client_a, _) = client_server_pair();
        let (client_b, _) = client_server_pair();
        assert_ne!(
            DatagramKeyMaterial::derive(&client_a).leg_token(),
            DatagramKeyMaterial::derive(&client_b).leg_token(),
        );
    }
}
