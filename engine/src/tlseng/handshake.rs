//! Сборка и разбор hello-сообщений рукопожатия.
//!
//! Здесь живёт «полезная контрабанда» внутри маскировки: поля поддельного
//! `ClientHello`/`ServerHello` переиспользуются под обмен ключами.
//!
//! - **`random` (32 байта)** ← локальная соль стороны (см. [`SessionKeys::local_salt`]).
//! - **`session_id` (32 байта)** ← 16 случайных байт + 16 байт time-based
//!   auth-тега. Сервер первым делом проверяет этот тег (см.
//!   [`bridge`](crate::nrxp)) — отсев чужих/сканеров до любой крипты.
//! - **публичный ключ X25519** ← в расширении KeyShare (собирается [`ExtensionBuilder`]).
//!
//! Все три структуры реализуют [`Parser`] (разбор входящих) и имеют `serialize`
//! (сборка исходящих). Точные размеры/порядок берутся из [`profile`](super::profile),
//! чтобы итоговый отпечаток совпал с реальным браузером.

use aead::{rand_core::RngCore, OsRng};
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    crypto::SessionKeys,
    errors::{ErrorAction, ErrorStage, TlsError},
    parser::Parser,
    tlseng::{
        consts::{HANDSHAKE_TYPE_CLIENT_HELLO, HANDSHAKE_TYPE_SERVER_HELLO},
        extension::ExtensionBuilder,
        grease::GreaseSet,
        profile::{BrowserProfile, ServerProfile},
        tls_record::TlsRecord,
        types::{ContentType, HelloType, ProtocolVersion},
    },
    utils::u24::{BufExt, U24},
};

/// Заголовок handshake-сообщения: тип (`ClientHello`/`ServerHello`) + 24-битная
/// длина тела. Парсится первым, чтобы понять, какое именно hello разбирать дальше.
pub(crate) struct HelloHeader {
    pub header_type: HelloType,
    pub _len: U24,
}

impl Parser for HelloHeader {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        bytes[0] == HelloType::Client as u8 || bytes[0] == HelloType::Server as u8
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let raw_type = bytes.get_u8();
        let header_type = HelloType::try_from(raw_type).map_err(|e| {
            TlsError::new(ErrorStage::Handshake(e), ErrorAction::Drop, Bytes::new())
        })?;

        let len = bytes.get_u24();

        Ok(Some(Self {
            header_type,
            _len: U24::from_u32(len),
        }))
    }
}

/// `ClientHello`: первое сообщение клиента, оно же главный носитель отпечатка.
///
/// `random` несёт соль, `session_id` — auth-тег, `extensions` — публичный ключ и
/// прочие поля профиля. Cipher-suites и порядок расширений берутся из браузерного
/// профиля.
pub(crate) struct ClientHello {
    pub _version: ProtocolVersion,
    /// 32 байта «random» = локальная соль клиента (для HKDF).
    pub random: [u8; 32],
    /// 32 байта: 16 случайных + 16 auth-тег (проверяется сервером).
    pub session_id: Bytes,
    /// Список cipher-suites (значения и порядок — часть JA3).
    pub cipher_suites: Vec<u16>,
    /// Сырые байты блока расширений (содержат KeyShare с pubkey).
    pub extensions: Bytes,
}

impl ClientHello {
    /// Сериализует `ClientHello` в тело handshake-сообщения с корректной
    /// 24-битной длиной (длина дописывается задним числом по `length_pos`).
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(512 + self.extensions.len());

        buf.put_u8(HANDSHAKE_TYPE_CLIENT_HELLO);

        let length_pos = buf.len();
        buf.put_bytes(0, 3);

        buf.put_u16(0x0303);
        buf.put_slice(&self.random);

        buf.put_u8(self.session_id.len() as u8);
        buf.put_slice(&self.session_id);

        buf.put_u16((self.cipher_suites.len() * 2) as u16);
        for &suite in &self.cipher_suites {
            buf.put_u16(suite);
        }

        buf.put_u8(1);
        buf.put_u8(0x00);

        buf.put_u16(self.extensions.len() as u16);
        buf.put_slice(&self.extensions);

        let total_len = (buf.len() - length_pos - 3) as u32;
        let len_bytes = total_len.to_be_bytes();

        buf[length_pos..length_pos + 3].copy_from_slice(&len_bytes[1..4]);

        buf.freeze()
    }

    /// Высокоуровневая сборка готового к отправке `ClientHello` (в TLS-записи).
    ///
    /// Кладёт соль в `random`, формирует `session_id` =
    /// `[1 версия протокола | 15 random | 16 auth-tag]`, затем через
    /// [`ExtensionBuilder`] собирает расширения по профилю (включая SNI=`host`
    /// и KeyShare с публичным ключом). `total_overhead` нужен билдеру, чтобы
    /// посчитать padding до целевого размера отпечатка.
    pub fn make_client_hello(profile: &BrowserProfile, host: &str, keys: &SessionKeys) -> Bytes {
        let tls_random = keys.local_salt();
        let mut session_id_bytes = [0u8; 32];

        // session_id[0] — заявленная версия протокола (см. crate::net_consts::PROTOCOL_VERSION):
        // не влияет на JA3/JA4 (значение session_id в отпечаток не входит, только
        // его длина), позволяет серверу узнать, какое "протокольное" поведение
        // клиент способен понять, до того как что-либо ему отправить.
        session_id_bytes[0] = keys.claimed_version();
        OsRng.fill_bytes(&mut session_id_bytes[1..16]);

        // session_id[16..32] = auth-тег: сервер проверит его первым делом и
        // отвергнет ClientHello без валидного тега. В схеме v3 тег считается на
        // секрете ноды и привязан к этому соединению (соль + KeyShare); в v2 —
        // старый тег от одного лишь времени. Выбор делает сам `SessionKeys` по
        // наличию учётных данных, см. `SessionKeys::handshake_tag`.
        session_id_bytes[16..].copy_from_slice(&keys.handshake_tag(&tls_random));

        // Цель паддинга (`profile.target_padding_len`) меряется в байтах
        // **payload TLS-записи**, а не всей записи вместе с её 5-байтовым
        // заголовком. RFC 7685 (и реализующий его BoringSSL) добивает
        // ClientHello так, чтобы payload записи был НЕ МЕНЬШЕ 512 байт —
        // именно затем, чтобы выскочить из диапазона 256..511, который часть
        // старых серверов принимает за SSLv2. На проводе это даёт запись 517.
        //
        // Раньше в `total_overhead` входили и эти 5 байт заголовка записи,
        // поэтому цель 512 достигалась целиком вместе с ним: Chrome-профиль
        // давал payload 507, Edge-профиль 511 — оба ВНУТРИ того самого
        // запрещённого диапазона, из которого паддинг обязан выводить.
        // Настоящий Chromium туда попасть не может по построению, так что
        // проверка «отпечаток Chromium И payload записи в 256..511» отделяла
        // нас от браузера одним пакетом и без единого ложного срабатывания.
        // Жребий GREASE тянется один раз и обслуживает и список шифронаборов,
        // и блок расширений: значение группы обязано совпасть в
        // `supported_groups` и `key_share` (см. `GreaseSet`), а строить их из
        // двух независимых жребиев — значит выдать себя рассогласованием.
        let grease = GreaseSet::random();

        let mut cipher_suites = Vec::with_capacity(profile.cipher_suites.len() + 1);
        if profile.has_grease {
            cipher_suites.push(grease.cipher);
        }
        cipher_suites.extend_from_slice(profile.cipher_suites);

        let handshake_header = 4;
        let client_hello_fixed = 2 + 32 + 1 + 32 + 2 + (cipher_suites.len() * 2) + 2 + 2;

        let total_overhead = handshake_header + client_hello_fixed;

        let mut ext_builder = ExtensionBuilder::with_grease(grease);

        ext_builder.apply_profile(profile, host, &keys.public_key_bytes(), total_overhead);

        let extensions_bytes = ext_builder.build();

        let client_hello = ClientHello {
            _version: ProtocolVersion::Tls12,
            random: tls_random,
            session_id: Bytes::copy_from_slice(&session_id_bytes),
            cipher_suites,
            extensions: extensions_bytes,
        };

        let record = TlsRecord::new(
            ContentType::Handshake,
            profile.record_layer_version,
            client_hello.serialize(),
        );

        record.serialize()
    }
}

/// Разбор входящего `ClientHello` (серверная сторона). `can_parse` «прыжковым
/// поиском» проходит по полям переменной длины (session_id → ciphers →
/// compression → extensions), не сдвигая курсор, и убеждается, что пришёл весь
/// блок; `parse` затем извлекает поля по-настоящему.
impl Parser for ClientHello {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        let mut reader = &bytes[..];

        // 34 = 2 (version) + 32 (random) — фиксированная «голова» перед session_id.
        if reader.len() < 35 {
            return false;
        }
        reader.advance(34);

        let sid_len = reader[0] as usize;
        reader.advance(1);
        if reader.len() < sid_len + 2 {
            return false;
        }
        reader.advance(sid_len);

        let ciphers_len = u16::from_be_bytes([reader[0], reader[1]]) as usize;
        reader.advance(2);
        if reader.len() < ciphers_len + 1 {
            return false;
        }
        reader.advance(ciphers_len);

        let comp_len = reader[0] as usize;
        reader.advance(1);
        if reader.len() < comp_len {
            return false;
        }
        reader.advance(comp_len);

        if reader.len() >= 2 {
            let ext_len = u16::from_be_bytes([reader[0], reader[1]]) as usize;
            reader.advance(2);
            if reader.len() < ext_len {
                return false;
            }
        }

        true
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let _version = ProtocolVersion::try_from(bytes.get_u16())
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Drop, Bytes::new()))?;

        let mut random = [0u8; 32];
        bytes.copy_to_slice(&mut random);

        let sid_len = bytes.get_u8() as usize;
        let session_id = bytes.split_to(sid_len).freeze();

        let c_len = bytes.get_u16() as usize;
        let mut cipher_suites = Vec::with_capacity(c_len / 2);
        let mut ciphers_data = bytes.split_to(c_len);
        while ciphers_data.has_remaining() {
            cipher_suites.push(ciphers_data.get_u16());
        }

        let cmp_len = bytes.get_u8() as usize;
        bytes.advance(cmp_len);

        let extensions = if bytes.remaining() >= 2 {
            let ext_len = bytes.get_u16() as usize;
            bytes.split_to(ext_len).freeze()
        } else {
            Bytes::new()
        };

        Ok(Some(Self {
            _version,
            random,
            session_id,
            cipher_suites,
            extensions,
        }))
    }
}

/// `ServerHello`: ответ сервера. Минимальный TLS 1.3-совместимый: всегда несёт
/// `supported_versions` и `key_share` (публичный ключ сервера), `random` = соль
/// сервера, а `session_id` эхом возвращается из `ClientHello`.
pub(crate) struct ServerHello {
    pub version: ProtocolVersion,
    /// 32 байта «random» = локальная соль сервера (для HKDF).
    pub random: [u8; 32],
    /// Эхо `session_id` клиента (так требует TLS 1.3).
    pub session_id: Bytes,
    /// Один выбранный cipher-suite.
    pub cipher_suite: u16,
    /// Блок расширений (supported_versions + key_share с pubkey сервера).
    pub extensions: BytesMut,
}
impl ServerHello {
    /// Высокоуровневая сборка готового к отправке `ServerHello` (в TLS-записи).
    pub fn make_server_hello(
        client_hello: &ClientHello,
        server_public_key: &[u8],
        salt: [u8; 32],
        profile: &ServerProfile,
    ) -> Bytes {
        let server_hello = Self::from_client_hello(client_hello, server_public_key, salt, profile);

        let record = TlsRecord::new(
            ContentType::Handshake,
            profile.record_layer_version,
            server_hello.serialize(),
        );

        record.serialize()
    }

    /// Конструирует `ServerHello` из принятого `ClientHello`.
    ///
    /// Выбор cipher-suite зависит от `honor_cipher_order`: либо берём первый из
    /// предпочтений сервера, который поддержал клиент, либо наоборот; fallback —
    /// `0x1301` (TLS_AES_128_GCM_SHA256). Дальше вручную пишутся два обязательных
    /// расширения: `supported_versions` (0x002b) и `key_share` (0x0033) с
    /// публичным ключом сервера по группе X25519 (0x001d).
    pub fn from_client_hello(
        client_hello: &ClientHello,
        server_public_key: &[u8],
        salt: [u8; 32],
        profile: &ServerProfile,
    ) -> Self {
        let server_random = salt;

        let selected_suite = if profile.honor_cipher_order {
            profile
                .cipher_suites
                .iter()
                .find(|&&suite| client_hello.cipher_suites.contains(&suite))
                .cloned()
                .unwrap_or(0x1301)
        } else {
            client_hello
                .cipher_suites
                .iter()
                .find(|&&suite| profile.cipher_suites.contains(&suite))
                .cloned()
                .unwrap_or(0x1301)
        };

        let mut extensions = BytesMut::new();

        let selected_version = profile.versions.max();

        extensions.put_u16(0x002b);
        extensions.put_u16(2);
        extensions.put_u16(selected_version as u16);

        let key_len = server_public_key.len() as u16;
        extensions.put_u16(0x0033);
        extensions.put_u16(key_len + 4);
        extensions.put_u16(0x001d);
        extensions.put_u16(key_len);
        extensions.put_slice(server_public_key);

        Self {
            version: ProtocolVersion::Tls12,
            random: server_random,
            session_id: client_hello.session_id.clone(),
            cipher_suite: selected_suite,
            extensions,
        }
    }

    /// Сериализует `ServerHello` в тело handshake с 24-битной длиной.
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(256 + self.extensions.len());

        buf.put_u8(HANDSHAKE_TYPE_SERVER_HELLO);

        let length_pos = buf.len();
        buf.put_slice(&[0, 0, 0]);

        buf.put_u16(self.version as u16);

        buf.put_slice(&self.random);

        buf.put_u8(self.session_id.len() as u8);
        buf.put_slice(&self.session_id);

        buf.put_u16(self.cipher_suite);

        buf.put_u8(0x00);

        if !self.extensions.is_empty() {
            buf.put_u16(self.extensions.len() as u16);
            buf.put_slice(&self.extensions);
        } else {
            buf.put_u16(0);
        }

        let total_handshake_body_len = (buf.len() - length_pos - 3) as u32;
        let len_bytes = total_handshake_body_len.to_be_bytes();
        buf[length_pos..length_pos + 3].copy_from_slice(&len_bytes[1..4]);

        buf.freeze()
    }
}

/// Разбор входящего `ServerHello` (клиентская сторона). Так же прыжками по полям
/// вычисляет полную длину сообщения, отрезает его (`split_to`) и читает поля;
/// из расширений потом достаётся публичный ключ сервера для ECDH.
impl Parser for ServerHello {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        // 34 = 2 (version) + 32 (random) перед длиной session_id.
        let mut offset = 34;
        if bytes.len() < offset + 1 {
            return false;
        }

        let session_id_len = bytes[offset] as usize;
        offset += 1 + session_id_len;

        offset += 3;

        if bytes.len() >= offset + 2 {
            let ext_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2 + ext_len;
        }

        bytes.len() >= offset
    }

    fn parse(bytes: &mut bytes::BytesMut) -> Result<Option<Self>, Self::Error> {
        let mut offset = 34;
        if bytes.len() < offset + 1 {
            return Ok(None);
        }
        let session_id_len = bytes[offset] as usize;
        offset += 1 + session_id_len;

        offset += 3;

        if bytes.len() >= offset + 2 {
            let ext_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2 + ext_len;
        }

        if bytes.len() < offset {
            return Ok(None);
        }

        let mut msg = bytes.split_to(offset);

        let version = ProtocolVersion::try_from(msg.get_u16())
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Drop, Bytes::new()))?;

        let mut random = [0u8; 32];
        msg.copy_to_slice(&mut random);

        let sid_len = msg.get_u8() as usize;
        let session_id = msg.split_to(sid_len).freeze();

        let cipher_suite = msg.get_u16();
        msg.advance(1);

        let extensions = if msg.remaining() >= 2 {
            let ext_len = msg.get_u16() as usize;
            msg.split_to(ext_len)
        } else {
            BytesMut::new()
        };

        Ok(Some(Self {
            version,
            random,
            session_id,
            cipher_suite,
            extensions,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionKeys;
    use crate::tlseng::ExtensionStack;
    use crate::{Identity, LocalIdentity, PeerIdentity};

    fn parse_client_hello_record(wire: &Bytes) -> (ClientHello, ExtensionStack) {
        let mut record_buf = BytesMut::from(&wire[..]);
        let record = TlsRecord::parse(&mut record_buf).unwrap().unwrap();
        let mut body = BytesMut::from(record.payload.as_ref());
        HelloHeader::parse(&mut body).unwrap().unwrap();
        let hello = ClientHello::parse(&mut body).unwrap().unwrap();
        let ext = ExtensionStack::parse(&mut BytesMut::from(hello.extensions.as_ref()))
            .unwrap()
            .unwrap();
        (hello, ext)
    }

    fn parse_server_hello_record(wire: &Bytes) -> (ServerHello, ExtensionStack) {
        let mut record_buf = BytesMut::from(&wire[..]);
        let record = TlsRecord::parse(&mut record_buf).unwrap().unwrap();
        let mut body = BytesMut::from(record.payload.as_ref());
        HelloHeader::parse(&mut body).unwrap().unwrap();
        let hello = ServerHello::parse(&mut body).unwrap().unwrap();
        let ext = ExtensionStack::parse(&mut BytesMut::from(hello.extensions.as_ref()))
            .unwrap()
            .unwrap();
        (hello, ext)
    }

    /// Полный цикл "как в проде": клиент строит ClientHello → сервер его
    /// разбирает и строит ServerHello → клиент разбирает ServerHello. Обе
    /// стороны должны вывести идентичные AEAD-параметры (крест-накрест: tx
    /// одной стороны == rx другой) и общий auth_key.
    #[test]
    fn chromium_client_hello_escapes_the_rfc7685_forbidden_range() {
        // RFC 7685 существует ровно затем, чтобы ClientHello не оставался в
        // диапазоне 256..511 байт payload записи; BoringSSL добивает его до 512,
        // что на проводе даёт запись 517. Раньше Chrome-профиль давал 507, а
        // Edge-профиль 511 — оба ВНУТРИ запрещённого диапазона, куда настоящий
        // Chromium попасть не может. Проверка «отпечаток Chromium И payload в
        // 256..511» отделяла нас от браузера одним пакетом без ложных
        // срабатываний.
        for (name, profile) in [
            ("Chrome 131", &BrowserProfile::CHROME_131),
            ("Edge 130", &BrowserProfile::EDGE_130),
        ] {
            for host in [
                "a.co",
                "example.com",
                "www.debian.org",
                "very-long-subdomain.example.organization.test",
            ] {
                let keys = SessionKeys::new(true);
                let wire = ClientHello::make_client_hello(profile, host, &keys);
                let record_payload = u16::from_be_bytes([wire[3], wire[4]]) as usize;

                assert_eq!(
                    record_payload, 512,
                    "{name} / SNI {host}: payload записи обязан быть ровно 512"
                );
                assert_eq!(
                    wire.len(),
                    517,
                    "{name} / SNI {host}: запись на проводе обязана быть 517 байт"
                );
            }
        }
    }

    #[test]
    fn padding_is_the_last_extension_in_every_profile_that_uses_it() {
        // Длина паддинга вычисляется под целевой размер всего ClientHello,
        // поэтому любое расширение после него промахивает цель ровно на свою
        // длину. Именно так Edge-профиль давал 511 вместо 512: за PADDING стоял
        // завершающий GREASE на 4 байта. BoringSSL по той же причине всегда
        // добавляет padding последним.
        for profile in BrowserProfile::ALL {
            let order = profile.extension_order.0;
            if let Some(pos) = order
                .iter()
                .position(|&e| e == crate::tlseng::types::TlsExtensions::PADDING)
            {
                assert_eq!(
                    pos,
                    order.len() - 1,
                    "PADDING обязан быть последним в порядке расширений"
                );
            }
        }
    }

    #[test]
    fn full_handshake_round_trip_derives_matching_keys() {
        for profile in BrowserProfile::ALL {
            let client_keys = SessionKeys::new(true);
            let ch_wire = ClientHello::make_client_hello(profile, "example.com", &client_keys);
            let (client_hello, client_ext) = parse_client_hello_record(&ch_wire);

            assert_eq!(client_hello.session_id.len(), 32);
            // Клиент без учётных данных ноды обязан заявлять анонимную схему:
            // иначе нода потребует ключевой тег, посчитать который ему нечем.
            assert_eq!(
                client_hello.session_id[0],
                crate::net_consts::PROTOCOL_VERSION_ANONYMOUS
            );
            // GREASE-шифронабор идёт первым, за ним — список профиля без
            // изменений. Так делает Chromium; сравнивать весь вектор с
            // `profile.cipher_suites` больше нельзя — этот тест кодировал
            // допущение «GREASE только в расширениях», из-за которого профиль
            // и не совпадал с живым браузером.
            if profile.has_grease {
                assert!(
                    crate::tlseng::types::TlsExtensions::is_grease(client_hello.cipher_suites[0]),
                    "первым шифронабором Chromium кладёт GREASE, получено 0x{:04x}",
                    client_hello.cipher_suites[0]
                );
                assert_eq!(&client_hello.cipher_suites[1..], profile.cipher_suites);
            } else {
                assert_eq!(client_hello.cipher_suites, profile.cipher_suites);
            }

            let mut server_keys = SessionKeys::new(false);
            server_keys
                .update_keys(client_hello.random, &client_ext, true)
                .expect("server key derivation must succeed from a real ClientHello");
            let server_pub = server_keys.public_key_bytes();
            let sh_wire = ServerHello::make_server_hello(
                &client_hello,
                &server_pub,
                server_keys.local_salt(),
                &ServerProfile::MODERN,
            );

            let (server_hello, server_ext) = parse_server_hello_record(&sh_wire);
            assert_eq!(&server_hello.session_id[..], &client_hello.session_id[..]);

            let mut client_keys = client_keys;
            client_keys
                .update_keys(server_hello.random, &server_ext, false)
                .expect("client key derivation must succeed from a real ServerHello");

            let (c_tx_k, c_tx_iv, c_rx_k, c_rx_iv) = client_keys.get_aead_parameters();
            let (s_tx_k, s_tx_iv, s_rx_k, s_rx_iv) = server_keys.get_aead_parameters();

            assert_eq!(c_tx_k, s_rx_k, "client tx key must equal server rx key");
            assert_eq!(c_tx_iv, s_rx_iv, "client tx iv must equal server rx iv");
            assert_eq!(c_rx_k, s_tx_k, "client rx key must equal server tx key");
            assert_eq!(c_rx_iv, s_tx_iv, "client rx iv must equal server tx iv");
            assert_eq!(
                client_keys.get_auth_key(),
                server_keys.get_auth_key(),
                "both sides must derive the same auth_key"
            );
        }
    }

    #[test]
    fn tampered_auth_tag_in_session_id_is_rejected_by_server() {
        use crate::crypto::SessionAuth;

        let client_keys = SessionKeys::new(true);
        let ch_wire = ClientHello::make_client_hello(
            &BrowserProfile::CHROME_131,
            "example.com",
            &client_keys,
        );
        let (client_hello, _ext) = parse_client_hello_record(&ch_wire);

        let mut tampered = client_hello.session_id.to_vec();
        tampered[20] ^= 0xFF; // flip a byte inside the auth tag (bytes 16..32)

        let auth = SessionAuth::new(client_keys.get_auth_key());
        let mut received_tag = [0u8; 16];
        received_tag.copy_from_slice(&tampered[16..32]);
        assert!(
            !auth.verify_tag(&received_tag),
            "a tampered auth tag must not verify"
        );
    }

    // ==================================================================
    // Протокол v3: аутентифицированный хендшейк
    // ==================================================================

    /// Пара учётных данных одной ноды: то, что лежит на ней самой, и то, что
    /// бэкенд отдаёт её клиентам.
    fn identity_pair(
        node_secret: [u8; 32],
        node_private: [u8; 32],
        strict: bool,
    ) -> (Identity, Identity) {
        let local = LocalIdentity::from_hex(
            &hex::encode(node_secret),
            &hex::encode(node_private),
            strict,
        )
        .expect("valid hex credentials");
        let peer = PeerIdentity::from_hex(&hex::encode(node_secret), &local.public_key_hex())
            .expect("valid hex credentials");
        (Identity::Peer(peer), Identity::Local(local))
    }

    /// Прогоняет полный обмен ClientHello/ServerHello и возвращает выведенные
    /// обеими сторонами AEAD-ключи. `server_identity` — то, чем отвечающая
    /// сторона представляется: в тесте на MITM сюда подставляется чужая.
    fn run_handshake(
        client_identity: Option<Identity>,
        server_identity: Option<Identity>,
    ) -> (SessionKeys, SessionKeys) {
        let client_keys = match client_identity {
            Some(id) => SessionKeys::with_identity(true, id),
            None => SessionKeys::new(true),
        };
        let ch_wire = ClientHello::make_client_hello(
            &BrowserProfile::CHROME_131,
            "example.com",
            &client_keys,
        );
        let (client_hello, client_ext) = parse_client_hello_record(&ch_wire);

        let mut server_keys = match server_identity {
            Some(id) => SessionKeys::with_identity(false, id),
            None => SessionKeys::new(false),
        };
        server_keys.set_peer_version(client_hello.session_id[0]);
        server_keys
            .update_keys(client_hello.random, &client_ext, true)
            .expect("server key derivation must succeed");

        let server_pub = server_keys.public_key_bytes();
        let sh_wire = ServerHello::make_server_hello(
            &client_hello,
            &server_pub,
            server_keys.local_salt(),
            &ServerProfile::MODERN,
        );
        let (server_hello, server_ext) = parse_server_hello_record(&sh_wire);

        let mut client_keys = client_keys;
        client_keys
            .update_keys(server_hello.random, &server_ext, false)
            .expect("client key derivation must succeed");

        (client_keys, server_keys)
    }

    #[test]
    fn v3_handshake_derives_matching_keys_and_claims_version_3() {
        let (peer, local) = identity_pair([7u8; 32], [9u8; 32], true);

        let client_keys = SessionKeys::with_identity(true, peer.clone());
        let ch_wire = ClientHello::make_client_hello(
            &BrowserProfile::CHROME_131,
            "example.com",
            &client_keys,
        );
        let (client_hello, _) = parse_client_hello_record(&ch_wire);
        assert_eq!(
            client_hello.session_id[0],
            crate::net_consts::PROTOCOL_VERSION,
            "клиент с учётными данными обязан заявлять v3"
        );
        // Раскладка `session_id` не изменилась: те же 32 байта, тег на том же
        // месте. Схема v3 не стоит на проводе ни одного лишнего байта.
        assert_eq!(client_hello.session_id.len(), 32);

        let (client_keys, server_keys) = run_handshake(Some(peer), Some(local));
        let (c_tx_k, _, c_rx_k, _) = client_keys.get_aead_parameters();
        let (s_tx_k, _, s_rx_k, _) = server_keys.get_aead_parameters();

        assert_eq!(c_tx_k, s_rx_k);
        assert_eq!(c_rx_k, s_tx_k);
        assert_eq!(client_keys.get_auth_key(), server_keys.get_auth_key());
    }

    /// Главный тест на активного посредника.
    ///
    /// Атакующий знает секрет ноды — предполагаем худшее, он разобрал
    /// клиентский конфиг, — поэтому валидный тег `ClientHello` он построить
    /// может и до обмена ключами его ничто не останавливает. Чего у него нет,
    /// так это приватного статического ключа ноды. Без него второй DH у сторон
    /// расходится, а с ним и все ключи сессии: клиент шифрует тем, что
    /// посредник расшифровать не в состоянии.
    ///
    /// До v3 этот тест был бы зелёным в обратную сторону — ключи совпадали бы,
    /// потому что сходиться им было не с чем.
    #[test]
    fn mitm_without_the_node_private_key_derives_different_keys() {
        let node_secret = [7u8; 32];
        let (peer_of_real_node, _real_node) = identity_pair(node_secret, [9u8; 32], true);
        // Тот же секрет входа, другой статический ключ — ровно то, чем
        // располагает посредник.
        let (_, impostor) = identity_pair(node_secret, [42u8; 32], true);

        let (client_keys, impostor_keys) = run_handshake(Some(peer_of_real_node), Some(impostor));

        let (c_tx_k, _, c_rx_k, _) = client_keys.get_aead_parameters();
        let (i_tx_k, _, i_rx_k, _) = impostor_keys.get_aead_parameters();

        assert_ne!(
            c_tx_k, i_rx_k,
            "посредник без статического ключа ноды не должен вывести ключ чтения клиента"
        );
        assert_ne!(
            c_rx_k, i_tx_k,
            "и ключ, которым клиент читает, тоже не должен сойтись"
        );
        assert_ne!(client_keys.get_auth_key(), impostor_keys.get_auth_key());
    }

    /// Клиент, у которого есть учётные данные, не должен сходиться с нодой,
    /// которая их не настроила: это несовпадение конфигурации, и падать оно
    /// обязано в сторону отказа, а не молчаливого отката на анонимную схему.
    #[test]
    fn v3_client_does_not_match_an_anonymous_node() {
        let (peer, _) = identity_pair([7u8; 32], [9u8; 32], true);
        let (client_keys, server_keys) = run_handshake(Some(peer), None);

        let (c_tx_k, _, _, _) = client_keys.get_aead_parameters();
        let (_, _, s_rx_k, _) = server_keys.get_aead_parameters();
        assert_ne!(c_tx_k, s_rx_k);
    }

    #[test]
    fn handshake_tag_requires_the_node_secret() {
        let (peer, local) = identity_pair([7u8; 32], [9u8; 32], true);
        // Нода с другим секретом входа — например, тег посчитан для соседней
        // ноды или клиент не обновил конфиг после ротации.
        let (_, other_node) = identity_pair([8u8; 32], [9u8; 32], true);

        let client_keys = SessionKeys::with_identity(true, peer);
        let ch_wire = ClientHello::make_client_hello(
            &BrowserProfile::CHROME_131,
            "example.com",
            &client_keys,
        );
        let (client_hello, client_ext) = parse_client_hello_record(&ch_wire);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&client_hello.session_id[16..32]);
        let peer_public = SessionKeys::extract_peer_public(&client_ext, true).unwrap();

        let mut right = SessionKeys::with_identity(false, local);
        right.set_peer_version(client_hello.session_id[0]);
        assert!(
            right.verify_handshake_tag(&tag, &client_hello.random, &peer_public),
            "своя нода обязана принять тег"
        );

        let mut wrong = SessionKeys::with_identity(false, other_node);
        wrong.set_peer_version(client_hello.session_id[0]);
        assert!(
            !wrong.verify_handshake_tag(&tag, &client_hello.random, &peer_public),
            "нода с другим секретом обязана отвергнуть тег"
        );
    }

    /// Тег привязан к соединению: перехваченный `ClientHello` нельзя переиграть,
    /// подставив свой KeyShare, хотя окно валидности по времени ещё открыто.
    #[test]
    fn handshake_tag_is_bound_to_the_client_keyshare() {
        let (peer, local) = identity_pair([7u8; 32], [9u8; 32], true);

        let client_keys = SessionKeys::with_identity(true, peer);
        let ch_wire = ClientHello::make_client_hello(
            &BrowserProfile::CHROME_131,
            "example.com",
            &client_keys,
        );
        let (client_hello, client_ext) = parse_client_hello_record(&ch_wire);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&client_hello.session_id[16..32]);
        let mut replayed_public = SessionKeys::extract_peer_public(&client_ext, true).unwrap();
        replayed_public[0] ^= 0xFF;

        let mut node = SessionKeys::with_identity(false, local);
        node.set_peer_version(client_hello.session_id[0]);
        assert!(
            !node.verify_handshake_tag(&tag, &client_hello.random, &replayed_public),
            "тег с чужим KeyShare не должен проходить"
        );
    }

    /// Переходный режим раскатки и его финал: пока `strict` выключен, нода
    /// принимает клиентов старой схемы (иначе апгрейд парка невозможен), после
    /// включения — перестаёт, и downgrade по заявленной версии закрывается.
    #[test]
    fn strict_mode_decides_the_fate_of_anonymous_clients() {
        let anonymous_client = SessionKeys::new(true);
        let ch_wire = ClientHello::make_client_hello(
            &BrowserProfile::CHROME_131,
            "example.com",
            &anonymous_client,
        );
        let (client_hello, client_ext) = parse_client_hello_record(&ch_wire);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&client_hello.session_id[16..32]);
        let peer_public = SessionKeys::extract_peer_public(&client_ext, true).unwrap();

        for (strict, expected) in [(false, true), (true, false)] {
            let (_, local) = identity_pair([7u8; 32], [9u8; 32], strict);
            let mut node = SessionKeys::with_identity(false, local);
            node.set_peer_version(client_hello.session_id[0]);
            assert_eq!(
                node.verify_handshake_tag(&tag, &client_hello.random, &peer_public),
                expected,
                "strict={strict}: анонимный клиент должен быть {}",
                if expected {
                    "принят"
                } else {
                    "отвергнут"
                }
            );
        }
    }

    #[test]
    #[ignore = "проверяет точное совпадение с живым захватом Chrome; в публичной копии \
                калибровка (BrowserProfile::CHROME_140 и связанные ExtensionOrder/TlsGroups/\
                TlsSignatures) заменена заглушками, см. README — тест закономерно не пройдёт"]
    fn chrome_client_hello_matches_the_live_capture_shape() {
        use crate::tlseng::types::TlsExtensions;
        let keys = SessionKeys::new(true);
        let wire = ClientHello::make_client_hello(
            &BrowserProfile::CHROME_140,
            "chrome.cloudflare-dns.com",
            &keys,
        );
        assert!(
            (1650..=1850).contains(&wire.len()),
            "ClientHello {} B — вне диапазона живого Chrome (~1741)",
            wire.len()
        );
        let (ch, ext) = parse_client_hello_record(&wire);
        assert!(TlsExtensions::is_grease(ch.cipher_suites[0]));
        assert_eq!(ch.cipher_suites.len(), 16);
        let groups = ext
            .find_by_type(TlsExtensions::SUPPORTED_GROUPS)
            .expect("supported_groups обязан быть");
        let g0 = u16::from_be_bytes([groups[2], groups[3]]);
        let g1 = u16::from_be_bytes([groups[4], groups[5]]);
        assert!(TlsExtensions::is_grease(g0), "первая группа — GREASE");
        assert_eq!(g1, 0x11ec, "за GREASE идёт X25519MLKEM768");
        let ks = ext
            .find_by_type(TlsExtensions::KEY_SHARE)
            .expect("key_share обязан быть");
        let ks_g0 = u16::from_be_bytes([ks[2], ks[3]]);
        assert_eq!(
            ks_g0, g0,
            "GREASE-группа в key_share совпадает с supported_groups"
        );
        assert!(
            ks.windows(2).any(|w| w == [0x11, 0xec]),
            "key_share несёт X25519MLKEM768"
        );
        assert!(
            ks.len() > 1240,
            "key_share без PQ-балласта мал: {}",
            ks.len()
        );
        assert!(
            ext.find_by_type(TlsExtensions::ECH).is_some(),
            "ECH есть всегда"
        );
    }
}
