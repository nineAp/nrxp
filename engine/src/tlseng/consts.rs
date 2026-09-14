//! Точечные wire-константы TLS, не попавшие в крупные наборы [`types`](super::types).
//!
//! Это «магические числа» из спецификации, вынесенные в именованные константы,
//! чтобы код сборки расширений и hello-сообщений читался без обращения к RFC.

/// Тип handshake-сообщения `ClientHello`.
pub(crate) const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// Тип handshake-сообщения `ServerHello`.
pub(crate) const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// Тип записи имени в расширении SNI — `host_name`.
pub(crate) const TYPE_HOST_NAME: u8 = 0x00;

/// Режим PSK `psk_dhe_ke` (обмен ключами с DHE) в расширении `psk_key_exchange_modes`.
pub(crate) const PSK_DHE_KE_MODE: u8 = 0x01;

/// Алгоритм сжатия сертификата Brotli (`compress_certificate`).
pub(crate) const CERT_COMPRESSION_BROTLI: u16 = 0x0002;

/// Тип запроса OCSP (`status_request`) — `ocsp`.
pub(crate) const OCSP_STATUS_TYPE: u8 = 0x01;
