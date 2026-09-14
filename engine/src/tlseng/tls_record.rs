//! Слой TLS-записи — самый внешний «конверт» на проводе.
//!
//! Каждая TLS-запись начинается с 5-байтового заголовка
//! `content_type(1) | version(2) | length(2)`, за которым идёт `payload`. Здесь
//! это (де)сериализуется. [`TlsRecord`] — полноценная запись с проверкой типа и
//! длины, а [`ApplicationData`] — лёгкий «сырой payload» для горячего пути data-фазы
//! (когда тип уже известен и проверять нечего).

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    errors::{ErrorAction, ErrorStage, TlsError},
    parser::Parser,
    tlseng::types::{ContentType, ProtocolVersion},
};

/// Разобранная TLS-запись: заголовок + полезная нагрузка.
#[derive(Debug)]
pub struct TlsRecord {
    /// Тип записи (`Handshake`/`ApplicationData`/`Alert`).
    pub content_type: ContentType,
    /// Версия из заголовка записи (как правило `Tls12` для маскировки).
    pub version: ProtocolVersion,
    /// Длина payload из заголовка (поле сохранено для отладки; имя с `_`).
    pub _len: u16,
    /// Тело записи (zero-copy ссылка в исходный буфер).
    pub payload: Bytes,
}

impl TlsRecord {
    pub fn new(content_type: ContentType, version: ProtocolVersion, payload: Bytes) -> Self {
        Self {
            content_type,
            version,
            _len: payload.len() as u16,
            payload,
        }
    }

    /// Сериализует запись в байты: `type | version | len | payload`.
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + self.payload.len());

        buf.put_u8(self.content_type as u8);
        buf.put_u16(self.version as u16);
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    /// Удобный конструктор: оборачивает готовый шифртекст в запись
    /// `ApplicationData` (версия маскируется под TLS 1.2) и сериализует.
    pub fn build_application_data(payload: Bytes) -> Bytes {
        netrunner_logger::trace!(payload_len = payload.len(), "Building TlsRecord from Bytes");

        let record = Self::new(
            ContentType::ApplicationData,
            ProtocolVersion::Tls12,
            payload,
        );
        record.serialize()
    }

    /// Готовые байты фиктивной записи `ChangeCipherSpec` (`14 03 03 00 01 01`) —
    /// ровно то, что шлёт настоящий Chrome/Firefox сразу после своего Hello
    /// (см. doc на [`ContentType::ChangeCipherSpec`]).
    pub fn build_change_cipher_spec() -> Bytes {
        let record = Self::new(
            ContentType::ChangeCipherSpec,
            ProtocolVersion::Tls12,
            Bytes::from_static(&[0x01]),
        );
        record.serialize()
    }
}

/// Разбор записи. `can_parse` проверяет валидность типа и наличие всех байт
/// (для `ApplicationData` дополнительно требует ≥17 байт — минимум под AEAD-тег
/// и непустой шифртекст). Ошибка типа/версии → [`ErrorAction::Redirect`]: это
/// похоже не на наш трафик, поэтому проксируем как обычный TLS, а не рвём.
impl Parser for TlsRecord {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < 5 {
            return false;
        }

        let content_type = bytes[0];
        let is_valid_type = content_type == ContentType::Handshake as u8
            || content_type == ContentType::ApplicationData as u8
            || content_type == ContentType::Alert as u8
            || content_type == ContentType::ChangeCipherSpec as u8;

        if !is_valid_type {
            return false;
        }

        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;

        if content_type == ContentType::ApplicationData as u8 && record_len < 17 {
            return false;
        }

        bytes.len() >= 5 + record_len
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<TlsRecord>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let raw_content_type = bytes.get_u8();
        let raw_version = bytes.get_u16();
        let record_len = bytes.get_u16() as usize;

        let content_type = ContentType::try_from(raw_content_type)
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Redirect, Bytes::new()))?;

        let version = ProtocolVersion::try_from(raw_version)
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Redirect, Bytes::new()))?;

        let payload = bytes.split_to(record_len).freeze();

        Ok(Some(TlsRecord::new(content_type, version, payload)))
    }
}

/// «Сырой» payload записи `ApplicationData` без повторной валидации.
///
/// Используется в горячем пути: тип записи уже проверен выше, и кодеку нужен
/// только зашифрованный кадр. Парсер просто забирает весь буфер целиком.
pub struct ApplicationData {
    pub _len: usize,
    pub payload: Bytes,
}

impl Parser for ApplicationData {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        !bytes.is_empty()
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        let _len = bytes.len();
        if _len == 0 {
            return Ok(None);
        }
        let payload = bytes.split_to(_len).freeze();
        Ok(Some(Self { _len, payload }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_data_round_trip() {
        let payload = Bytes::from_static(b"hello ciphertext + 16-byte tag!!");
        let wire = TlsRecord::build_application_data(payload.clone());

        let mut buf = BytesMut::from(&wire[..]);
        let record = TlsRecord::parse(&mut buf).unwrap().unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.payload, payload);
        assert!(buf.is_empty(), "parse must consume exactly one record");
    }

    #[test]
    fn change_cipher_spec_exact_bytes() {
        // Реальный Chrome/Firefox шлют ровно эти 6 байт — если когда-нибудь
        // поменяются, это должно быть осознанное решение, а не регрессия.
        let wire = TlsRecord::build_change_cipher_spec();
        assert_eq!(&wire[..], &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn change_cipher_spec_round_trip() {
        let wire = TlsRecord::build_change_cipher_spec();
        let mut buf = BytesMut::from(&wire[..]);
        let record = TlsRecord::parse(&mut buf).unwrap().unwrap();

        assert_eq!(record.content_type, ContentType::ChangeCipherSpec);
        assert_eq!(&record.payload[..], &[0x01]);
    }

    #[test]
    fn incomplete_record_is_none_not_error() {
        let wire = TlsRecord::build_application_data(Bytes::from_static(b"0123456789abcdef+"));
        // Отрезаем последний байт — запись объявляет себя длиннее, чем есть на самом деле.
        let mut buf = BytesMut::from(&wire[..wire.len() - 1]);
        assert!(TlsRecord::parse(&mut buf).unwrap().is_none());
        // Буфер не должен быть тронут при "рано".
        assert_eq!(buf.len(), wire.len() - 1);
    }

    #[test]
    fn application_data_below_min_len_is_none() {
        // < 17 байт payload у ApplicationData — заведомо меньше AEAD-тега,
        // can_parse должен отказать ещё до попытки распознать content-type.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[ContentType::ApplicationData as u8, 0x03, 0x03, 0x00, 0x05]);
        buf.extend_from_slice(&[0u8; 5]);
        assert!(!TlsRecord::can_parse(&buf));
    }

    #[test]
    fn unknown_content_type_is_rejected() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x99, 0x03, 0x03, 0x00, 0x01, 0x00]);
        assert!(!TlsRecord::can_parse(&buf));
    }

    #[test]
    fn raw_application_data_parser_takes_whole_buffer() {
        let mut buf = BytesMut::from(&b"anything at all"[..]);
        let parsed = ApplicationData::parse(&mut buf).unwrap().unwrap();
        assert_eq!(&parsed.payload[..], &b"anything at all"[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn raw_application_data_parser_empty_is_none() {
        let mut buf = BytesMut::new();
        assert!(ApplicationData::parse(&mut buf).unwrap().is_none());
    }
}
