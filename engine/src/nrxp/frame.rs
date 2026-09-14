//! Кадр NRXP: структура и (де)сериализация.
//!
//! Полный байтовый формат см. в [обзоре модуля](super). Здесь — типы кадра и две
//! зеркальные операции:
//! - [`Frame::into_bytes`] — собрать заголовок + payload + случайный padding в
//!   единый [`BytesMut`] (заготовка под последующее AEAD-шифрование на месте);
//! - реализации [`Parser`] для [`FrameHeader`] и [`Frame`] — разобрать буфер
//!   обратно в кадр, не копируя payload лишний раз (zero-copy через `split_to`).
//!
//! Весь файл написан под zero-copy/zero-alloc на горячем пути.

use crate::parser::Parser;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;

/// Тип кадра — первый байт после `stream_id`. Числовые значения фиксированы и
/// являются частью wire-формата (менять — это смена версии протокола).
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub(crate) enum FrameType {
    /// Открыть TCP-поток к цели (payload — адрес назначения).
    Connect = 0x00,
    /// Данные TCP-потока.
    Data = 0x01,
    /// Закрыть поток (FIN/abort).
    Close = 0x02,
    /// Keep-alive; держит туннель живым и измеряет RTT.
    Heartbeat = 0x03,
    /// Открыть UDP-«сессию» к цели.
    UdpConnect = 0x04,
    /// Датаграмма UDP-сессии.
    UdpData = 0x05,
    /// Диагностический отчёт клиента (один JSON-снапшот в payload). Холодный
    /// путь: едет по контрольному каналу, сервер сохраняет его в пер-сессионный
    /// файл. Никогда не маршрутизируется в локальные сокеты.
    Diag = 0x06,
    /// Кредит потока для сквозного flow-control (payload — `u32` BE, "можешь
    /// прислать ещё N байт"). Отправляется приёмной стороной по мере
    /// освобождения локального буфера — см. `Muxer::grant_credit`/`consume_credit`.
    Credit = 0x07,
    /// Кадр-пустышка: несёт только набивку и существует ради формы трафика,
    /// а не ради данных. Получатель молча его отбрасывает.
    ///
    /// Зачем: в настоящем TLS 1.3 сервер сразу после `ServerHello` отправляет
    /// `EncryptedExtensions` + `Certificate` + `CertificateVerify` + `Finished`,
    /// и всё это едет записями с content-type `ApplicationData` — то есть
    /// **первую запись ApplicationData в сессии всегда шлёт сервер**, и весит
    /// его первый flight порядка 1–5 КБ. Без этих кадров наш сервер отвечал
    /// 127-байтовым `ServerHello`, 6-байтовым CCS и замолкал до первого слова
    /// клиента: булев признак с нулевой ошибкой, обесценивающий сколь угодно
    /// точную мимикрию `ClientHello`.
    ///
    /// Тип введён в версии протокола 2 (см. [`crate::MIN_VERSION_FOR_COVER`]):
    /// клиенту, объявившему версию 1, такие кадры не отправляются — он бы не
    /// разобрал неизвестный тип и уронил ногу.
    Cover = 0x08,
}

/// Разобранный заголовок кадра (25 байт). Поля идут в том же порядке, что и в wire.
#[derive(Copy, Clone)]
pub(crate) struct FrameHeader {
    /// Time-based HMAC-тег (анти-replay). Проверяется приёмной стороной.
    pub(crate) auth_tag: [u8; 16],
    /// Идентификатор логического потока внутри туннеля.
    pub(crate) stream_id: u32,
    /// Длина полезной нагрузки в байтах.
    pub(crate) payload_len: u16,
    /// Длина случайного padding после payload (0 для Data/UdpData).
    pub(crate) padding_len: u16,
    /// Тип кадра.
    pub(crate) frame_type: FrameType,
}

/// Полный разобранный кадр: заголовок + payload (без padding — он отбрасывается).
pub(crate) struct Frame {
    /// Полезная нагрузка как [`Bytes`] (zero-copy ссылка на исходный буфер).
    pub(crate) payload: Bytes,
    /// Разобранный заголовок.
    pub(crate) header: FrameHeader,
}

// Размеры полей заголовка в байтах (см. формат в обзоре модуля).
const AUTH_TAG_SIZE: u16 = 16;
const STREAM_ID_SIZE: u16 = 4;
const FRAME_TYPE_SIZE: u16 = 1;
const PAYLOAD_LEN_SIZE: u16 = 2;
const PADDING_LEN_SIZE: u16 = 2;

/// Суммарный размер заголовка кадра — 25 байт.
pub const FRAME_HEADER_SIZE: u16 =
    AUTH_TAG_SIZE + STREAM_ID_SIZE + FRAME_TYPE_SIZE + PAYLOAD_LEN_SIZE + PADDING_LEN_SIZE; // 25 bytes

/// Потолок открытого текста одной TLS-записи — 2^14 + 1 байт.
///
/// Ровно столько выдаёт конформный TLS 1.3: `content` до 2^14 плюс байт
/// `content_type` в `TLSInnerPlaintext` (RFC 8446 §5.2). С 16-байтовым
/// AEAD-тегом это даёт поле длины записи 16401 — верхнюю границу, которую
/// реально видно в дампах браузерного HTTPS.
///
/// Раньше кадр мог занять 16384 байта payload, что после заголовка и тега
/// давало поле длины **16425** — значение, недостижимое ни для одного
/// браузера (record-padding TLS 1.3 они не применяют), то есть константный
/// маркер в открытом виде. Ограничение введено, чтобы максимальная запись
/// совпадала с настоящей байт-в-байт.
pub const MAX_RECORD_PLAINTEXT: usize = (1 << 14) + 1;

/// Потолок payload одного кадра: столько остаётся от [`MAX_RECORD_PLAINTEXT`]
/// после 25-байтового заголовка. Кадр максимального размера занимает запись
/// целиком, поле длины при этом равно 16401.
pub const MAX_FRAME_PAYLOAD: usize = MAX_RECORD_PLAINTEXT - FRAME_HEADER_SIZE as usize; // 16360

impl Frame {
    /// Конструирует кадр с нулевым `auth_tag` и `padding_len` — оба заполняются
    /// позже в [`into_bytes`](Frame::into_bytes) при сериализации.
    #[inline(always)]
    pub(crate) fn new(stream_id: u32, frame_type: FrameType, payload: Bytes) -> Self {
        Self {
            header: FrameHeader {
                auth_tag: [0u8; 16],
                stream_id,
                payload_len: payload.len() as u16,
                padding_len: 0,
                frame_type,
            },
            payload,
        }
    }

    /// Размер кадра на проводе (до шифрования) при заданном паддинге.
    #[inline(always)]
    pub(crate) fn wire_len(payload_len: usize, padding_len: u16) -> usize {
        FRAME_HEADER_SIZE as usize + payload_len + padding_len as usize
    }

    /// Сериализует кадр в [`BytesMut`], готовый к шифрованию на месте.
    ///
    /// `auth_key` здесь — это уже готовый 16-байтовый тег (имя историческое),
    /// который кладётся в начало заголовка. `padding_len` задаётся **снаружи**:
    /// решение о набивке принимает кодек, и принимает его на уровне целой
    /// TLS-записи, а не отдельного кадра — см. `nrxp::codec::PadGrid`. Кадр
    /// знает только, сколько случайных байт дописать в хвост.
    ///
    /// Раньше набивка считалась здесь же: `Data`/`UdpData` выравнивались до
    /// ближайшего бакета из фиксированного набора {256…8192}, остальные типы
    /// получали 0..255 случайных байт. Поскольку одна запись несла ровно один
    /// кадр, длина записи получалась равной `бакет + 41` — то есть в открытом
    /// поле длины TLS-записи наблюдалась арифметическая инварианта
    /// «длина − 41 равна степени двойки». Набор возможных длин был при этом
    /// одинаков для всех соединений и всех развёртываний. Именно поэтому
    /// решение перенесено на уровень записи и рандомизировано на соединение.
    ///
    /// Буфер выделяется один раз точно под итоговый размер; заголовок
    /// собирается на стеке и пишется одним `copy_from_slice`.
    #[inline]
    pub(crate) fn into_bytes(mut self, auth_key: &[u8; 16], padding_len: u16) -> BytesMut {
        self.header.padding_len = padding_len;

        let total_size = Self::wire_len(self.payload.len(), padding_len);
        let mut buf = BytesMut::with_capacity(total_size);

        // Заголовок собирается на стеке и пишется в буфер одним copy_from_slice,
        // а не полем за полем — так компилятору не нужно проверять границы буфера
        // на каждую отдельную запись.
        let mut header_buf = [0u8; 25];
        header_buf[0..16].copy_from_slice(auth_key);
        header_buf[16..20].copy_from_slice(&self.header.stream_id.to_be_bytes());
        header_buf[20] = self.header.frame_type as u8;
        header_buf[21..23].copy_from_slice(&self.header.payload_len.to_be_bytes());
        header_buf[23..25].copy_from_slice(&self.header.padding_len.to_be_bytes());

        buf.put_slice(&header_buf);
        buf.put(self.payload);

        if padding_len > 0 {
            // Буфер растягивается на месте и хвост заполняется RNG напрямую,
            // без промежуточного Vec.
            let start = buf.len();
            buf.resize(total_size, 0);
            rand::rng().fill_bytes(&mut buf[start..]);
        }

        buf
    }
}

/// Разбор только заголовка: `can_parse` проверяет, накопились ли 25 байт,
/// `parse` читает их и сдвигает курсор буфера (payload остаётся в `bytes`).
impl Parser for FrameHeader {
    type Error = String;

    #[inline(always)]
    fn can_parse(bytes: &BytesMut) -> bool {
        bytes.len() >= FRAME_HEADER_SIZE as usize
    }

    #[inline]
    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        // Заголовок читается срезом напрямую из буфера, без split_to — не нужно
        // создавать отдельный объект Bytes ради 25 байт, которые тут же разбираются.
        let header_slice = &bytes[..FRAME_HEADER_SIZE as usize];

        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&header_slice[0..16]);

        let stream_id = u32::from_be_bytes(header_slice[16..20].try_into().unwrap());

        let frame_type = match header_slice[20] {
            0x00 => FrameType::Connect,
            0x01 => FrameType::Data,
            0x02 => FrameType::Close,
            0x03 => FrameType::Heartbeat,
            0x04 => FrameType::UdpConnect,
            0x05 => FrameType::UdpData,
            0x06 => FrameType::Diag,
            0x07 => FrameType::Credit,
            0x08 => FrameType::Cover,
            unknown => {
                // After successful AEAD decryption an unknown frame type means a
                // protocol version mismatch or data corruption that the cipher
                // somehow didn't catch. Propagate as an error so the caller can
                // drop the leg and reconnect rather than silently treating it as
                // Close (which would leak resources on the remote end).
                return Err(format!("Unknown FrameType byte: 0x{:02x}", unknown));
            }
        };

        let payload_len = u16::from_be_bytes(header_slice[21..23].try_into().unwrap());
        let padding_len = u16::from_be_bytes(header_slice[23..25].try_into().unwrap());

        // Просто смещаем внутренний курсор оригинального буфера
        bytes.advance(FRAME_HEADER_SIZE as usize);

        Ok(Some(Self {
            auth_tag,
            stream_id,
            frame_type,
            payload_len,
            padding_len,
        }))
    }
}

/// Разбор полного кадра. `can_parse` подглядывает в поля длин прямо в буфере
/// (без сдвига курсора), чтобы убедиться, что пришёл весь кадр целиком; только
/// тогда `parse` извлекает заголовок и payload и пропускает padding.
impl Parser for Frame {
    type Error = String;

    #[inline(always)]
    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < FRAME_HEADER_SIZE as usize {
            return false;
        }

        // Подглядываем payload_len и padding_len по их смещениям в заголовке,
        // не трогая курсор: байты 21..23 и 23..25.
        let p_len = u16::from_be_bytes([bytes[21], bytes[22]]) as usize;
        let pad_len = u16::from_be_bytes([bytes[23], bytes[24]]) as usize;

        bytes.len() >= (FRAME_HEADER_SIZE as usize + p_len + pad_len)
    }

    #[inline]
    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let header = FrameHeader::parse(bytes)?.unwrap(); // Безопасно, т.к. can_parse прошел

        let p_len = header.payload_len as usize;
        let pad_len = header.padding_len as usize;

        // payload - единственное место, где мы аллоцируем Bytes объект (zero-copy clone),
        // так как он реально пойдет дальше по каналам в обработку.
        let payload = bytes.split_to(p_len).freeze();

        // Паддинг никому не нужен — курсор просто сдвигается мимо этих байт, без
        // отдельной аллокации Bytes под них.
        bytes.advance(pad_len);

        Ok(Some(Self { header, payload }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH_KEY: [u8; 16] = [0x42; 16];

    fn round_trip(frame_type: FrameType, payload: &[u8], pad: u16) -> Frame {
        let frame = Frame::new(7, frame_type, Bytes::copy_from_slice(payload));
        let mut wire = frame.into_bytes(&AUTH_KEY, pad);
        Frame::parse(&mut wire).unwrap().unwrap()
    }

    #[test]
    fn round_trip_preserves_payload_and_metadata() {
        let parsed = round_trip(FrameType::Data, b"some tunnel payload", 0);
        assert_eq!(parsed.header.stream_id, 7);
        assert_eq!(parsed.header.frame_type, FrameType::Data);
        assert_eq!(&parsed.payload[..], b"some tunnel payload");
        assert_eq!(parsed.header.auth_tag, AUTH_KEY);
    }

    #[test]
    fn padding_is_whatever_the_caller_asked_for() {
        // Кадр больше не решает сам, сколько набивки положить: решение принимает
        // кодек на уровне TLS-записи (см. `nrxp::codec::PadGrid`). Здесь
        // фиксируем ровно это — сколько попросили, столько и записано.
        for (frame_type, pad) in [
            (FrameType::Data, 0u16),
            (FrameType::Data, 137),
            (FrameType::UdpData, 4096),
            (FrameType::Heartbeat, 255),
            (FrameType::Connect, 1),
            (FrameType::Credit, 0),
        ] {
            let frame = Frame::new(1, frame_type, Bytes::from_static(b"x"));
            let wire = frame.into_bytes(&AUTH_KEY, pad);
            // padding_len живёт в байтах 23..25 заголовка.
            assert_eq!(u16::from_be_bytes([wire[23], wire[24]]), pad);
            assert_eq!(wire.len(), Frame::wire_len(1, pad));
        }
    }

    #[test]
    fn max_frame_payload_fills_exactly_one_tls_record() {
        // Кадр максимального размера должен занимать открытый текст записи
        // ЦЕЛИКОМ и ни байтом больше: после AEAD-тега это даёт поле длины
        // 16401 — ровно столько, сколько выдаёт настоящий TLS 1.3.
        assert_eq!(
            Frame::wire_len(MAX_FRAME_PAYLOAD, 0),
            MAX_RECORD_PLAINTEXT,
            "максимальный кадр обязан ровно заполнять открытый текст записи"
        );
        assert_eq!(MAX_RECORD_PLAINTEXT + 16, 16401);

        let frame = Frame::new(
            1,
            FrameType::Data,
            Bytes::from(vec![0u8; MAX_FRAME_PAYLOAD]),
        );
        let wire = frame.into_bytes(&AUTH_KEY, 0);
        assert_eq!(wire.len(), MAX_RECORD_PLAINTEXT);
    }

    #[test]
    fn payload_len_field_still_fits_u16() {
        // payload_len — 2 байта; потолок payload обязан в них помещаться,
        // иначе `Frame::new` молча обрежет длину при касте.
        assert!(MAX_FRAME_PAYLOAD <= u16::MAX as usize);
    }

    #[test]
    fn parse_skips_padding_without_exposing_it() {
        let frame = Frame::new(3, FrameType::Heartbeat, Bytes::from_static(b"auth-payload"));
        let mut wire = frame.into_bytes(&AUTH_KEY, 200);

        let parsed = Frame::parse(&mut wire).unwrap().unwrap();
        assert_eq!(&parsed.payload[..], b"auth-payload");
        assert!(
            wire.is_empty(),
            "parse must advance past payload AND padding, leaving nothing behind"
        );
    }

    #[test]
    fn incomplete_frame_is_none() {
        let frame = Frame::new(1, FrameType::Data, Bytes::copy_from_slice(&[0u8; 50]));
        let mut wire = frame.into_bytes(&AUTH_KEY, 16);
        wire.truncate(wire.len() - 1);
        assert!(Frame::parse(&mut wire).unwrap().is_none());
    }

    #[test]
    fn unknown_frame_type_byte_is_an_error() {
        let frame = Frame::new(1, FrameType::Data, Bytes::copy_from_slice(&[0u8; 10]));
        let mut wire = frame.into_bytes(&AUTH_KEY, 0);
        wire[20] = 0xEE; // frame_type byte — не входит ни в один известный вариант
        assert!(Frame::parse(&mut wire).is_err());
    }
}
