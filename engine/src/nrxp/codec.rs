//! Шифрующий кодек: мост между кадрами [`Frame`] и зашифрованными TLS-записями.
//!
//! Это слой, где встречаются протокол ([`nrxp::frame`](super::frame)),
//! криптография ([`crypto`](crate::crypto)) и TLS-обёртка ([`bridge`](super::bridge)).
//! Кодек разнесён на два независимых направления, чтобы чтение и запись жили в
//! разных задачах tokio без общего мьютекса:
//!
//! - [`TxCodec`] — `Frame` → AEAD-шифр in-place → TLS `ApplicationData`;
//! - [`RxCodec`] — TLS `ApplicationData` → AEAD-дешифр in-place → `Frame`.
//!
//! [`Codec`] — лишь фабрика: создаёт оба направления из одного [`ChaChaCipher`] и
//! `auth_key`, после чего [`split`](Codec::split) раздаёт их reader'у и writer'у.
//!
//! ## Буфер `staging` в [`RxCodec`]
//!
//! Инвариант — «кадр целиком лежит внутри одной TLS-записи»: кадр никогда не
//! режется границей записи, но записей на кадр может приходиться меньше одной,
//! то есть одна запись несёт **один или несколько** кадров (см.
//! [`TxCodec::encode_batch`]). TLS-записи расшифровываются по одной в общий
//! буфер `staging`, после чего делается попытка распарсить кадр; всё, что не
//! разобрано в текущем вызове, переживает `decode_inbound` в `staging` и
//! разбирается на следующем. Вызывающий reader крутит `decode_inbound` в цикле
//! до `Ok(None)`, поэтому пачка кадров из одной записи выгребается целиком.
//!
//! Именно из-за этого свойства батчинг на передающей стороне **не потребовал ни
//! изменений приёмника, ни бампа версии протокола**: уже задеплоенные узлы
//! разбирают многокадровые записи корректно.
//!
//! Любой провал AEAD или парсинга после успешной расшифровки трактуется
//! как рассинхрон/tampering → [`ErrorAction::Drop`] (пересоздать ногу с нуля).

use crate::crypto::{AeadPacker, ChaChaCipher, ChaChaStream, SessionAuth};
use crate::bridge::TlsBridge;
use crate::errors::{ErrorAction, ErrorStage, TlsError};
use crate::nrxp::frame::{Frame, FrameType, FRAME_HEADER_SIZE, MAX_RECORD_PLAINTEXT};
use crate::parser::Parser;
use bytes::{BufMut, Bytes, BytesMut};
use rand::RngExt;

/// Длина AEAD-тега ChaCha20-Poly1305: на столько шифртекст длиннее открытого
/// текста, и ровно на столько поле длины TLS-записи больше плейнтекста.
const AEAD_TAG_LEN: usize = 16;

/// Максимальная длина TLS-записи на проводе (поле длины) — 16401.
const MAX_RECORD_LEN: usize = MAX_RECORD_PLAINTEXT + AEAD_TAG_LEN;

/// Выравниватель длин TLS-записей, параметры которого **свои у каждого соединения**.
///
/// Зачем набивка вообще: длина TLS-записи едет в открытом виде (2 байта
/// заголовка записи не шифруются), поэтому без выравнивания наблюдатель читает
/// точный размер каждого сообщения и строит по нему website-fingerprinting
/// поверх сколь угодно хорошей маскировки хендшейка.
///
/// ## Две волны правок и почему решётки оказалось мало
///
/// **Было (волна 0).** Набивка считалась в кадре по фиксированным бакетам
/// {256, 512, …, 8192}, одна запись несла один кадр, поэтому длина записи
/// всегда равнялась `бакет + 41`. Инварианта `длина − 41 = 2^k` держалась для
/// всех соединений и всех развёртываний сразу — шесть значений на весь мир.
///
/// **Было (волна 1).** Сетка с шагом: цель — ближайшая сверху точка
/// `offset + k·step`, параметры свои у соединения. Глобальный маркер исчез, но
/// остался локальный: внутри соединения все длины сравнимы по модулю `step`, и
/// наблюдатель, собравший достаточно записей, шаг восстанавливает.
///
/// **Стало.** Квантование сохранено, но границы больше не образуют решётку.
///
/// ## Почему именно так, а не «добавить случайный паддинг»
///
/// Соблазн заменить сетку аддитивным шумом (`цель = длина + случайное`)
/// выглядит проще и убирает шаг. Но он ломает главное свойство набивки:
/// квантование **скрывает** точный размер, потому что множество разных
/// исходных длин отображается в одну цель. У аддитивного шума матожидание
/// цели равно `длина + E[шум]`, и наблюдатель, увидевший один и тот же запрос
/// несколько раз, восстанавливает исходный размер усреднением. Обмен
/// «скрытие размера» на «отсутствие шага» — не улучшение.
///
/// Поэтому здесь квантование остаётся, а лечится именно **регулярность**
/// границ: они выбираются один раз на соединение с неравными, случайными
/// промежутками. Шага, по которому можно взять остаток, не существует —
/// восстанавливать нечего.
///
/// Промежутки растут мультипликативно (доля от текущей границы, доля своя у
/// каждого промежутка), а не на постоянную величину. Это даёт две нужные вещи
/// сразу: мелкую гранулярность на коротких записях и грубую на длинных — как в
/// настоящем трафике, — и относительный оверхед, не зависящий от размера.
///
/// ## Что осталось незакрытым (честно)
///
/// Наблюдатель, собравший много записей ОДНОГО соединения, восстановит набор
/// его границ — но не шаг, потому что шага нет, и не параметры других
/// соединений. Знание набора границ не даёт ничего сверх того, что и так даёт
/// квантование: исходный размер по-прежнему известен лишь с точностью до
/// промежутка.
///
/// Полная имитация распределения длин конкретного decoy-сайта — следующий шаг,
/// и он требует живого захвата, а не правки кодека.
struct PadShaper {
    /// Возрастающие границы квантования, свои у каждого соединения.
    ///
    /// Хранятся списком, а не формулой, именно затем, чтобы между ними не было
    /// арифметического отношения, которое можно выразить и восстановить.
    boundaries: Vec<usize>,
}

// --- REDACTED FOR PUBLIC RELEASE -------------------------------------
// Приватный репозиторий держит здесь 4 калиброванных числа, подобранных так,
// чтобы распределение длин TLS-записей не образовывало решётку и при этом не
// било по throughput на крупных закачках. Значения ниже — заглушки: механизм
// (границы без арифметического отношения, растущие мультипликативно, свои у
// каждого соединения) работает и с ними, тесты ниже это проверяют, но реальные
// пороги намеренно не публикуются — это ровно тот материал, из которого
// строится статистический детектор трафика.

/// ЗАГЛУШКА. Нижняя граница длины записи выбирается из этого диапазона.
const FLOOR_RANGE: std::ops::RangeInclusive<usize> = 64..=256;

/// ЗАГЛУШКА. Минимальный промежуток между границами.
const MIN_GAP: usize = 16;

/// ЗАГЛУШКА. Промежуток — доля от текущей границы, своя у каждого промежутка.
const GAP_RATIO: std::ops::RangeInclusive<f64> = 0.05..=0.25;

/// ЗАГЛУШКА. Потолок промежутка, свой у КАЖДОГО промежутка — без него
/// мультипликативный рост давал бы на крупных записях набивку в килобайты.
const GAP_CAP: std::ops::RangeInclusive<usize> = 128..=320;
// -----------------------------------------------------------------------

impl PadShaper {
    fn new() -> Self {
        let mut rng = rand::rng();
        let floor = rng.random_range(FLOOR_RANGE);

        let mut boundaries = Vec::new();
        let mut current = floor;
        while current < MAX_RECORD_LEN {
            boundaries.push(current);
            let ratio: f64 = rng.random_range(GAP_RATIO);
            let cap = rng.random_range(GAP_CAP);
            let gap = ((current as f64 * ratio) as usize).clamp(MIN_GAP, cap);
            current = current.saturating_add(gap);
        }
        boundaries.push(MAX_RECORD_LEN);

        Self { boundaries }
    }

    /// Целевая длина TLS-записи (то самое открытое поле длины) для записи,
    /// открытый текст которой занимает `plaintext_len` байт.
    ///
    /// Записи, которые уже упёрлись в потолок, не трогаются: их длина и так
    /// определяется размером батча writer'а, а не содержимым одного сообщения.
    fn target_record_len(&self, plaintext_len: usize) -> usize {
        let record_len = plaintext_len + AEAD_TAG_LEN;
        if record_len >= MAX_RECORD_LEN {
            return record_len;
        }

        // Ближайшая граница сверху. Двоичный поиск, а не проход: границ
        // несколько десятков, и это горячий путь на каждую запись.
        match self.boundaries.binary_search(&record_len) {
            Ok(idx) => self.boundaries[idx],
            Err(idx) if idx < self.boundaries.len() => self.boundaries[idx],
            // Выше последней границы — оставляем как есть, выходить за потолок
            // настоящего TLS 1.3 нельзя ни при каких параметрах.
            Err(_) => record_len,
        }
    }
}

/// Исходящее направление: шифрует кадры для отправки в туннель.
pub struct TxCodec {
    crypto: ChaChaStream,
    auth: SessionAuth,
    shaper: PadShaper,
}

impl TxCodec {
    pub fn new(crypto: ChaChaStream, auth: SessionAuth) -> Self {
        Self {
            crypto,
            auth,
            shaper: PadShaper::new(),
        }
    }

    /// Кодирует один кадр в готовую к отправке TLS-запись `ApplicationData`.
    pub(crate) fn encode_frame(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
    ) -> Result<Bytes, TlsError> {
        self.encode_batch(vec![(stream_id, frame_type, payload)])
    }

    /// Кодирует пачку кадров, укладывая их в минимальное число TLS-записей.
    ///
    /// Кадры набиваются в запись жадно, пока помещаются в
    /// [`MAX_RECORD_PLAINTEXT`]; на каждую запись приходится одно AEAD-шифрование
    /// (один nonce) и один заголовок записи. Хвост последней записи добивается
    /// набивкой до целевой длины из [`PadShaper`].
    ///
    /// ## Совместимость
    ///
    /// Приёмная сторона к этому готова **без изменений и без бампа версии**:
    /// [`RxCodec::decode_inbound`] расшифровывает запись в буфер `staging`,
    /// отдаёт первый разобранный кадр, а остаток оставляет в `staging` до
    /// следующего вызова; вызывающий reader крутит `decode_inbound` в цикле до
    /// `Ok(None)`. То есть запись с N кадрами корректно разбирает и уже
    /// задеплоенная старая нода, и старый клиент.
    pub(crate) fn encode_batch(
        &mut self,
        items: Vec<(u32, FrameType, Bytes)>,
    ) -> Result<Bytes, TlsError> {
        if items.is_empty() {
            return Ok(Bytes::new());
        }

        let tag = self.auth.generate_current_tag();
        let mut out = BytesMut::new();
        let mut batch: Vec<(u32, FrameType, Bytes)> = Vec::new();
        let mut batch_len = 0usize;

        for item in items {
            let need = Frame::wire_len(item.2.len(), 0);

            // Кадр, который сам по себе не влезает в запись (крупный
            // control-payload вроде Diag-снапшота), уезжает отдельной записью
            // без набивки — как и до появления батчинга.
            if need > MAX_RECORD_PLAINTEXT {
                if !batch.is_empty() {
                    self.flush_shaped(&tag, std::mem::take(&mut batch), batch_len, &mut out)?;
                    batch_len = 0;
                }
                self.flush_record(&tag, vec![item], 0, &mut out)?;
                continue;
            }

            if batch_len + need > MAX_RECORD_PLAINTEXT {
                self.flush_shaped(&tag, std::mem::take(&mut batch), batch_len, &mut out)?;
                batch_len = 0;
            }

            batch_len += need;
            batch.push(item);
        }

        if !batch.is_empty() {
            self.flush_shaped(&tag, batch, batch_len, &mut out)?;
        }

        Ok(out.freeze())
    }

    /// Кодирует один [`FrameType::Cover`]-кадр так, чтобы длина TLS-записи
    /// вышла **ровно** `target_record_len`.
    ///
    /// Cover-кадры имитируют flight настоящего TLS-сервера, поэтому их размер
    /// задаётся снаружи ([`crate::decoy::CoverFlight`]) и
    /// не проходит через [`PadShaper`]: тот выравнивает наш собственный
    /// трафик, а здесь надо попасть в заранее посчитанную длину.
    pub(crate) fn encode_cover(&mut self, target_record_len: usize) -> Result<Bytes, TlsError> {
        // Запись из одного пустого кадра — это 25 байт заголовка + 16 байт
        // AEAD-тега, всё остальное добирается набивкой.
        const EMPTY_COVER_RECORD: usize = FRAME_HEADER_SIZE as usize + AEAD_TAG_LEN;

        let target = target_record_len.clamp(EMPTY_COVER_RECORD, MAX_RECORD_LEN);
        let pad = target - EMPTY_COVER_RECORD;

        let tag = self.auth.generate_current_tag();
        let mut out = BytesMut::new();
        self.flush_record(
            &tag,
            vec![(0, FrameType::Cover, Bytes::new())],
            pad,
            &mut out,
        )?;
        Ok(out.freeze())
    }

    /// [`flush_record`](Self::flush_record) с набивкой, посчитанной шейпером.
    fn flush_shaped(
        &mut self,
        tag: &[u8; 16],
        frames: Vec<(u32, FrameType, Bytes)>,
        plain_len: usize,
        out: &mut BytesMut,
    ) -> Result<(), TlsError> {
        let pad = self
            .shaper
            .target_record_len(plain_len)
            .saturating_sub(plain_len + AEAD_TAG_LEN)
            .min(MAX_RECORD_PLAINTEXT - plain_len);
        self.flush_record(tag, frames, pad, out)
    }

    /// Собирает кадры в один открытый текст, дописывает `pad` байт набивки,
    /// шифрует одним вызовом AEAD и кладёт готовую TLS-запись в `out`.
    ///
    /// Набивка идёт в ХВОСТ последнего кадра записи: `padding_len` — поле
    /// самого кадра, и приёмник пропускает его штатно, ничего не зная о том,
    /// что решение принималось на уровне записи.
    fn flush_record(
        &mut self,
        tag: &[u8; 16],
        frames: Vec<(u32, FrameType, Bytes)>,
        pad: usize,
        out: &mut BytesMut,
    ) -> Result<(), TlsError> {
        debug_assert!(!frames.is_empty());

        let plain_len: usize = frames
            .iter()
            .map(|(_, _, payload)| Frame::wire_len(payload.len(), 0))
            .sum();

        let mut buf = BytesMut::with_capacity(plain_len + pad);
        let last = frames.len() - 1;
        for (idx, (stream_id, frame_type, payload)) in frames.into_iter().enumerate() {
            let pad_here = if idx == last { pad as u16 } else { 0 };
            buf.put_slice(&Frame::new(stream_id, frame_type, payload).into_bytes(tag, pad_here));
        }

        self.crypto.encrypt(&mut buf).map_err(|e| {
            netrunner_logger::error!("Encryption failed: {:?}", e);
            TlsError::new(
                ErrorStage::Tls("Encryption failed"),
                ErrorAction::Drop,
                Bytes::new(),
            )
        })?;

        out.put_slice(&TlsBridge::pack_app_data(buf.freeze()));
        Ok(())
    }
}

/// Входящее направление: расшифровывает TLS-записи и собирает из них кадры.
pub struct RxCodec {
    crypto: ChaChaStream,
    auth: SessionAuth,
    /// Накопитель расшифрованного открытого текста между вызовами `decode_inbound`
    /// (хранит «хвост» кадров, не разобранных в текущем вызове).
    staging: BytesMut,
}

impl RxCodec {
    pub fn new(crypto: ChaChaStream, auth: SessionAuth, staging: BytesMut) -> Self {
        Self {
            crypto,
            auth,
            staging,
        }
    }
    /// Пытается извлечь **один** следующий кадр из накопленных TCP-данных.
    ///
    /// Возвращает `Ok(Some(frame))`, если кадр готов; `Ok(None)`, если данных
    /// пока недостаточно (ждём следующего чтения сокета); `Err(Drop)` при провале
    /// AEAD/парсинга. Сначала дочищает «хвост» из `staging`, затем по одной
    /// расшифровывает новые TLS-записи из `buffer`.
    pub(crate) fn decode_inbound(
        &mut self,
        buffer: &mut BytesMut,
    ) -> Result<Option<Frame>, TlsError> {
        // Drain any complete frame that was left in staging from the previous call.
        // This happens when multiple TLS records arrived in one TCP read and we
        // returned after the first parsed frame, leaving the rest in staging.
        if !self.staging.is_empty() {
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }
        }

        // Encoding invariant: an NRXP frame never straddles a TLS record boundary,
        // but one record may carry SEVERAL frames (see TxCodec::encode_batch).  We
        // decrypt each record independently into the staging buffer and immediately
        // attempt to parse; whatever is left over stays in staging for the next
        // call.  split_off + decrypt_in_place + unsplit is used to keep the
        // decrypted bytes in staging's existing allocation (zero extra allocation
        // on the fast path).
        while let Some(app_data) = TlsBridge::unpack_app_data(buffer)? {
            let start_idx = self.staging.len();
            self.staging.extend_from_slice(&app_data.payload);

            // Split off just the new encrypted bytes; staging[..start_idx] holds
            // any prior plaintext that is still waiting for a parse attempt.
            let mut data_to_decrypt = self.staging.split_off(start_idx);

            if self.crypto.decrypt(&mut data_to_decrypt).is_err() {
                // AEAD failure after a successful TCP delivery means key/nonce
                // mismatch or tampering.  Clear staging to avoid feeding garbled
                // plaintext into the parser on the next call, then signal Drop so
                // the caller tears down and reconnects (fresh keys, nonce=0).
                self.staging.clear();
                return Err(TlsError::new(
                    ErrorStage::Tls("AEAD Decrypt Failed"),
                    ErrorAction::Drop,
                    Bytes::new(),
                ));
            }

            // Re-join: staging now contains [prev_plaintext || new_plaintext].
            // decrypt_in_place shrank data_to_decrypt by 16 (stripped AEAD tag);
            // unsplit handles the adjusted length correctly because the underlying
            // allocation is contiguous and data_to_decrypt is still adjacent.
            self.staging.unsplit(data_to_decrypt);

            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }

            // try_parse_frame returned Ok(None) — this should never happen, since a
            // frame is never split across records, so a fully decrypted record
            // always yields at least one complete frame.  If it does happen anyway,
            // we continue to the next TLS record rather than looping indefinitely.
            // The staging bytes will be parsed on the next decode_inbound call.
        }

        Ok(None)
    }

    fn try_parse_frame(&mut self) -> Result<Option<Frame>, TlsError> {
        match Frame::parse(&mut self.staging) {
            Ok(Some(frame)) => Ok(Some(frame)),
            Ok(None) => Ok(None),
            Err(e) => {
                // Frame::parse only returns Err for protocol-level violations
                // (e.g. unknown FrameType byte) that survive AEAD decryption.
                // This is not a partial-data situation — it means the stream is
                // desynchronised. Drop the leg so reconnect generates fresh keys.
                netrunner_logger::error!(
                    "Frame parse error after AEAD success — dropping leg: {}",
                    e
                );
                self.staging.clear();
                Err(TlsError::new(
                    crate::errors::ErrorStage::Tls("Frame parse error"),
                    crate::errors::ErrorAction::Drop,
                    bytes::Bytes::new(),
                ))
            }
        }
    }
}

/// Фабрика кодеков: владеет обоими направлениями до момента, пока их не раздадут
/// в задачи reader/writer через [`split`](Codec::split).
pub struct Codec {
    tx: Option<TxCodec>,
    rx: Option<RxCodec>,
}

impl Codec {
    /// Создаёт оба направления из шифра сессии и ключа аутентификации.
    /// `auth` (одна `SessionAuth`) общий для tx и rx — тег зависит только от
    /// времени и `auth_key`, а не от направления.
    pub fn new(cipher: ChaChaCipher, auth_key: [u8; 32]) -> Self {
        let (rx_stream, tx_stream) = cipher.split();
        let auth = SessionAuth::new(auth_key);

        Self {
            tx: Some(TxCodec::new(tx_stream, auth)),
            rx: Some(RxCodec::new(rx_stream, auth, BytesMut::with_capacity(4096))),
        }
    }

    pub fn split(mut self) -> (RxCodec, TxCodec) {
        (
            self.rx.take().expect("RxCodec missing"),
            self.tx.take().expect("TxCodec missing"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ChaChaCipher;

    const AUTH_KEY: [u8; 32] = [0x11; 32];
    const KEY_A: [u8; 32] = [0xAA; 32];
    const IV_A: [u8; 12] = [0x01; 12];
    const KEY_B: [u8; 32] = [0xBB; 32];
    const IV_B: [u8; 12] = [0x02; 12];

    /// Пара codec'ов "клиент+сервер" с ключами, зеркальными друг другу — так же,
    /// как их реально назначает `SessionKeys::generate_keys` по ролям (tx одной
    /// стороны == rx другой).
    fn client_server_pair() -> ((RxCodec, TxCodec), (RxCodec, TxCodec)) {
        let mut client_cipher = ChaChaCipher::new();
        client_cipher.set_keys(KEY_A, IV_A, KEY_B, IV_B); // tx=A, rx=B
        let mut server_cipher = ChaChaCipher::new();
        server_cipher.set_keys(KEY_B, IV_B, KEY_A, IV_A); // tx=B, rx=A

        (
            Codec::new(client_cipher, AUTH_KEY).split(),
            Codec::new(server_cipher, AUTH_KEY).split(),
        )
    }

    #[test]
    fn cover_record_hits_the_requested_length_exactly() {
        let ((_c, mut tx), (_s, _t)) = client_server_pair();
        for target in [41usize, 60, 130, 1500, 4200, 16401] {
            let wire = tx.encode_cover(target).unwrap();
            let lens = record_lengths(&wire);
            assert_eq!(lens.len(), 1, "cover — это ровно одна TLS-запись");
            assert_eq!(
                lens[0], target,
                "профиль flight'а задаёт длину точно, шейпер к cover не применяется"
            );
        }
    }

    #[test]
    fn cover_record_is_clamped_to_the_real_tls_maximum() {
        let ((_c, mut tx), (_s, _t)) = client_server_pair();
        // Меньше пустой записи и больше потолка TLS 1.3 — оба края зажимаются,
        // а не приводят к панике на вычитании или к невалидной записи.
        for target in [0usize, 1, 40, 100_000] {
            let wire = tx.encode_cover(target).unwrap();
            let len = record_lengths(&wire)[0];
            assert!(
                (41..=16401).contains(&len),
                "длина cover-записи {len} вне допустимого диапазона"
            );
        }
    }

    #[test]
    fn cover_frames_decode_as_cover_and_carry_no_payload() {
        let ((_c, mut c_tx), (mut s_rx, _s_tx)) = client_server_pair();
        let wire = c_tx.encode_cover(2000).unwrap();

        let mut buf = BytesMut::from(&wire[..]);
        let frame = s_rx.decode_inbound(&mut buf).unwrap().unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Cover);
        assert!(frame.payload.is_empty(), "cover не несёт данных");
        assert!(
            s_rx.decode_inbound(&mut buf).unwrap().is_none(),
            "в записи был ровно один кадр"
        );
    }

    #[test]
    fn client_to_server_round_trip() {
        let ((_client_rx, mut client_tx), (mut server_rx, _server_tx)) = client_server_pair();

        let wire = client_tx
            .encode_frame(
                5,
                FrameType::Data,
                Bytes::from_static(b"payload from client"),
            )
            .unwrap();

        let mut buf = BytesMut::from(&wire[..]);
        let frame = server_rx.decode_inbound(&mut buf).unwrap().unwrap();

        assert_eq!(frame.header.stream_id, 5);
        assert_eq!(frame.header.frame_type, FrameType::Data);
        assert_eq!(&frame.payload[..], b"payload from client");
    }

    #[test]
    fn server_to_client_round_trip() {
        let ((mut client_rx, _client_tx), (_server_rx, mut server_tx)) = client_server_pair();

        let wire = server_tx
            .encode_frame(6, FrameType::Heartbeat, Bytes::from_static(b"pong"))
            .unwrap();

        let mut buf = BytesMut::from(&wire[..]);
        let frame = client_rx.decode_inbound(&mut buf).unwrap().unwrap();
        assert_eq!(&frame.payload[..], b"pong");
    }

    #[test]
    fn sequential_frames_keep_nonce_counters_in_sync() {
        let ((_client_rx, mut client_tx), (mut server_rx, _server_tx)) = client_server_pair();

        for i in 0..20u32 {
            let payload = format!("frame-{i}");
            let wire = client_tx
                .encode_frame(1, FrameType::Data, Bytes::from(payload.clone()))
                .unwrap();
            let mut buf = BytesMut::from(&wire[..]);
            let frame = server_rx.decode_inbound(&mut buf).unwrap().unwrap();
            assert_eq!(&frame.payload[..], payload.as_bytes());
        }
    }

    #[test]
    fn tampered_ciphertext_fails_aead_and_drops() {
        let ((_client_rx, mut client_tx), (mut server_rx, _server_tx)) = client_server_pair();

        let wire = client_tx
            .encode_frame(1, FrameType::Data, Bytes::from_static(b"secret"))
            .unwrap();

        let mut tampered = BytesMut::from(&wire[..]);
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF; // flip a byte inside the AEAD tag

        let result = server_rx.decode_inbound(&mut tampered);
        assert!(result.is_err(), "tampered ciphertext must not decrypt");
    }

    /// Разбирает буфер на длины TLS-записей (то, что видит DPI в открытую).
    fn record_lengths(wire: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 5 <= wire.len() {
            let len = u16::from_be_bytes([wire[i + 3], wire[i + 4]]) as usize;
            out.push(len);
            i += 5 + len;
        }
        assert_eq!(i, wire.len(), "буфер должен разбираться на целые записи");
        out
    }

    #[test]
    fn batch_of_frames_round_trips_through_an_unchanged_receiver() {
        // Главная гарантия совместимости: приёмник не менялся вообще, а пачку
        // кадров в одной записи обязан выгрести целиком и по порядку.
        let ((_c_rx, mut c_tx), (mut s_rx, _s_tx)) = client_server_pair();

        let sent: Vec<(u32, FrameType, Bytes)> = vec![
            (1, FrameType::Connect, Bytes::from_static(b"1.2.3.4:443")),
            (1, FrameType::Data, Bytes::from_static(b"GET / HTTP/1.1")),
            (3, FrameType::Data, Bytes::from_static(b"second stream")),
            (0, FrameType::Heartbeat, Bytes::new()),
        ];
        let wire = c_tx.encode_batch(sent.clone()).unwrap();

        let mut buf = BytesMut::from(&wire[..]);
        let mut got = Vec::new();
        while let Some(frame) = s_rx.decode_inbound(&mut buf).unwrap() {
            got.push((
                frame.header.stream_id,
                frame.header.frame_type,
                frame.payload,
            ));
        }

        assert_eq!(got, sent, "кадры должны прийти все и в исходном порядке");
    }

    #[test]
    fn small_frames_share_a_single_tls_record() {
        let ((_c_rx, mut c_tx), (_s_rx, _s_tx)) = client_server_pair();
        let items = (0..8)
            .map(|i| (i, FrameType::Data, Bytes::from_static(b"tiny")))
            .collect();
        let wire = c_tx.encode_batch(items).unwrap();
        assert_eq!(
            record_lengths(&wire).len(),
            1,
            "восемь мелких кадров обязаны уехать одной записью, а не восемью"
        );
    }

    #[test]
    fn record_length_never_exceeds_real_tls13_maximum() {
        // 16401 = 2^14 плейнтекста + байт content_type + 16 байт AEAD-тега —
        // потолок, который выдаёт настоящий TLS 1.3. Раньше кадр максимального
        // размера давал 16425, то есть значение, недостижимое для браузера:
        // константный маркер прямо в открытом поле длины.
        let ((_c_rx, mut c_tx), (_s_rx, _s_tx)) = client_server_pair();

        for total in [1usize, 8192, 16360, 16361, 40000, 100_000] {
            let items = vec![(1, FrameType::Data, Bytes::from(vec![0u8; total]))]
                .into_iter()
                .flat_map(|(sid, ty, data)| {
                    data.chunks(crate::nrxp::MAX_FRAME_PAYLOAD)
                        .map(|c| (sid, ty, Bytes::copy_from_slice(c)))
                        .collect::<Vec<_>>()
                })
                .collect();
            let wire = c_tx.encode_batch(items).unwrap();
            for len in record_lengths(&wire) {
                assert!(
                    len <= 16401,
                    "длина записи {len} превышает максимум настоящего TLS 1.3 (16401)"
                );
            }
        }
    }

    #[test]
    fn max_payload_frame_produces_exactly_the_real_tls_maximum() {
        let ((_c_rx, mut c_tx), (_s_rx, _s_tx)) = client_server_pair();
        let wire = c_tx
            .encode_frame(
                1,
                FrameType::Data,
                Bytes::from(vec![0u8; crate::nrxp::MAX_FRAME_PAYLOAD]),
            )
            .unwrap();
        assert_eq!(record_lengths(&wire), vec![16401]);
    }

    #[test]
    fn shaper_never_exceeds_the_real_tls_maximum_and_bounds_the_padding() {
        for _ in 0..2000 {
            let shaper = PadShaper::new();
            for plain in [
                1usize,
                42,
                300,
                1441,
                8233,
                MAX_RECORD_PLAINTEXT - 1,
                MAX_RECORD_PLAINTEXT,
            ] {
                let target = shaper.target_record_len(plain);
                let record_len = plain + AEAD_TAG_LEN;
                assert!(
                    target >= record_len,
                    "цель не может быть короче самой записи"
                );
                assert!(
                    target <= MAX_RECORD_LEN.max(record_len),
                    "цель {target} превышает потолок настоящего TLS 1.3"
                );
                // Набивка ограничена промежутком между границами либо подъёмом
                // до пола — оба ограничены сверху `GAP_CAP`/`FLOOR_RANGE`, без
                // потолка мультипликативный рост дал бы килобайты набивки на
                // крупных записях (см. докстринг `GAP_CAP`). Сравниваем с
                // самой константой, а не с зашитым числом, — граница здесь
                // заглушка, и тест обязан оставаться верным для любых её
                // значений, не только для реальной калибровки.
                let max_padding = (*FLOOR_RANGE.end()).max(*GAP_CAP.end());
                assert!(
                    target - record_len <= max_padding,
                    "набивка {} превышает {max_padding} байт",
                    target - record_len
                );
            }
        }
    }

    /// Регрессия на пункт №11 разбора протокола: «остаточная сравнимость длин
    /// по модулю шага». Прежняя сетка давала цели вида `offset + k·step`, то
    /// есть ВСЕ длины одного соединения были сравнимы по модулю `step`, и
    /// наблюдатель этот шаг восстанавливал перебором.
    ///
    /// Проверяем ровно это свойство: не существует шага, по модулю которого
    /// все наблюдаемые длины соединения дают один остаток.
    #[test]
    fn record_lengths_share_no_recoverable_step_within_a_connection() {
        // Перебор шагов — то же самое, что сделал бы наблюдатель. Верхняя
        // граница взята с запасом относительно прежнего диапазона шага
        // (64..=512): если бы решётка осталась, она нашлась бы здесь.
        for _ in 0..64 {
            let shaper = PadShaper::new();

            let targets: Vec<usize> = (1..4000usize)
                .step_by(7)
                .map(|plain| shaper.target_record_len(plain))
                .collect();
            let distinct: std::collections::BTreeSet<usize> = targets.iter().copied().collect();
            assert!(
                distinct.len() > 8,
                "квантование схлопнуло длины почти в одну: {distinct:?}"
            );

            for step in 2..=1024usize {
                let first = targets[0] % step;
                let all_congruent = targets.iter().all(|t| t % step == first);
                assert!(
                    !all_congruent,
                    "все длины сравнимы по модулю {step} — шаг восстановим, \
                     решётка вернулась"
                );
            }
        }
    }

    /// Квантование обязано сохраниться: разные исходные размеры должны
    /// сходиться в одну цель, иначе набивка перестаёт скрывать точный размер
    /// и наблюдатель восстанавливает его усреднением повторов.
    #[test]
    fn quantisation_still_collapses_distinct_sizes_into_one_target() {
        for _ in 0..64 {
            let shaper = PadShaper::new();
            let mut by_target: std::collections::HashMap<usize, usize> =
                std::collections::HashMap::new();
            for plain in 1..2000usize {
                *by_target
                    .entry(shaper.target_record_len(plain))
                    .or_default() += 1;
            }
            let max_collapsed = by_target.values().copied().max().unwrap_or(0);
            assert!(
                max_collapsed >= 16,
                "цели почти не совпадают — это уже аддитивный шум, а не \
                 квантование: максимум {max_collapsed} размеров на одну цель"
            );
        }
    }

    /// Границы должны отличаться между соединениями — иначе набор длин снова
    /// становится общим для всех узлов маркером (та самая ошибка волны 0).
    #[test]
    fn boundaries_differ_between_connections() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let shaper = PadShaper::new();
            seen.insert(shaper.target_record_len(1000));
        }
        assert!(
            seen.len() > 4,
            "цель для одного и того же размера почти не меняется между \
             соединениями: {seen:?}"
        );
    }

    #[test]
    fn record_lengths_carry_no_global_power_of_two_invariant() {
        // Регрессия на детектор `длина − 41 = 2^k`: до этой правки одна запись
        // несла один кадр с бакетным паддингом, и множество длин сводилось к
        // шести значениям, ОДИНАКОВЫМ для всех соединений сразу. Проверяем,
        // что разные соединения дают разные сетки и инварианта больше нет.
        let is_pow2 = |n: usize| n.is_power_of_two();

        let mut seen = std::collections::HashSet::new();
        let mut invariant_holds_everywhere = true;

        for _ in 0..64 {
            let ((_c_rx, mut c_tx), (_s_rx, _s_tx)) = client_server_pair();
            let wire = c_tx
                .encode_frame(1, FrameType::Data, Bytes::from_static(b"x"))
                .unwrap();
            let len = record_lengths(&wire)[0];
            seen.insert(len);
            if !is_pow2(len.saturating_sub(41)) {
                invariant_holds_everywhere = false;
            }
        }

        assert!(
            seen.len() > 1,
            "длина записи для одного и того же payload обязана отличаться между \
             соединениями, иначе это по-прежнему глобальная константа: {seen:?}"
        );
        assert!(
            !invariant_holds_everywhere,
            "инварианта `длина − 41 = степень двойки` не должна выполняться для \
             всех соединений подряд"
        );
    }

    #[test]
    fn replayed_frame_desyncs_nonce_and_fails() {
        // Кадр расшифровывается один раз успешно; повторная подача ТЕХ ЖЕ байт
        // получателю с уже продвинувшимся счётчиком nonce должна провалиться —
        // это и есть встроенная защита от replay на уровне AEAD-потока.
        let ((_client_rx, mut client_tx), (mut server_rx, _server_tx)) = client_server_pair();

        let wire = client_tx
            .encode_frame(1, FrameType::Data, Bytes::from_static(b"once"))
            .unwrap();

        let mut first = BytesMut::from(&wire[..]);
        assert!(server_rx.decode_inbound(&mut first).unwrap().is_some());

        let mut replay = BytesMut::from(&wire[..]);
        assert!(server_rx.decode_inbound(&mut replay).is_err());
    }
}
