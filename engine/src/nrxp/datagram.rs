//! Датаграммный AEAD-кодек, общий для [`crate::quiceng`], [`crate::webrtceng`]
//! и голого UDP-фолбэка.
//!
//! [`codec`](super::codec) существует ради потока байт с гарантированным
//! порядком (TCP-нога): его nonce — неявный монотонный счётчик, и одна
//! потерянная запись рвёт ногу насовсем (см. докстринг модуля). UDP такой
//! гарантии не даёт, поэтому здесь другая схема — ровно "вариант 2 + 3" из
//! `docs/UDP_LEG_RESEARCH.md`:
//!
//! - **Вариант 2.** Nonce строится из ПОЛНОГО 64-битного локального счётчика
//!   (никогда не исчерпывается на практике), а на проводе едет только его
//!   младшая часть (`wire_bits` бит — формат решает вызывающий движок:
//!   16 бит похоже на RTP `seq`, 32 — на raw UDP/QUIC packet number).
//!   Получатель восстанавливает полный счётчик по контексту —
//!   [`expand_counter`], тот же алгоритм, что и в QUIC (RFC 9000 Appendix A.3)
//!   и в SRTP ROC guess (RFC 3711 §3.3.1).
//! - **Вариант 3.** Ключ каждого направления живёт в [`DatagramKeyMaterial`]
//!   ([`crate::crypto::datagram_keys`]) как однонаправленная ratchet-цепочка,
//!   а не статичный вечный секрет — см. докстринг того модуля за тем, ЧТО
//!   именно это даёт (и чего не даёт).
//!
//! ## Что этот модуль НЕ решает
//!
//! Формат байт на проводе (где именно в пакете сидят `epoch`/счётчик, что
//! именно уходит в AAD) — целиком забота вызывающего движка: у QUIC это
//! защищённый заголовком packet number и key-phase бит, у RTP-мимикрии —
//! `seq`/`SSRC` настоящего RTP-заголовка. Этот файл знает только про
//! `(epoch_id, полный/усечённый счётчик, plaintext, aad) → ciphertext` и
//! обратно — он ничего не знает о QUIC или RTP.

use bytes::{Bytes, BytesMut};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};

use crate::crypto::{DatagramEpochKeys, DatagramKeyMaterial};
use crate::errors::{ErrorAction, ErrorStage, TlsError};
use crate::nrxp::frame::{Frame, FrameType};
use crate::parser::Parser;

// --- REDACTED FOR PUBLIC RELEASE -------------------------------------
// Оба порога ниже — гигиенические настройки, не криптографическая
// необходимость (счётчик nonce 64-битный и не исчерпывается на практике —
// см. докстринги ниже), но конкретные значения из приватного репозитория не
// публикуются: интервал ratchet-перевыпуска потенциально наблюдаем как
// периодичность в трафике UDP-ноги, и это тот же класс материала, что и
// калибровка выравнивания длин в `codec`.

/// ЗАГЛУШКА. Сколько датаграмм одно направление шлёт до ratchet-перевыпуска
/// ключа — ограничивает, сколько шифртекста лежит под одним производным
/// ключом, чтобы компрометация ключа ОДНОЙ эпохи не открывала весь трафик
/// ноги целиком (см. докстринг `crypto::datagram_keys`).
const REKEY_AFTER_DATAGRAMS: u64 = 1 << 14;

/// ЗАГЛУШКА. Ширина окна анти-replay в датаграммах — тот же порядок, что у
/// WireGuard.
const REPLAY_WINDOW_SIZE: u64 = 1024;
const REPLAY_WINDOW_WORDS: usize = (REPLAY_WINDOW_SIZE / 64) as usize;
// -----------------------------------------------------------------------

/// Восстанавливает полный локальный счётчик по его усечённой версии на
/// проводе (`truncated`, младшие `bits` бит) и по наибольшему уже принятому
/// счётчику (`highest`) — тот же алгоритм, что использует QUIC для packet
/// number (RFC 9000 Appendix A.3) и SRTP для ROC (RFC 3711 §3.3.1): среди
/// всех значений, совпадающих с `truncated` по младшим `bits` битам,
/// выбирается ближайшее к `highest + 1`.
///
/// `bits` обязан быть в `1..64` — учётверённая проверка на пути от
/// протокольных констант (16 для RTP-подобного `seq`, 32 для raw UDP/QUIC),
/// не пользовательский ввод, поэтому `debug_assert!`, а не `Result`.
pub(crate) fn expand_counter(highest: u64, truncated: u64, bits: u32) -> u64 {
    debug_assert!(
        (1..64).contains(&bits),
        "wire width must leave room for reconstruction"
    );
    let window = 1u64 << bits;
    let mask = window - 1;
    let half = window / 2;

    let candidate = (highest & !mask) | (truncated & mask);

    if candidate + half <= highest {
        candidate + window
    } else if candidate > highest + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

/// Обратная операция: младшие `bits` бит полного счётчика — то, что реально
/// едет на проводе.
pub(crate) fn truncate_counter(full: u64, bits: u32) -> u64 {
    debug_assert!(
        (1..64).contains(&bits),
        "wire width must leave room for reconstruction"
    );
    full & ((1u64 << bits) - 1)
}

/// Скользящее окно анти-replay на одну эпоху одного направления — та же
/// конструкция, что у WireGuard: битовая карта последних
/// [`REPLAY_WINDOW_SIZE`] счётчиков плюс наибольший увиденный.
///
/// Вызывается ТОЛЬКО после успешной AEAD-проверки: это фильтр повторов поверх
/// уже аутентифицированных данных, не замена аутентификации.
struct ReplayWindow {
    initialized: bool,
    highest: u64,
    bitmap: [u64; REPLAY_WINDOW_WORDS],
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            initialized: false,
            highest: 0,
            bitmap: [0; REPLAY_WINDOW_WORDS],
        }
    }

    /// Счётчик, относительно которого [`expand_counter`] реконструирует
    /// следующий. `0` для ещё пустого окна — безопасная база: TX всегда
    /// начинает счётчик свежей эпохи с нуля (см. [`DatagramTx`]), поэтому
    /// первая датаграмма эпохи реконструируется верно и без счётчика "окно
    /// пусто" отдельно.
    fn highest(&self) -> u64 {
        self.highest
    }

    fn slot(counter: u64) -> (usize, u64) {
        let idx = (counter % REPLAY_WINDOW_SIZE) as usize;
        (idx / 64, 1u64 << (idx % 64))
    }

    fn set_bit(&mut self, counter: u64) {
        let (word, bit) = Self::slot(counter);
        self.bitmap[word] |= bit;
    }

    /// `true`, если бит уже стоял (т.е. этот счётчик уже был принят раньше).
    fn test_and_set_bit(&mut self, counter: u64) -> bool {
        let (word, bit) = Self::slot(counter);
        let already = self.bitmap[word] & bit != 0;
        self.bitmap[word] |= bit;
        already
    }

    /// Гасит биты позиций, которые "въезжают" в окно сверху при продвижении
    /// `highest` на `shift` — те же модульные слоты хранили данные почти
    /// `REPLAY_WINDOW_SIZE` отправлений назад, и без очистки старое "принято"
    /// ложно засчиталось бы для нового счётчика с тем же остатком.
    fn advance(&mut self, shift: u64) {
        if shift >= REPLAY_WINDOW_SIZE {
            self.bitmap = [0; REPLAY_WINDOW_WORDS];
            return;
        }
        let mut s = self.highest + 1;
        let end = self.highest + shift;
        while s <= end {
            let (word, bit) = Self::slot(s);
            self.bitmap[word] &= !bit;
            s += 1;
        }
    }

    /// Отмечает `counter` увиденным. Возвращает `false`, если это повтор или
    /// счётчик безнадёжно старше окна — в обоих случаях датаграмму нужно
    /// отбросить, несмотря на то что AEAD её уже подтвердил.
    fn accept(&mut self, counter: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = counter;
            self.set_bit(counter);
            return true;
        }

        if counter > self.highest {
            let shift = counter - self.highest;
            self.advance(shift);
            self.highest = counter;
            self.set_bit(counter);
            return true;
        }

        let behind = self.highest - counter;
        if behind >= REPLAY_WINDOW_SIZE {
            return false;
        }

        !self.test_and_set_bit(counter)
    }
}

fn build_nonce(salt: &[u8; 12], counter: u64) -> Nonce {
    // Та же конструкция, что `crypto::chacha::NonceState::next_nonce`
    // (`salt XOR big_endian(counter)` по младшим 8 байтам), только со внешне
    // управляемым счётчиком: здесь его на TX-стороне не "следующий
    // внутренний", а явно переданный — на RX-стороне он вообще
    // реконструирован из провода, а не сосчитан локально.
    let mut iv = *salt;
    let counter_bytes = counter.to_be_bytes();
    for i in 0..8 {
        iv[i + 4] ^= counter_bytes[i];
    }
    *GenericArray::from_slice(&iv)
}

fn cipher_for(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

fn auth_fail(what: &'static str) -> TlsError {
    TlsError::new(ErrorStage::Tls(what), ErrorAction::Drop, Bytes::new())
}

/// Результат [`DatagramTx::seal`]: готовый шифртекст плюс метаданные, которые
/// вызывающий движок обязан как-то донести до приёмника на проводе (в своём,
/// протокол-специфичном формате — см. докстринг модуля).
pub(crate) struct SealedDatagram {
    pub(crate) epoch_id: u8,
    pub(crate) counter: u64,
    pub(crate) ciphertext: Bytes,
}

/// Исходящая сторона одного направления UDP-ноги.
pub(crate) struct DatagramTx {
    keys: DatagramKeyMaterial,
    counter: u64,
}

impl DatagramTx {
    pub(crate) fn new(keys: DatagramKeyMaterial) -> Self {
        Self { keys, counter: 0 }
    }

    pub(crate) fn leg_token(&self) -> [u8; 16] {
        self.keys.leg_token()
    }

    /// Форсирует ratchet-перевыпуск ключа немедленно, минуя
    /// [`REKEY_AFTER_DATAGRAMS`] (в приватном репозитории — число куда
    /// большего порядка, чем заглушка здесь; гонять реальный порог в
    /// юнит-тесте нечестно долго); вызывающие
    /// движки (`quiceng`/`webrtceng`) используют это, чтобы протестировать
    /// именно переход через эпоху, а не то, что порог когда-нибудь наступит
    /// (см. `nrxp::datagram::tests::rekey_is_transparent_across_the_boundary`
    /// за тем же приёмом внутри этого модуля).
    #[cfg(test)]
    pub(crate) fn force_rekey_for_test(&mut self) {
        self.keys.tx_advance();
        self.counter = 0;
    }

    /// `(epoch_id, полный счётчик)`, которые СЛЕДУЮЩИЙ вызов [`Self::seal`]
    /// использует для шифрования.
    ///
    /// Существует ради курицы-и-яйца в обоих движках мимикрии: чтобы собрать
    /// свой заголовок пакета (QUIC packet number / RTP `seq`), им нужен
    /// счётчик, который станет частью AAD, а `seal` берёт `aad` уже готовым
    /// байтовым срезом (см. его докстринг) — расчёт счётчика внутри самого
    /// `seal` для этого недоступен снаружи.
    ///
    /// # Контракт вызывающего кода
    ///
    /// Действителен только для **немедленно следующего** вызова `seal` на
    /// этом же `DatagramTx`, без какого-либо другого вызова между ними —
    /// `DatagramTx` не `Sync`, и оба движка используют его строго
    /// последовательно (одна датаграмма зараз на направление), так что это
    /// не ограничение сверх того, как он и так используется.
    pub(crate) fn peek_next_epoch_and_counter(&self) -> (u8, u64) {
        if self.counter >= REKEY_AFTER_DATAGRAMS {
            (self.keys.tx_epoch_id().wrapping_add(1), 0)
        } else {
            (self.keys.tx_epoch_id(), self.counter)
        }
    }

    /// Шифрует один кадр NRXP как одну датаграмму. `aad` — байты, которые
    /// вызывающий движок хочет криптографически привязать к этому шифртексту
    /// (типично — открытый заголовок пакета на проводе, построенный по
    /// счётчику из [`Self::peek_next_epoch_and_counter`], как в настоящем
    /// SRTP/QUIC), помимо самого содержимого.
    pub(crate) fn seal(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
        aad: &[u8],
    ) -> Result<SealedDatagram, TlsError> {
        if self.counter >= REKEY_AFTER_DATAGRAMS {
            self.keys.tx_advance();
            self.counter = 0;
        }

        let epoch: DatagramEpochKeys = self.keys.tx_current();
        let counter = self.counter;
        self.counter += 1;

        // auth_tag кадра здесь не имеет смысла отдельно от AEAD-печати всей
        // датаграммы (см. `nrxp` docs: он и на TCP-ноге сейчас не проверяется
        // независимо) — нулевой, чтобы не тратить время на TOTP ради поля,
        // которое никто не читает.
        let mut buf = Frame::new(stream_id, frame_type, payload).into_bytes(&[0u8; 16], 0);
        buf.reserve(16);

        let nonce = build_nonce(&epoch.salt, counter);
        cipher_for(&epoch.key)
            .encrypt_in_place(&nonce, aad, &mut buf)
            .map_err(|e| {
                netrunner_logger::error!(error = ?e, "Datagram AEAD seal failed");
                auth_fail("Datagram AEAD seal failed")
            })?;

        Ok(SealedDatagram {
            epoch_id: epoch.epoch_id,
            counter,
            ciphertext: buf.freeze(),
        })
    }
}

/// Ключи + окно анти-replay одной эпохи на приёмной стороне.
struct EpochSlot {
    epoch_id: u8,
    keys: DatagramEpochKeys,
    window: ReplayWindow,
}

impl EpochSlot {
    fn fresh(keys: DatagramEpochKeys) -> Self {
        Self {
            epoch_id: keys.epoch_id,
            keys,
            window: ReplayWindow::new(),
        }
    }

    /// Пробует расшифровать и пропустить через анти-replay окно. `None` —
    /// либо AEAD не сошёлся, либо это повтор/безнадёжно старая датаграмма;
    /// вызывающий не обязан различать эти случаи (оба ведут к отбрасыванию).
    fn try_open(
        &mut self,
        wire_counter: u64,
        wire_bits: u32,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Option<BytesMut> {
        let full_counter = expand_counter(self.window.highest(), wire_counter, wire_bits);
        let nonce = build_nonce(&self.keys.salt, full_counter);

        let mut buf = BytesMut::from(ciphertext);
        cipher_for(&self.keys.key)
            .decrypt_in_place(&nonce, aad, &mut buf)
            .ok()?;

        if self.window.accept(full_counter) {
            Some(buf)
        } else {
            None
        }
    }
}

/// Входящая сторона одного направления UDP-ноги.
///
/// Держит текущую эпоху и ровно одну предыдущую (для датаграмм, отправленных
/// непосредственно перед тем, как отправитель перевыпустил ключ, но
/// доставленных с опозданием). Датаграмма, задержавшаяся дольше — переживает
/// два ratchet-события пира сразу — отбрасывается: при пороге в
/// [`REKEY_AFTER_DATAGRAMS`] датаграмм на эпоху это требует патологической
/// задержки, а не обычного переупорядочивания UDP.
pub(crate) struct DatagramRx {
    keys: DatagramKeyMaterial,
    current: EpochSlot,
    previous: Option<EpochSlot>,
}

impl DatagramRx {
    pub(crate) fn new(keys: DatagramKeyMaterial) -> Self {
        let current = EpochSlot::fresh(keys.rx_current());
        Self {
            keys,
            current,
            previous: None,
        }
    }

    pub(crate) fn leg_token(&self) -> [u8; 16] {
        self.keys.leg_token()
    }

    /// Текущая (не "предыдущая") принятая эпоха — нужна движкам, у которых
    /// на проводе нет места под полный `epoch_id` (RTP-подобная мимикрия
    /// вообще без него, QUIC-подобная — только под однобитный key phase),
    /// чтобы восстановить полное значение по своему усечённому
    /// представлению относительно того, что мы уже приняли. См.
    /// `quiceng::header::QuicRx::open` за примером использования.
    pub(crate) fn current_epoch_id(&self) -> u8 {
        self.current.epoch_id
    }

    /// Расшифровывает и разбирает одну датаграмму в кадр NRXP.
    ///
    /// `epoch_id` — как его прочитал вызывающий движок со своего,
    /// протокол-специфичного заголовка (см. докстринг модуля). Принимает три
    /// значения: текущую эпоху, предыдущую (если ещё жива) и текущую+1 —
    /// последнее трактуется как "пир перевыпустил ключ", и состояние
    /// продвигается, но ТОЛЬКО после успешной AEAD-проверки (см.
    /// `crypto::datagram_keys::KeyRatchet::peek_next`): один поддельный
    /// пакет с чужим `epoch_id` не может сдвинуть наш ratchet вхолостую.
    pub(crate) fn open(
        &mut self,
        epoch_id: u8,
        wire_counter: u64,
        wire_bits: u32,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Frame, TlsError> {
        let mut plaintext = if epoch_id == self.current.epoch_id {
            self.current
                .try_open(wire_counter, wire_bits, ciphertext, aad)
                .ok_or_else(|| auth_fail("Datagram AEAD open failed (current epoch)"))?
        } else if self
            .previous
            .as_ref()
            .is_some_and(|slot| slot.epoch_id == epoch_id)
        {
            self.previous
                .as_mut()
                .expect("checked Some above")
                .try_open(wire_counter, wire_bits, ciphertext, aad)
                .ok_or_else(|| auth_fail("Datagram AEAD open failed (previous epoch)"))?
        } else if epoch_id == self.current.epoch_id.wrapping_add(1) {
            let mut candidate = EpochSlot::fresh(self.keys.rx_peek_next());
            let plain = candidate
                .try_open(wire_counter, wire_bits, ciphertext, aad)
                .ok_or_else(|| auth_fail("Datagram AEAD open failed (candidate next epoch)"))?;

            // Коммит: реально продвигаем ratchet и сдвигаем окно
            // current/previous — только теперь, когда AEAD уже подтвердил,
            // что это не подделка.
            self.keys.rx_advance();
            let retired = std::mem::replace(&mut self.current, candidate);
            self.previous = Some(retired);
            plain
        } else {
            return Err(auth_fail("Datagram epoch_id out of acceptable range"));
        };

        Frame::parse(&mut plaintext)
            .map_err(|e| {
                netrunner_logger::error!("Datagram frame parse error: {}", e);
                auth_fail("Datagram frame parse error")
            })?
            .ok_or_else(|| auth_fail("Datagram plaintext did not contain a full frame"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionKeys;

    // ── expand_counter ──────────────────────────────────────────────────

    #[test]
    fn expand_counter_reconstructs_the_next_small_value() {
        assert_eq!(expand_counter(0, 1, 16), 1);
        assert_eq!(expand_counter(41, 42, 16), 42);
    }

    #[test]
    fn expand_counter_handles_reordering_without_wraparound() {
        // highest=100, но пришла задержавшаяся датаграмма с truncated=97.
        assert_eq!(expand_counter(100, 97, 16), 97);
    }

    #[test]
    fn expand_counter_reconstructs_forward_wraparound() {
        let bits = 8u32; // окно 256 — маленькое, чтобы обернуть его в тесте.
        let highest = 250u64;
        // Реальный следующий счётчик — 260, на проводе видно только 260 % 256 = 4.
        let wire = 4u64;
        assert_eq!(expand_counter(highest, wire, bits), 260);
    }

    #[test]
    fn expand_counter_reconstructs_backward_wraparound() {
        let bits = 8u32;
        let highest = 260u64;
        // Задержавшаяся датаграмма из ДО оборота: настоящий счётчик 250, на
        // проводе 250 % 256 = 250.
        let wire = 250u64;
        assert_eq!(expand_counter(highest, wire, bits), 250);
    }

    #[test]
    fn truncate_then_expand_round_trips_for_nearby_values() {
        for bits in [16u32, 32] {
            let highest = 1_000_000u64;
            for delta in [0i64, 1, -1, 5, -5] {
                let full = (highest as i64 + delta) as u64;
                let wire = truncate_counter(full, bits);
                assert_eq!(
                    expand_counter(highest, wire, bits),
                    full,
                    "bits={bits} delta={delta}"
                );
            }
        }
    }

    // ── ReplayWindow ────────────────────────────────────────────────────

    #[test]
    fn replay_window_accepts_strictly_increasing_counters() {
        let mut w = ReplayWindow::new();
        for i in 0..10u64 {
            assert!(w.accept(i), "counter {i} should be accepted the first time");
        }
    }

    #[test]
    fn replay_window_rejects_exact_replay() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(
            !w.accept(5),
            "replaying the exact same counter must be rejected"
        );
    }

    #[test]
    fn replay_window_accepts_reordered_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(10));
        assert!(w.accept(8), "8 arrived late but is still within the window");
        assert!(!w.accept(8), "but only once");
        assert!(w.accept(9));
    }

    #[test]
    fn replay_window_rejects_counters_too_far_behind() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(REPLAY_WINDOW_SIZE + 100));
        assert!(
            !w.accept(50),
            "far enough behind highest to be outside the window"
        );
    }

    #[test]
    fn replay_window_survives_a_huge_forward_jump_without_false_accepts() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(w.accept(5 + REPLAY_WINDOW_SIZE * 10));
        // Тот же остаток по модулю REPLAY_WINDOW_SIZE, что и первый принятый
        // счётчик, но САМ он — старый и не должен пройти повторно.
        assert!(!w.accept(5));
    }

    // ── Сквозной seal/open ──────────────────────────────────────────────

    fn handshaken_pair() -> (SessionKeys, SessionKeys) {
        use crate::bridge::TlsBridge;
        use crate::tlseng::{BrowserProfile, ServerProfile};

        let mut client = SessionKeys::new(true);
        let mut server = SessionKeys::new(false);

        let ch = TlsBridge::wrap_client_hello(&BrowserProfile::CHROME_140, "example.com", &client);
        let mut ch_buf = BytesMut::from(&ch[..]);
        let client_msg = TlsBridge::unpack_handshake(&mut ch_buf).unwrap().unwrap();

        let (sh, _peer_version) =
            TlsBridge::wrap_server_hello(&client_msg, &mut server, &ServerProfile::MODERN).unwrap();
        let mut sh_buf = BytesMut::from(&sh[..]);
        let server_msg = TlsBridge::unpack_handshake(&mut sh_buf).unwrap().unwrap();

        client
            .update_keys(server_msg.random(), server_msg.extensions(), false)
            .unwrap();

        (client, server)
    }

    fn tx_rx_pair() -> (DatagramTx, DatagramRx) {
        let (client, server) = handshaken_pair();
        let tx = DatagramTx::new(DatagramKeyMaterial::derive(&client));
        let rx = DatagramRx::new(DatagramKeyMaterial::derive(&server));
        (tx, rx)
    }

    #[test]
    fn peek_next_epoch_and_counter_matches_what_seal_actually_uses() {
        let (mut tx, _rx) = tx_rx_pair();
        for _ in 0..3 {
            let (peeked_epoch, peeked_counter) = tx.peek_next_epoch_and_counter();
            let sealed = tx
                .seal(1, FrameType::UdpData, Bytes::from_static(b"x"), b"aad")
                .unwrap();
            assert_eq!(peeked_epoch, sealed.epoch_id);
            assert_eq!(peeked_counter, sealed.counter);
        }

        // То же самое верно и через границу ratchet-перевыпуска — ради этого
        // и существует особый случай в `peek_next_epoch_and_counter`.
        tx.keys.tx_advance();
        tx.counter = 0;
        let (peeked_epoch, peeked_counter) = tx.peek_next_epoch_and_counter();
        let sealed = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"y"), b"aad")
            .unwrap();
        assert_eq!(peeked_epoch, sealed.epoch_id);
        assert_eq!(peeked_counter, sealed.counter);
    }

    #[test]
    fn seal_open_round_trip_preserves_frame_contents() {
        let (mut tx, mut rx) = tx_rx_pair();
        let sealed = tx
            .seal(3, FrameType::UdpData, Bytes::from_static(b"hello"), b"aad")
            .unwrap();

        let frame = rx
            .open(
                sealed.epoch_id,
                sealed.counter,
                32,
                &sealed.ciphertext,
                b"aad",
            )
            .unwrap();
        assert_eq!(frame.header.stream_id, 3);
        assert_eq!(frame.header.frame_type, FrameType::UdpData);
        assert_eq!(&frame.payload[..], b"hello");
    }

    #[test]
    fn mismatched_aad_is_rejected() {
        let (mut tx, mut rx) = tx_rx_pair();
        let sealed = tx
            .seal(
                1,
                FrameType::UdpData,
                Bytes::from_static(b"x"),
                b"real-header",
            )
            .unwrap();
        assert!(rx
            .open(
                sealed.epoch_id,
                sealed.counter,
                32,
                &sealed.ciphertext,
                b"forged-header"
            )
            .is_err());
    }

    #[test]
    fn replaying_the_exact_wire_datagram_is_rejected() {
        let (mut tx, mut rx) = tx_rx_pair();
        let sealed = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"x"), b"aad")
            .unwrap();
        assert!(rx
            .open(
                sealed.epoch_id,
                sealed.counter,
                32,
                &sealed.ciphertext,
                b"aad"
            )
            .is_ok());
        assert!(
            rx.open(
                sealed.epoch_id,
                sealed.counter,
                32,
                &sealed.ciphertext,
                b"aad"
            )
            .is_err(),
            "replay of the exact same datagram must be rejected"
        );
    }

    #[test]
    fn reordered_datagrams_within_window_all_open() {
        let (mut tx, mut rx) = tx_rx_pair();
        let sealed: Vec<_> = (0..5)
            .map(|i| {
                tx.seal(1, FrameType::UdpData, Bytes::from(vec![i]), b"aad")
                    .unwrap()
            })
            .collect();

        for i in [2, 0, 1, 4, 3] {
            let s = &sealed[i];
            let frame = rx
                .open(s.epoch_id, s.counter, 32, &s.ciphertext, b"aad")
                .unwrap();
            assert_eq!(&frame.payload[..], &[i as u8]);
        }
    }

    #[test]
    fn rekey_is_transparent_across_the_boundary() {
        let (mut tx, mut rx) = tx_rx_pair();

        let before = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"before"), b"aad")
            .unwrap();
        assert!(rx
            .open(
                before.epoch_id,
                before.counter,
                32,
                &before.ciphertext,
                b"aad"
            )
            .is_ok());

        // Форсируем ratchet вручную, минуя счётчик-порог — тестируем именно
        // переход эпохи, а не то, что порог когда-нибудь наступит.
        tx.keys.tx_advance();
        tx.counter = 0;

        let after = tx
            .seal(2, FrameType::UdpData, Bytes::from_static(b"after"), b"aad")
            .unwrap();
        assert_ne!(after.epoch_id, before.epoch_id);

        let frame = rx
            .open(after.epoch_id, after.counter, 32, &after.ciphertext, b"aad")
            .unwrap();
        assert_eq!(&frame.payload[..], b"after");
    }

    #[test]
    fn a_datagram_delayed_across_exactly_one_rekey_still_opens() {
        let (mut tx, mut rx) = tx_rx_pair();

        // "before" запечатан, но доставка задержится.
        let before = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"before"), b"aad")
            .unwrap();

        tx.keys.tx_advance();
        tx.counter = 0;
        let after = tx
            .seal(2, FrameType::UdpData, Bytes::from_static(b"after"), b"aad")
            .unwrap();

        // "after" приходит первым (обгоняет "before" в сети)...
        assert!(rx
            .open(after.epoch_id, after.counter, 32, &after.ciphertext, b"aad")
            .is_ok());
        // ...а "before" (предыдущая эпоха) всё равно открывается благодаря
        // слоту `previous`.
        let frame = rx
            .open(
                before.epoch_id,
                before.counter,
                32,
                &before.ciphertext,
                b"aad",
            )
            .unwrap();
        assert_eq!(&frame.payload[..], b"before");
    }

    #[test]
    fn forged_next_epoch_claim_does_not_desync_state() {
        let (mut tx, mut rx) = tx_rx_pair();

        // Атакующий шлёт мусор, помечая его как "следующая эпоха".
        let garbage = vec![0u8; 64];
        assert!(rx
            .open(rx.current.epoch_id.wrapping_add(1), 0, 32, &garbage, b"aad")
            .is_err());

        // Реальная датаграмма ТЕКУЩЕЙ эпохи после этого всё ещё открывается —
        // подделка не сдвинула ratchet вхолостую.
        let real = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"real"), b"aad")
            .unwrap();
        assert_eq!(real.epoch_id, rx.current.epoch_id);
        let frame = rx
            .open(real.epoch_id, real.counter, 32, &real.ciphertext, b"aad")
            .unwrap();
        assert_eq!(&frame.payload[..], b"real");
    }

    #[test]
    fn a_datagram_delayed_across_two_rekeys_is_dropped() {
        let (mut tx, mut rx) = tx_rx_pair();
        let before = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"before"), b"aad")
            .unwrap();

        tx.keys.tx_advance();
        tx.counter = 0;
        let _mid = tx
            .seal(2, FrameType::UdpData, Bytes::from_static(b"mid"), b"aad")
            .unwrap();
        rx.open(_mid.epoch_id, _mid.counter, 32, &_mid.ciphertext, b"aad")
            .unwrap();

        tx.keys.tx_advance();
        tx.counter = 0;
        let after = tx
            .seal(3, FrameType::UdpData, Bytes::from_static(b"after"), b"aad")
            .unwrap();
        rx.open(after.epoch_id, after.counter, 32, &after.ciphertext, b"aad")
            .unwrap();

        // Две эпохи спустя "before" уже не в {current, previous}.
        assert!(
            rx.open(
                before.epoch_id,
                before.counter,
                32,
                &before.ciphertext,
                b"aad"
            )
            .is_err(),
            "datagram delayed across two rekeys is expected to be dropped, not silently accepted"
        );
    }
}
