//! Потоковое AEAD-шифрование ChaCha20-Poly1305.
//!
//! Это «горячий путь» крипто-блока: через него проходит каждый кадр данных.
//! Ключевые свойства:
//!
//! - **Раздельные направления.** [`ChaChaCipher`] держит два независимых потока —
//!   `tx` (исходящий) и `rx` (входящий), у каждого свой ключ, IV и счётчик nonce.
//! - **Детерминированный nonce.** Nonce не передаётся по сети: обе стороны
//!   синхронно считают `nonce = base_iv XOR counter` (см. [`NonceState`]).
//!   Счётчики растут строго в ногу, поэтому любой пропуск/повтор кадра ломает
//!   расшифровку — это и есть встроенная защита целостности потока.
//! - **In-place.** Шифр работает прямо в [`BytesMut`] без копий и аллокаций.

use bytes::BytesMut;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use zeroize::Zeroize;

use crate::crypto::aead::AeadPacker;

/// Генератор nonce для одного направления.
///
/// Nonce строится как `base_iv XOR big_endian(counter)` по младшим 8 байтам IV.
/// `counter` монотонно растёт на каждый кадр, гарантируя уникальность nonce в
/// пределах ключа (повтор nonce при одном ключе фатален для ChaCha20-Poly1305).
struct NonceState {
    /// Счётчик кадров. Должен совпадать у отправителя и получателя по направлению.
    counter: u64,
    /// Базовый IV (12 байт), полученный из HKDF; неизменен на всю сессию.
    base_iv: [u8; 12],
}

impl NonceState {
    pub fn new(base_iv: [u8; 12]) -> Self {
        Self {
            counter: 0,
            base_iv,
        }
    }

    /// Возвращает nonce для текущего кадра и инкрементирует счётчик.
    ///
    /// Затирание `base_iv` см. в [`Drop for NonceState`](NonceState#impl-Drop).
    ///
    /// XOR накладывается на байты `iv[4..12]` (младшие 8 байт 12-байтового IV),
    /// старшие 4 байта остаются «солью» из IV. После вызова `counter`
    /// увеличивается, поэтому следующий кадр получит другой nonce.
    pub fn next_nonce(&mut self) -> Nonce {
        let mut iv = self.base_iv;
        let counter_bytes = self.counter.to_be_bytes();

        for i in 0..8 {
            iv[i + 4] ^= counter_bytes[i];
        }

        self.counter += 1;
        *GenericArray::from_slice(&iv)
    }
}

/// Затирание базового IV.
///
/// IV — не ключ, но выводится тем же HKDF из того же секрета сессии, и вместе с
/// утёкшим ключом даёт готовый nonce для каждого кадра. Сам ключ `ChaCha20Poly1305`
/// затирает уже сам (`ZeroizeOnDrop` в `chacha20poly1305`), так что это добирает
/// вторую половину пары.
impl Drop for NonceState {
    fn drop(&mut self) {
        self.base_iv.zeroize();
    }
}

/// Однонаправленный шифр: одна пара (ключ, IV) + её счётчик nonce.
///
/// Реализует [`AeadPacker`]. Используется парами внутри [`ChaChaCipher`].
pub struct ChaChaStream {
    cipher: ChaCha20Poly1305,
    state: NonceState,
}

impl ChaChaStream {
    pub fn new(key: &[u8; 32], iv: [u8; 12]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            state: NonceState::new(iv),
        }
    }
}

impl AeadPacker for ChaChaStream {
    fn encrypt(&mut self, data: &mut BytesMut) -> Result<(), chacha20poly1305::aead::Error> {
        let current_counter = self.state.counter;
        let nonce = self.state.next_nonce();
        let data_len = data.len();

        // Убеждаемся, что в BytesMut есть место для тега, чтобы избежать аллокации
        data.reserve(16);

        match self.cipher.encrypt_in_place(&nonce, &nonce, data) {
            Ok(_) => {
                netrunner_logger::trace!(
                    counter = current_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    "Encryption successful"
                );
                Ok(())
            }
            Err(e) => {
                netrunner_logger::error!(
                    counter = current_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    error = ?e,
                    "AEAD encryption failure"
                );
                Err(e)
            }
        }
    }

    fn decrypt(&mut self, data: &mut BytesMut) -> Result<(), chacha20poly1305::aead::Error> {
        let saved_counter = self.state.counter;
        let nonce = self.state.next_nonce();
        let data_len = data.len();

        match self.cipher.decrypt_in_place(&nonce, &nonce, data) {
            Ok(_) => {
                netrunner_logger::trace!(
                    counter = saved_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    "Decryption successful"
                );
                Ok(())
            }
            Err(e) => {
                // Roll back the counter: the plaintext was not produced, so the
                // peer's TX counter is still at saved_counter. If the caller
                // decides to retry (e.g., after a corrective re-read) rather
                // than drop the connection, the next decrypt attempt will use
                // the same nonce and succeed. In practice we always Drop on
                // AEAD failure, but correctness requires the rollback.
                self.state.counter = saved_counter;

                let data_prefix = if data.len() >= 8 {
                    hex::encode(&data[..8])
                } else {
                    hex::encode(data.as_ref())
                };
                netrunner_logger::error!(
                    counter = saved_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    prefix = %data_prefix,
                    error = ?e,
                    "AEAD decryption failure! Verification failed or data malformed"
                );
                Err(e)
            }
        }
    }
}

/// Двунаправленный шифр сессии: исходящий (`tx`) и входящий (`rx`) потоки.
///
/// Создаётся «пустым» (нулевые ключи) до завершения хендшейка, затем
/// [`set_keys`](ChaChaCipher::set_keys) заряжает реальные ключи из HKDF.
pub struct ChaChaCipher {
    /// Исходящее направление (шифрование того, что отправляем).
    pub tx: ChaChaStream,
    /// Входящее направление (расшифровка того, что приняли).
    pub rx: ChaChaStream,
}

impl ChaChaCipher {
    /// Создаёт шифр с нулевыми ключами-заглушками (до хендшейка).
    pub fn new() -> Self {
        Self {
            tx: ChaChaStream::new(&[0u8; 32], [0u8; 12]),
            rx: ChaChaStream::new(&[0u8; 32], [0u8; 12]),
        }
    }

    /// Заряжает реальные ключи/IV после хендшейка: `w_*` — на запись (tx),
    /// `r_*` — на чтение (rx). Сбрасывает счётчики nonce в 0 для обоих направлений.
    pub fn set_keys(
        &mut self,
        mut w_key: [u8; 32],
        w_iv: [u8; 12],
        mut r_key: [u8; 32],
        r_iv: [u8; 12],
    ) {
        self.tx = ChaChaStream::new(&w_key, w_iv);
        self.rx = ChaChaStream::new(&r_key, r_iv);
        // Ключи пришли по значению — это копии на стеке поверх тех, что уже
        // легли внутрь шифра. Свои копии затираем сразу: дальше они не нужны,
        // а `[u8; 32]` при выходе из области видимости не затирается сам.
        // IV затрутся вместе с `NonceState` предыдущих потоков (Drop выше).
        w_key.zeroize();
        r_key.zeroize();
        netrunner_logger::debug!("Cipher keys and IVs updated for both directions");
    }

    /// Разбирает шифр на два независимых потока `(rx, tx)`.
    ///
    /// Нужно, чтобы отдать чтение и запись в разные задачи tokio (reader/writer),
    /// не деля шифр под мьютексом — каждое направление владеет своим потоком.
    pub fn split(self) -> (ChaChaStream, ChaChaStream) {
        (self.rx, self.tx)
    }
}
