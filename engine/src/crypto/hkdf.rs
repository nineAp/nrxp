//! Расширение ключей по HKDF-SHA256 (RFC 5869).
//!
//! Общий секрет, полученный из [`ECDH`](super::ecdh), сам по себе как ключ не
//! используется. Через HKDF из него детерминированно «разворачивается» несколько
//! независимых ключей под разные цели (см. [`session`](super::session)):
//! AEAD-ключи и IV для каждого направления плюс ключ для time-based аутентификации.
//!
//! Схема двухфазная:
//! - **extract**: `PRK = HKDF-Extract(salt, ikm)` — «сжимает» энтропию секрета;
//! - **expand**: `okm = HKDF-Expand(PRK, label, N)` — выдаёт ключ нужной длины,
//!   уникальный для каждого `label` (`mark`).

use hkdf::Hkdf;
use sha2::Sha256;

/// Безсостоятельная обёртка над `hkdf::Hkdf<Sha256>` с двумя удобными методами.
#[allow(clippy::upper_case_acronyms)]
pub(crate) struct HKDF;

impl HKDF {
    /// Фаза **extract**: связывает соль и входной материал ключа (`ikm`,
    /// общий ECDH-секрет) в псевдослучайный ключ `PRK`.
    ///
    /// Возвращает готовый к фазе expand экстрактор **и** сырые байты `PRK`.
    /// Обычным вызывающим (session-ключи tx/rx) байты не нужны — только
    /// `Hkdf<Sha256>` для `expand_key`. Байты существуют ради
    /// [`crate::crypto::datagram_keys`]: UDP-нога выводит свой ключевой
    /// материал из того же хендшейка позже, чем живёт локальный `ikm`
    /// (`generate_keys` уничтожает его сразу после этого вызова), а
    /// `Hkdf<Sha256>` сам по себе не переживаемо и не восстановимо из
    /// внешнего состояния — только 32-байтный `PRK` можно сохранить и
    /// использовать как основу для `Hkdf::from_prk` в другой момент времени.
    /// Соль здесь — это объединённые локальная+удалённая соли сторон (см.
    /// `SaltPair::get_total`).
    pub(crate) fn extract_key(salt: &[u8], ikm: &[u8]) -> ([u8; 32], Hkdf<Sha256>) {
        let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(salt), ikm);
        let mut prk_bytes = [0u8; 32];
        prk_bytes.copy_from_slice(&prk);
        (prk_bytes, hkdf)
    }

    /// Восстанавливает expand-состояние из уже посчитанного `PRK` — без
    /// повторного `extract`. Единственный потребитель —
    /// [`crate::crypto::datagram_keys`]: ключевой ratchet UDP-ноги хранит
    /// между вызовами только 32-байтные значения (`Zeroizing`-дружелюбно) и
    /// каждый раз пересобирает `Hkdf<Sha256>` заново, а не носит его с собой.
    ///
    /// Паникует только если бы `prk` был длиннее максимума HKDF (`255 *
    /// hash_len`) — недостижимо для фиксированных 32 байт SHA-256.
    pub(crate) fn from_prk(prk: &[u8; 32]) -> Hkdf<Sha256> {
        Hkdf::<Sha256>::from_prk(prk).expect("32-byte PRK is always a valid HKDF-SHA256 PRK")
    }

    /// Фаза **expand**: выводит ключ длины `N` байт под меткой `mark`.
    ///
    /// `mark` (например `b"client_aead"`) играет роль контекстного лейбла:
    /// разные метки из одного и того же `PRK` дают криптографически независимые
    /// ключи. `N` — параметр-константа, поэтому длина проверяется на этапе
    /// компиляции (32 для ключа, 12 для IV и т.п.).
    pub(crate) fn expand_key<const N: usize>(
        extracted_key: &Hkdf<Sha256>,
        mark: &[u8],
    ) -> Result<[u8; N], String> {
        let mut expanded_key: [u8; N] = [0u8; N];
        extracted_key
            .expand(mark, &mut expanded_key)
            .map_err(|e| e.to_string())?;
        Ok(expanded_key)
    }
}
