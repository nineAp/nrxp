//! # Криптографический блок (`crypto`)
//!
//! Весь криптографический фундамент протокола Netrunner. Модуль самодостаточен:
//! снаружи (из [`net`](crate::net)) видны только высокоуровневые сущности
//! [`SessionKeys`], [`SessionAuth`] и потоковый шифр [`ChaChaCipher`].
//!
//! ## Из чего состоит блок
//!
//! | Файл         | Ответственность                                                      |
//! |--------------|----------------------------------------------------------------------|
//! | [`ecdh`]     | Эфемерный обмен ключами X25519 (Diffie-Hellman).                     |
//! | [`identity`] | Долговременные учётные данные ноды: секрет входа + статический ключ. |
//! | [`hkdf`]     | Расширение общего секрета в набор ключей (HKDF-SHA256).              |
//! | [`session`]  | Оркестрация хендшейка: соль → ECDH → HKDF → ключи; time-based auth.  |
//! | [`chacha`]   | Потоковое AEAD-шифрование ChaCha20-Poly1305 с раздельными nonce.     |
//! | [`aead`]     | Трейт-абстракция [`AeadPacker`] над шифром (для подмены алгоритма).  |
//!
//! ## Жизненный цикл ключей (как всё связано)
//!
//! ```text
//!  1. SessionKeys::new(is_initiator)   → генерит эфемерный X25519 + локальную соль
//!  2. <обмен ClientHello/ServerHello>  → стороны узнают чужой pubkey и соль
//!  3. SessionKeys::update_keys(...)     → ECDH → HKDF → 2×(key+iv) + auth_key
//!  4. ChaChaCipher::set_keys(...)       → горячий путь: in-place шифр/дешифр
//!  5. SessionAuth (auth_key)            → TOTP-подобный тег в каждом кадре
//! ```
//!
//! ## Модель безопасности (инварианты, которые нельзя ломать)
//!
//! - **Forward secrecy.** Приватный ключ X25519 — эфемерный: он живёт только
//!   внутри хендшейка и стирается [`ECDH::burn`](ecdh) сразу после вывода
//!   ключей сессии.
//! - **Аутентификация пира (v3).** В `ikm` уходит второй DH — с долговременным
//!   ключом ноды (см. [`identity`]). Без него ключи сессии сходятся у кого
//!   угодно, кто оказался в разрыве, — это и есть отсутствие защиты от MITM.
//! - **Уникальность nonce.** Каждое направление имеет свой счётчик; nonce =
//!   `base_iv XOR counter`. Повтор nonce при одном ключе ломает ChaCha20-Poly1305.
//! - **Анти-replay по времени.** [`SessionAuth::verify_tag`] сверяет HMAC-тег в
//!   окне `±AUTH_WINDOW_SIZE` шагов и работает **в постоянном времени** (не
//!   ветвится по факту совпадения) — иначе утечёт тайминг подбора тега.

mod aead;
mod chacha;
mod datagram_keys;
mod ecdh;
mod hkdf;
pub mod identity;
mod session;

pub(crate) use aead::AeadPacker;
pub(crate) use chacha::{ChaChaCipher, ChaChaStream};
pub(crate) use datagram_keys::{DatagramEpochKeys, DatagramKeyMaterial};
pub use identity::{Identity, LocalIdentity, PeerIdentity};
pub(crate) use session::{SessionAuth, SessionKeys};
