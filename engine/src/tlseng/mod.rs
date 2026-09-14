//! # Движок TLS-маскировки (`tlseng`)
//!
//! Минимальный TLS-«стек», задача которого — **не** реализовать TLS, а
//! правдоподобно его *имитировать*. Цель — чтобы первый пакет сессии
//! (`ClientHello`) по своему отпечатку (JA3/JA4) был неотличим от популярного
//! браузера, и DPI классифицировал туннель как обычный HTTPS-сёрфинг.
//!
//! Фокус блока — **fingerprint mimicry**, а не криптография: настоящие ключи и
//! шифрование живут в [`crypto`](crate::crypto), а собственно обмен ими спрятан
//! внутри полей этих поддельных TLS-сообщений.
//!
//! ## Состав блока
//!
//! | Файл            | Ответственность                                                     |
//! |-----------------|---------------------------------------------------------------------|
//! | [`types`]       | Wire-константы и enum'ы TLS (content-type, версии, группы, расширения).|
//! | [`consts`]      | Прочие фиксированные значения протокола.                            |
//! | [`decoy`]       | Домен узла, каталог допустимых SNI и cover-flight.                  |
//! | [`grease`]      | Жребий GREASE-значений соединения (RFC 8701).                       |
//! | [`mlkem`]       | Балласт постквантовой доли `key_share` (FIPS 203).                  |
//! | [`tls_record`]  | Слой TLS-записи: (де)сериализация заголовка `type|version|len`.      |
//! | [`extension`]   | Сборка и парсинг TLS Extensions ([`ExtensionStack`]) — ядро отпечатка.|
//! | [`handshake`]   | `ClientHello`/`ServerHello`: сборка и разбор hello-сообщений.        |
//! | [`profile`]     | Профили браузеров/сервера: какие cipher-suites, группы, порядок ext. |
//!
//! ## Почему порядок и длины критичны
//!
//! JA3/JA4-отпечаток вычисляется из набора и **порядка** cipher-suites и
//! расширений, их содержимого, GREASE-значений и паддинга. Поэтому [`profile`]
//! хранит точные списки и [`ExtensionOrder`](types::ExtensionOrder), повторяющие
//! реальный браузер байт-в-байт. Любая перестановка ломает маскировку.
//!
//! ## Чего здесь намеренно нет
//!
//! Полного TLS state machine, проверки сертификатов, `Finished`/verify и самого
//! шифрования. Это осознанно: движок изображает рукопожатие ровно настолько,
//! чтобы пройти DPI, а защищённость обеспечивает кастомный протокол поверх.

mod consts;
pub mod decoy;
mod extension;
mod grease;
mod handshake;
mod mlkem;
mod profile;
mod tls_record;
mod types;

pub(crate) use extension::ExtensionStack;
pub(crate) use handshake::{ClientHello, HelloHeader, ServerHello};
pub(crate) use profile::{BrowserProfile, ServerProfile};
pub(crate) use tls_record::{ApplicationData, TlsRecord};
pub(crate) use types::{ContentType, HelloType};
