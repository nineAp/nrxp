//! Wire-константы и типы TLS, нужные для маскировки.
//!
//! Все числовые значения здесь — части формата TLS «на проводе» (RFC 8446 и
//! реестр IANA tls-extensiontype-values). Менять их нельзя: от точного совпадения
//! зависит JA3/JA4-отпечаток. Группировка по смыслу:
//! - базовый каркас записи/хендшейка: [`ContentType`], [`ProtocolVersion`], [`HelloType`];
//! - наборы для отпечатка: [`TlsGroups`], [`TlsSignatures`], [`TlsVersions`],
//!   [`TlsExtensions`], [`ExtensionOrder`].

/// Тип TLS-записи (первый байт на проводе). Мы используем четыре из них:
/// `Handshake` для hello-сообщений, `ApplicationData` для кадров NRXP,
/// `Alert` распознаём для совместимости, `ChangeCipherSpec` — фиктивная запись
/// middlebox-совместимости TLS 1.3 (RFC 8446 Appendix D.4): настоящие браузеры
/// шлют её сразу после своего Hello, и её отсутствие в последовательности
/// типов TLS-записей само по себе отличает нестандартный TLS-стек от
/// браузерного трафика — криптографически в TLS 1.3 она ничего не значит.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentType {
    ChangeCipherSpec = 0x14,

    Handshake = 0x16,

    ApplicationData = 0x17,

    Alert = 0x15,
}

impl TryFrom<u8> for ContentType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x14 => Ok(ContentType::ChangeCipherSpec),
            0x16 => Ok(ContentType::Handshake),
            0x17 => Ok(ContentType::ApplicationData),
            0x15 => Ok(ContentType::Alert),
            _ => Err("This is not ContentType"),
        }
    }
}

/// Версия TLS на проводе. Заметьте «маскировочный» нюанс: реальный TLS 1.3
/// притворяется 1.2 в поле версии записи (`0x0303`), а настоящая версия едет в
/// расширении `supported_versions` — ровно как делают браузеры.
#[repr(u16)]
#[derive(Copy, Clone, Debug)]
pub(crate) enum ProtocolVersion {
    Tls10 = 0x0301,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

impl TryFrom<u16> for ProtocolVersion {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0301 => Ok(ProtocolVersion::Tls10),

            0x0303 => Ok(ProtocolVersion::Tls12),

            0x0304 => Ok(ProtocolVersion::Tls13),
            _ => Err("This is not Protocol Version"),
        }
    }
}

/// Тип handshake-сообщения: `ClientHello` (`0x01`) или `ServerHello` (`0x02`) —
/// первый байт тела `Handshake`-записи.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum HelloType {
    Client = 0x01,

    Server = 0x02,
}

impl TryFrom<u8> for HelloType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(HelloType::Client),
            0x02 => Ok(HelloType::Server),
            _ => Err("This is not Hello header"),
        }
    }
}

/// Поддерживаемые ECDH-группы (расширение `supported_groups`). Обёртка над
/// статическим срезом, чтобы профили могли ссылаться на готовые наборы
/// ([`CHROMIUM`](TlsGroups::CHROMIUM)/[`MODERN`](TlsGroups::MODERN)) без аллокаций.
/// На практике обмен идёт по `X25519` — остальные перечислены для правдоподобия.
#[derive(Clone, Copy)]
pub(crate) struct TlsGroups(pub &'static [u16]);

impl TlsGroups {
    pub const X25519: u16 = 0x001d;
    pub const SECP256R1: u16 = 0x0017;
    pub const SECP384R1: u16 = 0x0018;
    pub const SECP521R1: u16 = 0x0019;
    /// Гибридная постквантовая группа (draft-kwiatkowski-tls-ecdhe-mlkem).
    /// Chrome предлагает её первой в `supported_groups` с версии ~131, и
    /// именно она делает его `ClientHello` ~1700-байтовым. Профиль без неё не
    /// совпадает ни с одним живым Chromium — см. [`super::mlkem`].
    pub const X25519_MLKEM768: u16 = 0x11ec;

    // --- REDACTED FOR PUBLIC RELEASE -----------------------------------
    // Приватный репозиторий держит здесь наборы групп, скопированные байт-в-байт
    // из живых захватов конкретных браузеров (порядок и состав — часть
    // JA3/JA4-отпечатка). Значения ниже — заглушки, а не рабочая калибровка:
    // подставьте собственный захват перед использованием в проде.
    /// ЗАГЛУШКА — не соответствует ни одному живому браузеру.
    pub const CHROMIUM: Self = Self(&[Self::X25519, Self::SECP256R1]);

    /// ЗАГЛУШКА — не соответствует ни одному живому браузеру.
    pub const CHROMIUM_PQ: Self = Self(&[Self::X25519_MLKEM768, Self::X25519]);

    pub const MODERN: Self = Self(&[Self::X25519, Self::SECP256R1]);

    /// ЗАГЛУШКА — не соответствует ни одному живому браузеру.
    pub const FIREFOX: Self = Self(&[Self::X25519, Self::SECP256R1, Self::SECP521R1]);

    /// ЗАГЛУШКА — не соответствует ни одному живому браузеру.
    pub const SAFARI: Self = Self(&[Self::X25519, Self::SECP256R1]);
    // ---------------------------------------------------------------------
}

/// Алгоритмы подписи (`signature_algorithms`). Для нас это «декорация» отпечатка:
/// сертификаты мы не проверяем, но список и его порядок должны совпадать с
/// браузером ([`BROWSER_STANDARD`](TlsSignatures::BROWSER_STANDARD)).
#[derive(Clone, Copy)]
pub(crate) struct TlsSignatures(pub &'static [u16]);

impl TlsSignatures {
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;

    /// ML-DSA (FIPS 204). Chrome рекламирует все три уровня первыми в списке —
    /// снято с живого захвата, см. doc [`CHROME_PQ`](Self::CHROME_PQ).
    pub const MLDSA44: u16 = 0x0904;
    pub const MLDSA65: u16 = 0x0905;
    pub const MLDSA87: u16 = 0x0906;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;

    // --- REDACTED FOR PUBLIC RELEASE -----------------------------------
    // Приватный репозиторий держит здесь точный список живого Chrome, снятый
    // с захвата трафика. Заглушка ниже НЕ воспроизводит реальный отпечаток —
    // подставьте собственную калибровку перед использованием в проде.
    /// ЗАГЛУШКА — не соответствует ни одному живому браузеру.
    pub const CHROME_PQ: Self = Self(&[
        Self::MLDSA44,
        Self::ECDSA_SECP256R1_SHA256,
        Self::RSA_PSS_RSAE_SHA256,
    ]);
    // ---------------------------------------------------------------------

    pub const BROWSER_STANDARD: Self = Self(&[
        Self::ECDSA_SECP256R1_SHA256,
        Self::RSA_PSS_RSAE_SHA256,
        Self::RSA_PKCS1_SHA256,
        Self::ECDSA_SECP384R1_SHA384,
        Self::RSA_PSS_RSAE_SHA384,
        Self::RSA_PKCS1_SHA384,
        Self::RSA_PSS_RSAE_SHA512,
    ]);
}

/// Версии для расширения `supported_versions`. Профиль решает, рекламировать
/// только 1.3 ([`TLS_13_ONLY`](TlsVersions::TLS_13_ONLY), как Chrome) или 1.3+1.2
/// ([`MODERN`](TlsVersions::MODERN), как Firefox).
#[derive(Clone, Copy)]
pub struct TlsVersions(pub &'static [u16]);

impl TlsVersions {
    pub const TLS_1_3: u16 = 0x0304;
    pub const TLS_1_2: u16 = 0x0303;

    pub const TLS_13_ONLY: Self = Self(&[Self::TLS_1_3]);
    pub const MODERN: Self = Self(&[Self::TLS_1_3, Self::TLS_1_2]);

    /// Наибольшая версия из набора — кладётся в основное поле версии хендшейка.
    pub fn max(&self) -> ProtocolVersion {
        if self.0.contains(&Self::TLS_1_3) {
            ProtocolVersion::Tls13
        } else if self.0.contains(&Self::TLS_1_2) {
            ProtocolVersion::Tls12
        } else {
            ProtocolVersion::Tls10
        }
    }
}

/// Идентификаторы TLS-расширений (реестр IANA) + детектор GREASE.
///
/// Используются как ключи при сборке/поиске расширений в [`extension`](super::extension).
pub struct TlsExtensions;

impl TlsExtensions {
    pub const SNI: u16 = 0x0000;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SCT: u16 = 0x0012;
    pub const PADDING: u16 = 0x0015;
    pub const EMS: u16 = 0x0017;
    pub const COMPRESS_CERT: u16 = 0x001b;
    pub const DELEGATED_CREDENTIAL: u16 = 0x0022;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const PSK_MODES: u16 = 0x002d;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const ALPS: u16 = 0x44cd;
    /// `encrypted_client_hello` (RFC 9180 / draft-ietf-tls-esni). Chrome шлёт
    /// это расширение **всегда**: при отсутствии HTTPS-RR с реальным
    /// ECHConfig — в GREASE-виде, неотличимом на проводе от настоящего.
    /// Его отсутствие в 2026 году отделяет нас от браузера само по себе.
    pub const ECH: u16 = 0xfe0d;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;

    /// Слот под GREASE-расширение, открывающее список (у Chrome — нулевой
    /// длины). В [`ExtensionOrder`] это **маркер позиции**, а не значение:
    /// конкретный id свой на каждое соединение и приходит из
    /// [`GreaseSet`](super::grease::GreaseSet).
    pub const GREASE_SLOT_FIRST: u16 = 0x0a0a;
    /// Слот под замыкающее GREASE-расширение (у Chrome — один байт `0x00`).
    /// Тоже маркер позиции, см. [`GREASE_SLOT_FIRST`](Self::GREASE_SLOT_FIRST).
    pub const GREASE_SLOT_LAST: u16 = 0x2a2a;

    /// Является ли id GREASE-значением (RFC 8701).
    ///
    /// GREASE-значения имеют вид `0x?a?a`, где оба байта равны (например `0x0a0a`,
    /// `0x1a1a`). Браузеры на базе Chromium вставляют их, чтобы серверы не «костенели»
    /// на конкретных значениях; для нас они — обязательная часть Chromium-отпечатка.
    pub fn is_grease(id: u16) -> bool {
        if (id & 0x0f0f) != 0x0a0a {
            return false;
        }

        (id & 0xff) == (id >> 8)
    }
}

/// Точный порядок расширений в `ClientHello` — определяющий фактор JA3/JA4.
///
/// Хранится как статический срез id и перебирается [`ExtensionBuilder`] при
/// сборке. Константы ниже скопированы из реальных захватов соответствующих
/// браузеров; первые/последние элементы — GREASE-значения.
#[derive(Clone, Copy)]
pub struct ExtensionOrder(pub &'static [u16]);

impl<'a> IntoIterator for &'a ExtensionOrder {
    type Item = &'a u16;
    type IntoIter = std::slice::Iter<'a, u16>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl ExtensionOrder {
    // --- REDACTED FOR PUBLIC RELEASE -------------------------------------
    // Приватный репозиторий держит здесь точный порядок расширений каждого
    // браузера, снятый с живых захватов трафика (сентябрь 2026) — это самый
    // чувствительный элемент JA3/JA4-калибровки. Заглушки ниже структурно
    // валидны (движок с ними компилируется и проходит round-trip), но НЕ
    // воспроизводят отпечаток ни одного живого браузера. Подставьте
    // собственную калибровку из свежего захвата перед использованием в проде.
    /// ЗАГЛУШКА.
    pub const CHROMIUM_131: Self = Self(&[
        0xaaaa,
        TlsExtensions::SNI,
        TlsExtensions::SUPPORTED_GROUPS,
        TlsExtensions::SIGNATURE_ALGORITHMS,
        TlsExtensions::KEY_SHARE,
        TlsExtensions::SUPPORTED_VERSIONS,
        TlsExtensions::PADDING,
    ]);

    /// ЗАГЛУШКА.
    pub const CHROME_140: Self = Self(&[
        TlsExtensions::GREASE_SLOT_FIRST,
        TlsExtensions::SNI,
        TlsExtensions::SUPPORTED_GROUPS,
        TlsExtensions::KEY_SHARE,
        TlsExtensions::SUPPORTED_VERSIONS,
        TlsExtensions::SIGNATURE_ALGORITHMS,
        TlsExtensions::GREASE_SLOT_LAST,
    ]);

    /// ЗАГЛУШКА.
    pub const EDGE_130: Self = Self(&[
        0x1a1a,
        TlsExtensions::SNI,
        TlsExtensions::SUPPORTED_GROUPS,
        TlsExtensions::SIGNATURE_ALGORITHMS,
        TlsExtensions::KEY_SHARE,
        TlsExtensions::SUPPORTED_VERSIONS,
        0x3a3a,
        TlsExtensions::PADDING,
    ]);

    /// ЗАГЛУШКА.
    pub const FIREFOX_133: Self = Self(&[
        TlsExtensions::SNI,
        TlsExtensions::RENEGOTIATION_INFO,
        TlsExtensions::SUPPORTED_GROUPS,
        TlsExtensions::KEY_SHARE,
        TlsExtensions::SUPPORTED_VERSIONS,
        TlsExtensions::SIGNATURE_ALGORITHMS,
    ]);

    /// ЗАГЛУШКА.
    pub const SAFARI_17: Self = Self(&[
        TlsExtensions::SNI,
        TlsExtensions::RENEGOTIATION_INFO,
        TlsExtensions::SUPPORTED_GROUPS,
        TlsExtensions::KEY_SHARE,
        TlsExtensions::SUPPORTED_VERSIONS,
    ]);
    // -----------------------------------------------------------------------
}
