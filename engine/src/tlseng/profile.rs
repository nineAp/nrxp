//! Профили отпечатков: «рецепты» того, как должен выглядеть наш TLS.
//!
//! [`BrowserProfile`] описывает клиентский отпечаток (что и в каком порядке класть
//! в `ClientHello`, чтобы JA3/JA4 совпал с реальным браузером), а [`ServerProfile`] —
//! как отвечать на стороне сервера. Профили — это `const`-значения без аллокаций;
//! все списки ссылаются на статические срезы из [`types`](super::types).
//!
//! Менять поля профиля = менять отпечаток.
//!
//! **Публичная копия:** значения ниже — заглушки, не рабочая калибровка.
//! Приватная версия хранит списки, скопированные байт-в-байт из реальных
//! захватов трафика; они намеренно не публикуются (см. README репозитория).

use crate::tlseng::types::{
    ExtensionOrder, ProtocolVersion, TlsGroups, TlsSignatures, TlsVersions,
};

/// Клиентский отпечаток конкретного браузера.
pub(crate) struct BrowserProfile {
    /// ECDH-группы (`supported_groups`).
    pub groups: TlsGroups,
    /// Алгоритмы подписи (`signature_algorithms`).
    pub signatures: TlsSignatures,
    /// Подписи для `delegated_credentials`.
    pub delegated_signatures: TlsSignatures,
    /// Рекламируемые версии TLS (`supported_versions`).
    pub versions: TlsVersions,
    /// Протоколы ALPN (например `h2`, `http/1.1`).
    pub alpn: &'static [&'static str],
    /// Точный порядок расширений — определяющий фактор JA3/JA4.
    pub extension_order: ExtensionOrder,
    /// Список cipher-suites (значения и порядок — часть отпечатка).
    pub cipher_suites: &'static [u16],
    /// Версия в заголовке TLS-записи (у Chrome — TLS 1.0, как в реальности).
    pub record_layer_version: ProtocolVersion,
    /// До какого размера добивать `ClientHello` паддингом (0 = без паддинга).
    pub target_padding_len: u16,
    /// Протоколы ALPS (`application_settings`) — поведение только Chromium.
    pub alps_protocols: &'static [&'static str],
    /// Вставлять ли GREASE-значения (обязательно для Chromium).
    pub has_grease: bool,
    /// Перемешивать ли середину списка расширений на каждое соединение.
    /// Chromium делает это с версии 110; не-Chromium стеки (Firefox, Safari)
    /// шлют фиксированный порядок, и для них флаг обязан быть `false`.
    pub shuffle_extensions: bool,
}

impl BrowserProfile {
    // --- REDACTED FOR PUBLIC RELEASE -------------------------------------
    // Приватный репозиторий держит здесь профили, снятые байт-в-байт с живых
    // захватов трафика реальных браузеров (cipher suites, паддинг, GREASE —
    // именно это определяет JA3/JA4-отпечаток). Профили ниже — ЗАГЛУШКИ:
    // движок с ними компилируется и проходит структурные тесты, но результат
    // не совпадает по отпечатку ни с одним живым браузером. Перед боевым
    // использованием подставьте собственную калибровку из свежего захвата.

    /// ЗАГЛУШКА.
    pub const CHROME_140: Self = Self {
        groups: TlsGroups::CHROMIUM_PQ,
        signatures: TlsSignatures::CHROME_PQ,
        delegated_signatures: TlsSignatures::CHROME_PQ,
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls10,

        cipher_suites: &[0x1301, 0x1302, 0x1303],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::CHROME_140,

        has_grease: true,
        shuffle_extensions: true,

        alps_protocols: &["h2"],

        target_padding_len: 0,
    };

    /// ЗАГЛУШКА.
    pub const CHROME_131: Self = Self {
        groups: TlsGroups::CHROMIUM,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::TLS_13_ONLY,

        record_layer_version: ProtocolVersion::Tls10,

        cipher_suites: &[0x1301, 0x1302, 0x1303],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::CHROMIUM_131,

        has_grease: true,
        shuffle_extensions: true,

        alps_protocols: &["h2"],

        target_padding_len: 512,
    };

    /// ЗАГЛУШКА.
    pub const FIREFOX_130: Self = Self {
        groups: TlsGroups::FIREFOX,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::FIREFOX_133,

        has_grease: false,
        shuffle_extensions: false,
        alps_protocols: &[],
        target_padding_len: 0,
    };

    /// ЗАГЛУШКА.
    pub const EDGE_130: Self = Self {
        groups: TlsGroups::CHROMIUM,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::TLS_13_ONLY,

        record_layer_version: ProtocolVersion::Tls10,

        cipher_suites: &[0x1301, 0x1302, 0x1303],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::EDGE_130,

        has_grease: true,
        shuffle_extensions: true,

        alps_protocols: &["h2"],

        target_padding_len: 512,
    };

    /// ЗАГЛУШКА.
    pub const SAFARI_17: Self = Self {
        groups: TlsGroups::SAFARI,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::SAFARI_17,

        has_grease: false,
        shuffle_extensions: false,
        alps_protocols: &[],
        target_padding_len: 0,
    };
    // -----------------------------------------------------------------------

    /// Пул профилей для ротации между туннельными сессиями.
    ///
    /// **Сейчас в пуле ровно один профиль, и это не недосмотр.** Ротация имеет
    /// смысл, только если каждый её элемент сам по себе неотличим от живого
    /// браузера. Замер сентября 2026 показал, что этому условию отвечает
    /// единственный профиль — [`CHROME_140`](Self::CHROME_140): у остальных нет
    /// постквантовой группы, то есть их `ClientHello` не совпадает ни с одним
    /// существующим браузером ни по JA3/JA4, ни по размеру. Ротация по такому
    /// пулу не размывала бы отпечаток, а раздавала бы трём четвертям сессий
    /// заведомо палевный.
    ///
    /// Чтобы вернуть сюда профиль, нужен свежий захват соответствующего
    /// браузера и перенос из него точных списков (см. историю правок
    /// `TlsSignatures::CHROME_PQ` — значения снимались с провода, а не
    /// восстанавливались по памяти). Профили ниже по файлу оставлены как
    /// образцы структуры и намеренно исключены из пула.
    pub const ALL: &'static [&'static Self] = &[&Self::CHROME_140];

    /// Выбирает профиль детерминированно по `session_id` — один и тот же
    /// стабильный отпечаток браузера на все ноги и все переподключения одной
    /// туннельной сессии.
    ///
    /// Раньше выбор шёл по номеру попытки реконнекта
    /// ([`ClientHandler::establish_leg`](crate::net::connection::ClientHandler::establish_leg)/
    /// [`TunnelEngine::attempt_reconnect`](crate::net::connection::engine::TunnelEngine::attempt_reconnect)):
    /// при нескольких быстрых реконнектах одной и той же ноги (сетевая
    /// нестабильность, экспоненциальный backoff в несколько секунд) с одного и
    /// того же клиентского IP на один и тот же серверный IP летели ClientHello
    /// с разными отпечатками браузеров подряд — Chrome, затем Edge, затем
    /// Firefox. Ни один настоящий браузер так себя не ведёт: смена «личности»
    /// TLS-стека на лету с того же адреса — сама по себе аномалия для
    /// корреляции по 5-tuple, более заметная, чем константный отпечаток,
    /// который эта ротация была призвана скрыть. Привязка к `session_id`
    /// (генерируется один раз на весь туннель в
    /// [`ClientHandler::connect`](crate::net::connection::ClientHandler::connect))
    /// даёт ту же цель (разные клиенты/сессии выглядят по-разному), не создавая
    /// эту внутрисессионную «смену браузера».
    pub fn for_session(session_id: &str) -> &'static Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session_id.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % Self::ALL.len();
        Self::ALL[idx]
    }
}

/// Серверный профиль ответа. Поля с префиксом `_` зарезервированы под будущее
/// расширение `ServerHello` и сейчас в сборке не участвуют.
pub(crate) struct ServerProfile {
    /// Версии для `supported_versions` в ответе.
    pub versions: TlsVersions,
    /// Версия заголовка TLS-записи ответа.
    pub record_layer_version: ProtocolVersion,
    /// Cipher-suites, среди которых выбирается один итоговый.
    pub cipher_suites: &'static [u16],
    pub _groups: TlsGroups,
    pub _signatures: TlsSignatures,
    pub _alpn: &'static [&'static str],
    pub _session_tickets: bool,
    /// `true` — приоритет у порядка сервера при выборе cipher-suite, иначе клиента.
    pub honor_cipher_order: bool,
}

impl ServerProfile {
    /// Современный серверный профиль: TLS 1.3/1.2, выбор suite по порядку сервера.
    pub const MODERN: Self = Self {
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303],
        _groups: TlsGroups::MODERN,
        _signatures: TlsSignatures::BROWSER_STANDARD,
        _alpn: &["h2", "http/1.1"],
        _session_tickets: true,
        honor_cipher_order: true,
    };

    /// Совместимый профиль: те же suite'ы плюс CBC-варианты — на случай, если
    /// понадобится отвечать клиентам/зондам, которые в своём (настоящем, не
    /// нашем) `ClientHello` не предлагают ни одного suite из [`MODERN`](Self::MODERN).
    /// Сейчас не используется по умолчанию (`ServerHandler` берёт `MODERN`),
    /// заготовлен как второй вариант — так же, как раньше `FIREFOX_130` был
    /// заготовкой без пути включения.
    pub const COMPAT: Self = Self {
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030],
        _groups: TlsGroups::MODERN,
        _signatures: TlsSignatures::BROWSER_STANDARD,
        _alpn: &["h2", "http/1.1"],
        _session_tickets: true,
        honor_cipher_order: true,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_session_is_deterministic_for_the_same_session_id() {
        let sid = "abc123deadbeef";
        let p1 = BrowserProfile::for_session(sid) as *const BrowserProfile;
        let p2 = BrowserProfile::for_session(sid) as *const BrowserProfile;
        assert_eq!(
            p1, p2,
            "same session_id must always pick the same profile — that's the whole point (stable fingerprint for the life of a tunnel session)"
        );
    }

    #[test]
    fn for_session_spreads_across_many_distinct_session_ids() {
        // Не строгая гарантия равномерности, но при 200 разных session_id все
        // 4 профиля из пула должны хоть раз да встретиться — иначе это не
        // ротация, а фиксированный выбор под видом ротации.
        let mut seen = std::collections::HashSet::new();
        for i in 0..200u32 {
            let sid = format!("session-{i}");
            let chosen = BrowserProfile::for_session(&sid) as *const BrowserProfile;
            seen.insert(chosen);
        }
        assert_eq!(
            seen.len(),
            BrowserProfile::ALL.len(),
            "expected all {} profiles to appear across 200 distinct sessions",
            BrowserProfile::ALL.len()
        );
    }
}
