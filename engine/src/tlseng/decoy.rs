//! Decoy: под какой домен маскируется узел и из чего собирается его витрина.
//!
//! ## Смена модели: не изображать сайт, а быть им
//!
//! Раньше decoy был чужим доменом (`www.debian.org`), а всё «не наше»
//! соединение прозрачно проксировалось на него. У этого было три следствия,
//! каждое из которых по отдельности выдавало узел:
//!
//! 1. **Открытый релей.** Fallback ходил на тот SNI, который назвал клиент, —
//!    значит узел отдавал валидный сертификат любого запрошенного домена. Ни
//!    один настоящий сервер так себя не ведёт; классификация занимала две
//!    TCP-сессии.
//! 2. **Сертификат против географии.** Узел в одной стране предъявлял
//!    сертификат сайта, чей origin в другой, а DNS этого домена никогда не
//!    указывал на узел.
//! 3. **Cover-flight пальцем в небо.** Настоящий flight сайта детерминирован
//!    (у `www.debian.org` это ровно `27 → 4342 → 537 → 69` байт, воспроизводимо
//!    от зонда к зонду), а мы отправляли две записи случайной длины — и разные
//!    на каждой ноге, то есть «сертификат», меняющийся от коннекта к коннекту.
//!
//! Все три исчезают разом, если узел обслуживает **собственный** домен с
//! **собственным** сертификатом и настоящим содержимым. Тогда мимикрия не
//! нужна: отпечаток совпадает не потому, что скопирован, а потому что он и
//! есть настоящий.
//!
//! Отсюда критерий «под что можно валидно мимикрировать» — не «какой известный
//! сайт похож», а **«какой домен мы контролируем и реально отдаём»**. Список
//! таких доменов приходит извне ([`DecoyCatalog`]), а [`DecoySni`] — билет,
//! который нельзя выписать в обход каталога.
//!
//! ## Витрина как конструктор
//!
//! [`Decoy`] описывает страницу списком блоков ([`elements`](Decoy::elements)):
//! имена файлов, которые собираются в один статический HTML. Сборка
//! происходит **один раз при деплое узла**, не на каждый запрос — витрина не
//! SSR и не должна им быть: динамика на «обычном сайте» создаёт нагрузочный
//! профиль, которого у статического лендинга не бывает.

use std::fmt;

/// Переменная окружения со списком доменов узла через запятую.
/// Заполняется провижинингом из того же источника, что и админка бэкенда,
/// чтобы список «что можно выбрать» был один на систему.
pub const DECOY_DOMAINS_ENV: &str = "NETRUNNER_DECOY_DOMAINS";

/// Как узел маскируется. Два взаимоисключающих режима — оба валидны, у каждого
/// свой размен, поэтому выбор делается **на узел** (в админке), а не глобально.
///
/// ## `Relay` — заимствование чужого сертификата (REALITY-style)
///
/// Узел **не владеет** доменом-decoy. «Не наши» соединения (сканеры, активные
/// зонды) он прозрачно ретранслирует на *настоящий* сайт (`decoy_host`), и тот
/// отдаёт свой подлинный сертификат. Клиент в своём `ClientHello` тоже ставит
/// SNI этого чужого домена.
///
/// - **Плюс:** не нужно покупать домен и выпускать сертификат — берётся уже
///   доверенный, часто в белых списках (напр. большой CDN).
/// - **Минус:** ретрансляция добавляет к хендшейку время round-trip до
///   заимствованного сайта (в первом отчёте это была та самая сигнатура
///   «+107 мс»), а сертификат чужого домена приезжает с IP/ASN узла — то есть
///   `cert ↔ ASN` расходятся. Лечится географией (decoy рядом с узлом), но не
///   исчезает полностью.
///
/// Это **исторический режим по умолчанию**: узлы, поднятые до появления выбора,
/// работают именно так, и [`DecoyMode::default`] возвращает его — обратная
/// совместимость.
///
/// ## `SelfHosted` — узел САМ является сайтом (УТП)
///
/// Узел **владеет** доменом и обслуживает под ним настоящую витрину (см.
/// [`super::decoy`] и конструктор блоков). Ничего никуда не ретранслируется:
/// отпечаток, сертификат и cover-flight — не скопированы, а настоящие, потому
/// что это и есть настоящий сайт этого узла.
///
/// - **Плюс:** нет ретрансляционной задержки, нет расхождения `cert ↔ ASN`,
///   нет открытого релея. Активный зонд с любым SNI получает один и тот же
///   собственный сайт узла — ровно как настоящий сервер.
/// - **Минус:** нужен свой домен, свой сертификат (обычно Let's Encrypt рядом
///   через локальный TLS-терминатор) и собранная витрина.
///
/// SNI в этом режиме обязан пройти [`DecoyCatalog::validate`]: под домен,
/// которым узел не владеет, валидного сертификата нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyMode {
    /// REALITY-style: ретрансляция на чужой реальный сайт.
    Relay,
    /// УТП: узел сам обслуживает свою витрину под своим доменом.
    SelfHosted,
}

impl Default for DecoyMode {
    /// [`Relay`](DecoyMode::Relay) — историческое поведение. Узел без явно
    /// выбранного режима ведёт себя ровно как до появления выбора.
    fn default() -> Self {
        Self::Relay
    }
}

impl DecoyMode {
    /// Разбор из строки конфига/CLI. Неизвестное значение — ошибка (а не тихий
    /// откат к дефолту): опечатка в режиме маскировки не должна молча поднять
    /// узел не в том режиме.
    pub fn parse(s: &str) -> Result<Self, DecoyError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "relay" | "reality" | "borrowed" => Ok(Self::Relay),
            "self-hosted" | "self_hosted" | "selfhosted" | "owned" | "utp" => Ok(Self::SelfHosted),
            _ => Err(DecoyError::UnknownMode),
        }
    }

    /// Ретранслировать ли fallback на **запрошенный клиентом** SNI.
    ///
    /// В [`Relay`](DecoyMode::Relay) — да, это историческое поведение
    /// `handle_stealth_fallback`. В [`SelfHosted`](DecoyMode::SelfHosted) — нет:
    /// узел всегда отдаёт свой собственный сайт, а не идёт на чей-то ещё,
    /// поэтому запрошенный зондом SNI игнорируется (и открытого релея не
    /// возникает).
    pub fn honor_requested_sni(self) -> bool {
        matches!(self, Self::Relay)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::SelfHosted => "self-hosted",
        }
    }
}

/// Почему SNI отвергнут. Отдельный тип, а не `bool`/`String`: админке нужно
/// показать причину, а не просто «нельзя».
#[derive(Debug, PartialEq, Eq)]
pub enum DecoyError {
    /// Пустая строка или одни пробелы.
    Empty,
    /// Длиннее 253 байт — предела hostname по RFC 1035.
    TooLong,
    /// Литеральный IP: SNI по стандарту несёт имя, а не адрес. Браузер туда
    /// IP не кладёт никогда, поэтому его наличие — самостоятельный признак.
    IpLiteral,
    /// Недопустимые символы для hostname.
    BadSyntax,
    /// Синтаксически валиден, но узел этим доменом не владеет. Именно этот
    /// случай закрывает дыру «в админке можно указать любой SNI»: под чужой
    /// домен мимикрировать валидно нельзя — у нас нет его сертификата, и
    /// первый же активный зонд это покажет.
    NotOwned { available: usize },
    /// Строка режима маскировки не распознана (см. [`DecoyMode::parse`]).
    UnknownMode,
}

impl fmt::Display for DecoyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "SNI не задан"),
            Self::TooLong => write!(f, "SNI длиннее 253 байт"),
            Self::IpLiteral => write!(f, "SNI обязан быть именем хоста, а не IP-адресом"),
            Self::BadSyntax => write!(f, "SNI содержит недопустимые для hostname символы"),
            Self::UnknownMode => write!(
                f,
                "неизвестный режим маскировки (ожидалось relay | self-hosted)"
            ),
            Self::NotOwned { available } => write!(
                f,
                "домен не принадлежит узлу; доступно доменов: {available}. \
                 Мимикрия валидна только под собственный домен с собственным \
                 сертификатом — иначе активный зонд получит чужой сертификат \
                 с нашего адреса"
            ),
        }
    }
}

/// Проверенный SNI. Сконструировать можно **только** через
/// [`DecoyCatalog::validate`] — поле приватное, публичного конструктора нет.
/// Тип существует именно ради этого: он делает «непроверенный SNI» состоянием,
/// которое невозможно выразить, вместо того чтобы полагаться на дисциплину
/// вызывающего кода.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoySni(String);

impl DecoySni {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DecoySni {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Домены, которыми узел реально владеет и которые реально отдаёт.
#[derive(Debug, Clone, Default)]
pub struct DecoyCatalog {
    domains: Vec<String>,
}

impl DecoyCatalog {
    /// Разбирает список вида `a.com, b.net,c.org`. Пустые элементы и пробелы
    /// отбрасываются, регистр нормализуется: DNS-имена регистронезависимы, а
    /// сравнение строк — нет, и это ровно тот баг, который проявляется один
    /// раз в проде на домене, введённом в админке с заглавной буквы.
    pub fn from_list(list: &str) -> Self {
        let mut domains: Vec<String> = list
            .split(',')
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        domains.sort();
        domains.dedup();
        Self { domains }
    }

    /// Читает каталог из [`DECOY_DOMAINS_ENV`]. Отсутствие переменной — пустой
    /// каталог, а не паника: узел должен подняться и внятно сказать, что
    /// маскироваться ему не подо что, а не упасть на старте.
    pub fn from_env() -> Self {
        std::env::var(DECOY_DOMAINS_ENV)
            .map(|v| Self::from_list(&v))
            .unwrap_or_default()
    }

    /// Список для выпадающего меню в админке. Ровно те значения, которые
    /// пройдут [`validate`](Self::validate) — админка не должна предлагать
    /// вариант, который потом будет отвергнут.
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Единственный путь получить [`DecoySni`].
    pub fn validate(&self, sni: &str) -> Result<DecoySni, DecoyError> {
        let host = sni.trim().trim_end_matches('.').to_ascii_lowercase();

        if host.is_empty() {
            return Err(DecoyError::Empty);
        }
        if host.len() > 253 {
            return Err(DecoyError::TooLong);
        }
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Err(DecoyError::IpLiteral);
        }
        if !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(DecoyError::BadSyntax);
        }
        if !self.domains.iter().any(|d| *d == host) {
            return Err(DecoyError::NotOwned {
                available: self.domains.len(),
            });
        }

        Ok(DecoySni(host))
    }
}

/// Витрина узла: под каким именем он живёт и из каких блоков собрана страница.
#[derive(Debug, Clone)]
pub struct Decoy {
    /// Домен узла — он же SNI в `ClientHello`, он же CN сертификата.
    pub sni: DecoySni,
    /// Имена блоков в порядке вывода: `header`, `hero`, `pricing`, `footer`…
    /// Резолвятся в файлы `blocks/<имя>.html` при сборке витрины.
    pub elements: Vec<String>,
}

/// Длины TLS-записей, которыми узел отвечает сразу после `ServerHello`.
///
/// ## Почему это больше не случайные числа
///
/// Раньше flight сэмплировался (`random_range(1400..=4200)`), и замер показал,
/// во что это выливается: четыре ноги одной сессии за три секунды предъявили
/// «сертификаты» на 3627, 3217, 1910 и 1493 байта. У настоящего сервера длина
/// flight'а определяется цепочкой сертификатов, то есть постоянна — два зонда
/// к `www.debian.org` дали побайтово одинаковый ответ. Разброс сам стал
/// признаком, более грубым, чем константа, которую он маскировал.
///
/// Теперь узел обслуживает собственный домен, а значит **знает свою цепочку**.
/// Длины считаются из неё арифметически — и совпадают с тем, что отдал бы
/// настоящий TLS-терминатор с тем же сертификатом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverFlight {
    /// Длины записей `ApplicationData` по порядку.
    pub records: Vec<usize>,
}

impl CoverFlight {
    /// Накладные расходы TLS 1.3-записи под шифром: 16 байт AEAD-тега плюс
    /// байт внутреннего content-type.
    const SEALED: usize = 17;

    /// Считает flight по длинам DER-сертификатов цепочки и длине подписи в
    /// `CertificateVerify`.
    ///
    /// Порядок и состав воспроизводят настоящий сервер (RFC 8446 §4.4):
    ///
    /// | Запись | Содержимое |
    /// |--------|-----------|
    /// | 1 | `EncryptedExtensions` — маленькая, обычно 20–30 байт |
    /// | 2 | `Certificate` — вся цепочка, килобайты |
    /// | 3 | `CertificateVerify` — подпись |
    /// | 4 | `Finished` — HMAC размера хеша |
    ///
    /// Именно такую четвёрку отдал живой `www.debian.org` (27 → 4342 → 537 →
    /// 69). Прежняя реализация слала **две** записи в обратном порядке —
    /// большую, затем маленькую, — то есть не совпадала ни числом записей, ни
    /// их формой.
    /// Типовой flight узла по умолчанию, когда точная цепочка ещё не измерена:
    /// лист + промежуточный сертификат уровня Let's Encrypt (ECDSA P-256),
    /// подпись P-256, SHA-256. Это разумная отправная точка на старте узла до
    /// того, как он снимет собственную цепаль; главное её свойство —
    /// **детерминизм**: одинаковый flight на всех ногах, чего и не хватало.
    ///
    /// Правильный следующий шаг — заменить её реально измеренной цепочкой
    /// узла (`--decoy-cert-chain` или одноразовый зонд локального сайта на
    /// старте): числа станут не просто стабильными, а совпадающими с тем, что
    /// отдаёт настоящий TLS-терминатор этого домена.
    pub fn node_default() -> Self {
        Self::from_chain(&[1250, 1100], 72, 32)
    }

    /// Длины записей как срез — для передачи в движок cover-flight.
    pub fn as_records(&self) -> &[usize] {
        &self.records
    }

    pub fn from_chain(cert_der_lens: &[usize], signature_len: usize, hash_len: usize) -> Self {
        // EncryptedExtensions: заголовок(4) + список расширений. У сервера с
        // ALPN там ровно одно расширение (`application_layer_protocol_negotiation`).
        let encrypted_extensions = 4 + 2 + 7 + Self::SEALED;

        // Certificate: заголовок(4) + context_len(1) + list_len(3) +
        // на каждый сертификат: len(3) + DER + extensions_len(2).
        let cert_body: usize = cert_der_lens.iter().map(|l| 3 + l + 2).sum();
        let certificate = 4 + 1 + 3 + cert_body + Self::SEALED;

        // CertificateVerify: заголовок(4) + scheme(2) + sig_len(2) + подпись.
        let certificate_verify = 4 + 2 + 2 + signature_len + Self::SEALED;

        // Finished: заголовок(4) + verify_data размера хеша.
        let finished = 4 + hash_len + Self::SEALED;

        Self {
            records: vec![
                encrypted_extensions,
                certificate,
                certificate_verify,
                finished,
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> DecoyCatalog {
        DecoyCatalog::from_list("clipforge.app, hauler.tools ,, LOGDRAIN.io ,")
    }

    #[test]
    fn catalog_normalises_case_whitespace_and_duplicates() {
        let c = DecoyCatalog::from_list(" a.com , A.com,, b.net. ");
        assert_eq!(c.domains(), &["a.com".to_string(), "b.net".to_string()]);
    }

    #[test]
    fn owned_domain_validates_case_insensitively() {
        let c = catalog();
        assert_eq!(
            c.validate("ClipForge.app").unwrap().as_str(),
            "clipforge.app"
        );
        assert_eq!(c.validate("logdrain.io").unwrap().as_str(), "logdrain.io");
    }

    #[test]
    fn foreign_domain_is_rejected_however_famous() {
        // Это и есть закрытая дыра: в админке нельзя выбрать чужой домен.
        // Под него невозможно валидно мимикрировать — сертификата нет.
        let c = catalog();
        for foreign in ["www.debian.org", "www.microsoft.com", "github.com"] {
            assert!(
                matches!(c.validate(foreign), Err(DecoyError::NotOwned { .. })),
                "{foreign} не принадлежит узлу и обязан быть отвергнут"
            );
        }
    }

    #[test]
    fn malformed_sni_is_rejected_before_ownership_is_considered() {
        let c = catalog();
        assert_eq!(c.validate("").unwrap_err(), DecoyError::Empty);
        assert_eq!(c.validate("10.0.0.1").unwrap_err(), DecoyError::IpLiteral);
        assert_eq!(c.validate("a_b.com").unwrap_err(), DecoyError::BadSyntax);
        assert_eq!(
            c.validate(&"a".repeat(254)).unwrap_err(),
            DecoyError::TooLong
        );
    }

    #[test]
    fn empty_catalog_rejects_everything_without_panicking() {
        let c = DecoyCatalog::from_list("");
        assert!(c.is_empty());
        assert!(matches!(
            c.validate("anything.com"),
            Err(DecoyError::NotOwned { available: 0 })
        ));
    }

    #[test]
    fn relay_mode_is_the_backward_compatible_default() {
        // Узел без явного выбора обязан вести себя как исторический REALITY-релей.
        assert_eq!(DecoyMode::default(), DecoyMode::Relay);
        assert!(
            DecoyMode::Relay.honor_requested_sni(),
            "relay учитывает запрошенный SNI (как раньше)"
        );
    }

    #[test]
    fn self_hosted_never_honours_the_requested_sni() {
        // Ключевое отличие: узел всегда отдаёт СВОЙ сайт, поэтому открытого
        // релея (сертификат любого запрошенного домена) не возникает.
        assert!(!DecoyMode::SelfHosted.honor_requested_sni());
    }

    #[test]
    fn mode_parses_its_aliases_and_rejects_typos() {
        for s in ["relay", "REALITY", "borrowed"] {
            assert_eq!(DecoyMode::parse(s).unwrap(), DecoyMode::Relay);
        }
        for s in ["self-hosted", "owned", "utp", "SelfHosted"] {
            assert_eq!(DecoyMode::parse(s).unwrap(), DecoyMode::SelfHosted);
        }
        // Опечатка не должна молча поднять узел не в том режиме.
        assert_eq!(
            DecoyMode::parse("realyy").unwrap_err(),
            DecoyError::UnknownMode
        );
    }

    #[test]
    fn cover_flight_reproduces_the_shape_of_a_real_server() {
        // Цепочка масштаба Let's Encrypt: лист ~1200 B + промежуточный ~1100 B,
        // подпись ECDSA P-256 ~72 B, SHA-256.
        let f = CoverFlight::from_chain(&[1200, 1100], 72, 32);
        assert_eq!(f.records.len(), 4, "настоящий flight — четыре записи");

        let [ee, cert, cv, fin] = f.records[..] else {
            panic!("ожидалось ровно четыре записи");
        };
        // Форма: маленькая → большая → средняя → маленькая. Прежняя реализация
        // давала обратную (большая → маленькая) и всего из двух записей.
        assert!(ee < 64, "EncryptedExtensions — десятки байт, получено {ee}");
        assert!(cert > 2000, "Certificate — килобайты, получено {cert}");
        assert!(cv < cert && cv > fin, "CertificateVerify между ними: {cv}");
        assert!(fin < 64, "Finished — десятки байт, получено {fin}");
    }

    #[test]
    fn cover_flight_is_deterministic_for_a_given_chain() {
        // Ровно то свойство, которого не хватало: у настоящего сервера длина
        // flight'а не меняется от коннекта к коннекту.
        let a = CoverFlight::from_chain(&[1200, 1100], 72, 32);
        let b = CoverFlight::from_chain(&[1200, 1100], 72, 32);
        assert_eq!(a, b);
    }

    #[test]
    fn bigger_chain_yields_proportionally_bigger_certificate_record() {
        let small = CoverFlight::from_chain(&[1200, 1100], 72, 32);
        let rsa = CoverFlight::from_chain(&[1600, 1500, 1400], 256, 48);
        assert!(rsa.records[1] > small.records[1] + 1500);
    }
}
