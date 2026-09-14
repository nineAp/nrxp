//! # netrunner-logger — единый логгер и реестр ошибок проекта
//!
//! Тонкая обёртка над `tracing`/`tracing-subscriber`, дающая всем крейтам общий
//! стиль логирования и типизированные ошибки ([`error`]). Особенности:
//!
//! - **Один глобальный [`Logger`]** (`OnceLock` + `Once`): инициализируется раз,
//!   уровень переключается на лету через reloadable-фильтр ([`set_level`](Logger::set_level)).
//! - **Два режима**: production (JSON в файл с суточной ротацией + перехват паник)
//!   и debug (цветной вывод в консоль; на Android — `tracing_android`).
//! - **PII-редактор** ([`PiiRedactorLayer`]) — слой-заготовка для маскировки IP и
//!   прочих чувствительных данных перед записью.
//!
//! Макросы `info!`/`error!`/… ре-экспортируются, чтобы во всех крейтах писать
//! `netrunner_logger::info!` без прямой зависимости на `tracing`.

pub mod error;

use regex::Regex;
use std::sync::{Once, OnceLock};

// Экспортируем макросы и instrument, чтобы они были доступны как netrunner_logger::instrument
pub use tracing::{debug, error, info, instrument, span, trace, warn, Event};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt::{self, MakeWriter},
    layer::SubscriberExt,
    reload::Handle,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};

pub use error::{
    AppError, ERR_AUTH_FAILED, ERR_INFRA_TIMEOUT, ERR_NET_MTU_DROP, ERR_NET_TLS_TAMPER,
    ERR_SYS_PANIC,
};

type ReloadableFilter = Handle<EnvFilter, Registry>;

/// Глобальный логгер: ручка перезагружаемого фильтра уровня + guard файлового
/// аппендера (держит фоновый writer живым, пока жив логгер).
pub struct Logger {
    filter_handle: ReloadableFilter,
    _guard: Option<WorkerGuard>,
}

static INIT: Once = Once::new();
static LOGGER: OnceLock<Logger> = OnceLock::new();

/// `Write`-обёртка: вычищает IPv4-адреса из каждого записываемого куска байт
/// ПЕРЕД тем, как они дойдут до реального writer'а (файл/stdout). Основная
/// защита — вообще не логировать такие данные (см. call sites в
/// `netrunner-proxy`, где IP/hostname убраны из полей и текста событий) —
/// это только defense-in-depth на случай регресса (кто-то в будущем случайно
/// подставит адрес прямо в текст сообщения).
///
/// `tracing`'s `fmt::layer()` пишет одно событие = один вызов `write()` с уже
/// полностью отформatированной строкой, поэтому построчного/потокового
/// разбора не нужно — regex просто прогоняется по каждому куску целиком.
#[derive(Clone)]
struct RedactingWriter<W> {
    inner: W,
    ip_regex: Regex,
}

impl<W: std::io::Write> std::io::Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match std::str::from_utf8(buf) {
            Ok(s) => {
                let redacted = self.ip_regex.replace_all(s, "[redacted]");
                self.inner.write_all(redacted.as_bytes())?;
                Ok(buf.len())
            }
            // Не текст (не должно случаться для JSON/fmt-слоя) — пишем как есть,
            // чем терять данные лога целиком из-за одной небинарной строки.
            Err(_) => self.inner.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn pii_ip_regex() -> Regex {
    Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap()
}

/// `MakeWriter`-обёртка, оборачивающая каждый созданный writer в
/// [`RedactingWriter`] — так `RedactingWriter` можно навесить на любой слой
/// (`with_writer`), включая `NonBlocking` файлового аппендера.
struct RedactingMakeWriter<M> {
    inner: M,
    ip_regex: Regex,
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactingMakeWriter<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.make_writer(),
            ip_regex: self.ip_regex.clone(),
        }
    }
}

impl Logger {
    /// Инициализирует глобальный логгер (идемпотентно — только первый вызов
    /// действует). `is_production` выбирает JSON + перехват паник против
    /// цветного вывода в консоль.
    ///
    /// `log_dir` раньше означал "писать JSON-файлы прямо на диск ноды" — это
    /// было дебаг-решением: неограниченный локальный файл на проде уже дважды
    /// приводил к забитому диску и зависанию прокси (см. историю инцидентов
    /// на proxy-fr1). Теперь параметр сохранён только для дев/ручной
    /// диагностики (запуск локально с явным путём) — прод (`main.rs`) всегда
    /// зовёт `init(None, true)`: JSON уходит в stdout (его читает `docker logs`
    /// и, если нужно централизованно, promtail/аналог), файла на диске ноды
    /// не остаётся вообще.
    pub fn init(log_dir: Option<&str>, is_production: bool) {
        INIT.call_once(|| {
            // 1. Настройка динамического фильтра
            let filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            let (filter_layer, handle) = tracing_subscriber::reload::Layer::new(filter);

            // 2. Базовый реестр
            let registry = tracing_subscriber::registry().with(filter_layer);

            let mut file_guard = None;

            if is_production {
                // Прод: JSON, PII-фильтр на writer'е — на файл (если явно
                // попросили, дев-путь) или на stdout (обычный прод-путь).
                if let Some(path) = log_dir {
                    let file_appender = tracing_appender::rolling::daily(path, "netrunner.json");
                    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
                    let redacting_writer = RedactingMakeWriter {
                        inner: non_blocking,
                        ip_regex: pii_ip_regex(),
                    };

                    let json_layer = fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_current_span(true)
                        .with_span_list(true)
                        .with_writer(redacting_writer)
                        .with_ansi(false);

                    registry.with(json_layer).init();
                    file_guard = Some(guard);

                    // Глобальный перехват паник
                    std::panic::set_hook(Box::new(|info| {
                        tracing::error!(
                            error_code = ERR_SYS_PANIC,
                            panic_info = ?info,
                            "FATAL: Unhandled panic occurred. System is going down."
                        );
                    }));
                } else {
                    let redacting_writer = RedactingMakeWriter {
                        inner: std::io::stdout,
                        ip_regex: pii_ip_regex(),
                    };
                    registry
                        .with(
                            fmt::layer()
                                .json()
                                .with_writer(redacting_writer)
                                .with_ansi(false),
                        )
                        .init();
                }
            } else {
                // Дебаг режим: Красивый вывод в консоль
                #[cfg(target_os = "android")]
                let android_layer = tracing_android::layer("NETRUNNER_RUST")
                    .expect("Failed to create android layer");

                #[cfg(not(target_os = "android"))]
                let fmt_layer = fmt::layer()
                    .with_target(true)
                    .with_line_number(true)
                    .with_ansi(true)
                    .with_writer(std::io::stdout);

                #[cfg(target_os = "android")]
                registry.with(android_layer).init();

                #[cfg(not(target_os = "android"))]
                registry.with(fmt_layer).init();
            }

            let logger_instance = Logger {
                filter_handle: handle,
                _guard: file_guard,
            };

            let _ = LOGGER.set(logger_instance);

            eprintln!(
                "--- [DEBUG] Netrunner Logger initialized (Mode: {}, File: {}) ---",
                if is_production { "PROD" } else { "DEBUG" },
                log_dir.is_some()
            );
        });
    }

    /// Меняет уровень логирования на лету (например `"debug"`, `"info,foo=warn"`).
    pub fn set_level(&self, level: &str) {
        if let Ok(new_filter) = EnvFilter::try_new(level) {
            let _ = self.filter_handle.reload(new_filter);
            eprintln!("--- [DEBUG] Log level changed to: {} ---", level);
        }
    }

    /// Доступ к глобальному логгеру (паникует, если [`init`](Logger::init) не звали).
    pub fn global() -> &'static Logger {
        LOGGER.get().expect("Logger not initialized!")
    }

    // Вспомогательные методы для работы без макросов
    pub fn log_info(&self, msg: &str) {
        tracing::info!("{}", msg);
    }
    pub fn log_error(&self, msg: &str) {
        tracing::error!("{}", msg);
    }
}
