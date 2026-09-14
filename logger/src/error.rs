//! Типизированная ошибка приложения и реестр кодов ошибок.
//!
//! [`AppError`] несёт стабильный машинный `code` (из реестра `ERR_*` ниже),
//! раздельные сообщения для пользователя и для логов, произвольные метаданные и
//! опциональную причину-источник. Коды используются в логах и метриках как
//! устойчивые идентификаторы классов ошибок.

use std::collections::HashMap;
use std::fmt;

// ── Реестр кодов ошибок (стабильные машинные идентификаторы) ──
/// Таймаут инфраструктуры (сеть/DNS/соединение).
pub const ERR_INFRA_TIMEOUT: &str = "INFRA_TIMEOUT";
/// Провал аутентификации (неверный auth-тег/payload).
pub const ERR_AUTH_FAILED: &str = "AUTH_FAILED";
/// Пакет отброшен из-за MTU в туннеле.
pub const ERR_NET_MTU_DROP: &str = "NET_TUNNEL_MTU_DROP";
/// Нарушение маскировки/целостности TLS (tampering, провал AEAD).
pub const ERR_NET_TLS_TAMPER: &str = "NET_TLS_TAMPER";
/// Необработанная паника (перехватывается логгером).
pub const ERR_SYS_PANIC: &str = "SYS_UNHANDLED_PANIC";

/// Ошибка приложения с машинным кодом, раздельными сообщениями и контекстом.
#[derive(Debug)]
pub struct AppError {
    /// Стабильный код класса ошибки (один из `ERR_*`).
    pub code: &'static str,
    /// Сообщение для пользователя (может показываться в UI).
    pub user_msg: String,
    /// Техническое сообщение для логов/отладки.
    pub internal_msg: String,
    /// Произвольные пары ключ-значение с контекстом.
    pub metadata: HashMap<String, String>,
    /// Опциональная причина-источник (для цепочки ошибок).
    pub cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl AppError {
    pub fn new(
        code: &'static str,
        user_msg: impl Into<String>,
        internal_msg: impl Into<String>,
    ) -> Self {
        Self {
            code,
            user_msg: user_msg.into(),
            internal_msg: internal_msg.into(),
            metadata: HashMap::new(),
            cause: None,
        }
    }

    /// Добавляет пару ключ-значение в метаданные (builder-стиль).
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Прикрепляет причину-источник ошибки (builder-стиль).
    pub fn with_cause(mut self, err: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.cause = Some(Box::new(err));
        self
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.internal_msg)
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|e| e.as_ref() as _)
    }
}
