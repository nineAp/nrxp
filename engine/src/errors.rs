//! Ошибки разбора/обработки протокола и стратегия реакции на них.
//!
//! Ключевая идея — ошибка несёт в себе не только «что и где сломалось»
//! ([`ErrorStage`]), но и **что с этим делать** ([`ErrorAction`]). Вызывающий код
//! не принимает решение сам: он берёт [`TlsError::action`] и реагирует
//! единообразно. Это разводит «частичные данные» (норма — ждём ещё) и
//! «вмешательство/рассинхрон» (рвём ногу) по разным веткам без дублирования
//! логики в каждом месте парсинга.

use bytes::Bytes;
use netrunner_logger::{error, trace};

/// Что делать с соединением после ошибки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorAction {
    /// Данных пока недостаточно — это не ошибка, ждём следующего чтения сокета.
    Wait,
    /// Проксировать как обычный TLS (stealth-fallback) вместо разрыва.
    Redirect,
    /// Критично (tampering/рассинхрон) — закрыть ногу и переподключиться.
    Drop,
}

/// На каком уровне протокола произошла ошибка (со static-описанием причины).
#[derive(Debug)]
pub enum ErrorStage {
    /// Слой TLS-записи / шифрования.
    Tls(&'static str),
    /// Фаза хендшейка (`ClientHello`/`ServerHello`, обмен ключами).
    Handshake(&'static str),
    /// Фаза передачи данных (`ApplicationData`).
    ApplicationData(&'static str),
}

/// Ошибка протокола: стадия + предписанное действие + (опционально) сырые данные
/// для перенаправления/диагностики.
#[derive(Debug)]
pub struct TlsError {
    /// Где и почему сломалось.
    pub stage: ErrorStage,
    /// Как на это реагировать.
    pub action: ErrorAction,
    /// Сырые байты (например, для `Redirect` — переслать как есть; иначе пусто).
    pub data: Bytes,
}

impl TlsError {
    pub fn new(stage: ErrorStage, action: ErrorAction, data: Bytes) -> Self {
        Self {
            stage,
            action,
            data,
        }
    }

    fn log_error(&self) {
        let stage_name = match &self.stage {
            ErrorStage::Tls(_) => "TLS",
            ErrorStage::Handshake(_) => "Handshake",
            ErrorStage::ApplicationData(_) => "AppData",
        };

        let message = match &self.stage {
            ErrorStage::Tls(m) | ErrorStage::Handshake(m) | ErrorStage::ApplicationData(m) => m,
        };

        let data_preview = if !self.data.is_empty() {
            let limit = self.data.len().min(8);
            format!(
                "Hex: {:02x?}{}",
                &self.data[..limit],
                if self.data.len() > 8 { "..." } else { "" }
            )
        } else {
            "No data".to_string()
        };

        match self.action {
            ErrorAction::Wait => {
                trace!(
                    stage = stage_name,
                    action = ?self.action,
                    data = %data_preview,
                    "{}", message
                );
            }
            ErrorAction::Redirect => {
                error!(
                    stage = stage_name,
                    action = ?self.action,
                    data = %data_preview,
                    "⚠️ {}", message
                );
            }
            ErrorAction::Drop => {
                error!(
                    stage = stage_name,
                    action = ?self.action,
                    data = %data_preview,
                    "🚨 {}", message
                );
            }
        }
    }

    /// Логирует ошибку с уровнем, соответствующим её серьёзности, и возвращает
    /// предписанное действие. Вызывающий код матчится по результату.
    pub fn execute_strategy(&self) -> ErrorAction {
        self.log_error();
        self.action
    }
}
