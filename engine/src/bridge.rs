//! TLS-обёртка: граница между NRXP и маскирующим слоем [`tlseng`](crate::tlseng).
//!
//! [`TlsBridge`] — единственная точка, где протокол соприкасается с TLS-кадрами.
//! Он умеет две вещи:
//!
//! 1. **Хендшейк.** Собрать `ClientHello` (клиент) / `ServerHello` (сервер) с
//!    нужным профилем браузера и провести обмен ключами. На стороне сервера здесь
//!    же проверяется начальный auth-тег, спрятанный в `session_id` ClientHello, —
//!    первый барьер против чужих/сканирующих подключений.
//! 2. **Data-фаза.** Упаковать готовый шифртекст в TLS-запись `ApplicationData`
//!    ([`pack_app_data`](TlsBridge::pack_app_data)) и распаковать обратно
//!    ([`unpack_app_data`](TlsBridge::unpack_app_data)).
//!
//! Внутренний трейт [`TlsInterceptor`] задаёт общий каркас «распарсить TLS-запись
//! → проверить её тип → достать полезное содержимое» для хендшейка и AppData.

use crate::crypto::SessionKeys;
use crate::errors::{ErrorAction, ErrorStage, TlsError};
use crate::parser::Parser;
use crate::tlseng::ExtensionStack;
use crate::tlseng::{ApplicationData, TlsRecord};
use crate::tlseng::{BrowserProfile, ServerProfile};
use crate::tlseng::{ClientHello, HelloHeader, ServerHello};
use crate::tlseng::{ContentType, HelloType};
use bytes::{Bytes, BytesMut};

/// Каркас разбора TLS-записи нужного типа: `start_process` парсит запись и
/// делегирует в `handle_record`, который проверяет content-type и извлекает
/// типизированный результат.
trait TlsInterceptor {
    type Output;

    fn start_process(buffer: &mut BytesMut) -> Result<Option<Self::Output>, TlsError> {
        match TlsRecord::parse(buffer) {
            Ok(Some(record)) => Self::handle_record(record),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, TlsError>;
}

/// Разобранное handshake-сообщение одной из сторон вместе с его TLS-расширениями
/// (в расширениях лежат публичный ключ KeyShare и прочие поля, нужные для вывода
/// ключей сессии).
pub(crate) enum HandshakeMessage {
    /// `ClientHello` от клиента.
    Client {
        base: ClientHello,
        extensions: ExtensionStack,
    },
    /// `ServerHello` от сервера.
    Server {
        base: ServerHello,
        extensions: ExtensionStack,
    },
}

impl HandshakeMessage {
    pub fn random(&self) -> [u8; 32] {
        match self {
            Self::Client { base, .. } => base.random,
            Self::Server { base, .. } => base.random,
        }
    }

    pub fn extensions(&self) -> &ExtensionStack {
        match self {
            Self::Client { extensions, .. } => extensions,
            Self::Server { extensions, .. } => extensions,
        }
    }
}

impl TlsInterceptor for HandshakeMessage {
    type Output = HandshakeMessage;

    /// `record` здесь уже целиком получена с провода (длина взята из заголовка
    /// TLS-записи и `TlsRecord::parse` дожидается ровно стольких байт). Значит,
    /// если `HelloHeader`/`ClientHello`/`ServerHello` не смогли разобрать этот
    /// payload целиком — это не «пришло не всё», а испорченный/чужой hello.
    ///
    /// Раньше такой случай тихо возвращал `Ok(None)`, и вызывающий код
    /// (`ServerHandler::run`) трактовал его как «нужно больше данных» и ждал
    /// ещё до [`TLS_HELLO_TIMEOUT`](crate::net::TLS_HELLO_TIMEOUT) (10с), хотя
    /// новых байт для уже полностью прочитанной записи никогда не придёт —
    /// stealth-fallback запускался с большой задержкой вместо немедленно,
    /// нарушая заявленный принцип «при малейшем несоответствии — fallback».
    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, TlsError> {
        if record.content_type != ContentType::Handshake {
            return Err(TlsError::new(
                ErrorStage::Handshake("Expected Handshake record"),
                ErrorAction::Drop,
                record.serialize(),
            ));
        }

        let malformed = || {
            TlsError::new(
                ErrorStage::Handshake("Malformed handshake message"),
                ErrorAction::Drop,
                Bytes::new(),
            )
        };

        let mut payload = BytesMut::from(record.payload.as_ref());
        let header = HelloHeader::parse(&mut payload)?.ok_or_else(malformed)?;

        match header.header_type {
            HelloType::Client => {
                let hello = ClientHello::parse(&mut payload)?.ok_or_else(malformed)?;
                let ext = ExtensionStack::parse(&mut BytesMut::from(hello.extensions.as_ref()))?
                    .ok_or_else(|| {
                        TlsError::new(
                            ErrorStage::Handshake("Ext Err"),
                            ErrorAction::Drop,
                            Bytes::new(),
                        )
                    })?;
                Ok(Some(HandshakeMessage::Client {
                    base: hello,
                    extensions: ext,
                }))
            }
            HelloType::Server => {
                let hello = ServerHello::parse(&mut payload)?.ok_or_else(malformed)?;
                let ext = ExtensionStack::parse(&mut BytesMut::from(hello.extensions.as_ref()))?
                    .ok_or_else(|| {
                        TlsError::new(
                            ErrorStage::Handshake("Ext Err"),
                            ErrorAction::Drop,
                            Bytes::new(),
                        )
                    })?;
                Ok(Some(HandshakeMessage::Server {
                    base: hello,
                    extensions: ext,
                }))
            }
        }
    }
}

impl TlsInterceptor for ApplicationData {
    type Output = ApplicationData;

    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, TlsError> {
        if record.content_type != ContentType::ApplicationData {
            return Err(TlsError::new(
                ErrorStage::ApplicationData("Expected AppData record"),
                ErrorAction::Drop,
                record.serialize(),
            ));
        }
        Ok(Some(ApplicationData {
            _len: record.payload.len(),
            payload: record.payload,
        }))
    }
}

/// Маркер «фиктивная запись ChangeCipherSpec прочитана и вырезана из буфера» —
/// см. [`TlsBridge::build_middlebox_ccs`]/[`TlsBridge::unpack_middlebox_ccs`].
/// Сама запись не несёт полезной нагрузки, поэтому у типа нет полей.
struct ChangeCipherSpecMarker;

impl TlsInterceptor for ChangeCipherSpecMarker {
    type Output = ChangeCipherSpecMarker;

    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, TlsError> {
        if record.content_type != ContentType::ChangeCipherSpec {
            return Err(TlsError::new(
                ErrorStage::Tls("Expected ChangeCipherSpec record"),
                ErrorAction::Drop,
                record.serialize(),
            ));
        }
        Ok(Some(ChangeCipherSpecMarker))
    }
}

/// Фасад TLS-обёртки. Безсостоятельный набор статических операций над буферами;
/// всё состояние сессии живёт в [`SessionKeys`], которые передаются явно.
pub(crate) struct TlsBridge;

impl TlsBridge {
    /// Распаковать handshake-сообщение (`ClientHello`/`ServerHello`) из буфера.
    pub fn unpack_handshake(buffer: &mut BytesMut) -> Result<Option<HandshakeMessage>, TlsError> {
        HandshakeMessage::start_process(buffer)
    }

    /// Распаковать TLS-запись `ApplicationData` (ещё зашифрованный кадр NRXP).
    pub fn unpack_app_data(buffer: &mut BytesMut) -> Result<Option<ApplicationData>, TlsError> {
        ApplicationData::start_process(buffer)
    }

    /// Собрать `ClientHello` по профилю браузера для маскировки (клиент).
    pub fn wrap_client_hello(profile: &BrowserProfile, host: &str, keys: &SessionKeys) -> Bytes {
        ClientHello::make_client_hello(profile, host, keys)
    }

    /// Обработать `ClientHello` и собрать ответный `ServerHello` (сервер).
    ///
    /// Порядок критичен: сначала проверяется auth-тег из `session_id`
    /// (16 байт со смещения 16) — неверный тег ⇒ отказ ещё до любых
    /// криптоопераций; затем выводятся ключи сессии и формируется ответ.
    ///
    /// Возвращает вместе с готовым `ServerHello` заявленную клиентом версию
    /// протокола (`session_id[0]`, см. [`crate::PROTOCOL_VERSION`]) — вызывающий
    /// код использует её, чтобы решить, какое версионно-зависимое поведение
    /// (например, обмен `ChangeCipherSpec`) включать именно для этого клиента.
    pub fn wrap_server_hello(
        client_msg: &HandshakeMessage,
        keys: &mut SessionKeys,
        profile: &ServerProfile,
    ) -> Result<(Bytes, u8), TlsError> {
        if let HandshakeMessage::Client { base, extensions } = client_msg {
            if base.session_id.len() != 32 {
                return Err(TlsError::new(
                    ErrorStage::Handshake("Invalid SessionID len"),
                    ErrorAction::Drop,
                    Bytes::new(),
                ));
            }

            let peer_version = base.session_id[0];
            keys.set_peer_version(peer_version);

            let mut received_tag = [0u8; 16];
            received_tag.copy_from_slice(&base.session_id[16..32]);

            // Эфемерный ключ клиента нужен ДО проверки тега: в схеме v3 он
            // входит в сам тег. Это только разбор уже распарсенных расширений,
            // без криптографии, — на неаутентифицированном вводе тяжелее HMAC
            // здесь ничего быть не должно.
            let peer_public = SessionKeys::extract_peer_public(extensions, true).map_err(|e| {
                netrunner_logger::warn!(error = %e, "Malformed KeyShare in ClientHello");
                TlsError::new(
                    ErrorStage::Handshake("Bad KeyShare"),
                    ErrorAction::Drop,
                    Bytes::new(),
                )
            })?;

            // Порядок сохранён: тег проверяется до вывода ключей. Какой именно
            // тег ожидается — ключевой (v3) или старый безключевой (v2) —
            // решает `SessionKeys` по учётным данным ноды и заявленной версии
            // клиента; нода в строгом режиме отвергает анонимную схему целиком.
            if !keys.verify_handshake_tag(&received_tag, &base.random, &peer_public) {
                netrunner_logger::warn!(
                    peer_version,
                    "Unauthorized ClientHello: Auth Tag mismatch"
                );
                return Err(TlsError::new(
                    ErrorStage::Handshake("Auth Failed"),
                    ErrorAction::Drop,
                    Bytes::new(),
                ));
            }

            keys.update_keys(base.random, extensions, true)
                .map_err(|e| {
                    netrunner_logger::error!(error = %e, "Server failed key update");
                    TlsError::new(
                        ErrorStage::Handshake("Key Exchange Failed"),
                        ErrorAction::Drop,
                        Bytes::new(),
                    )
                })?;

            let server_pub_key = keys.public_key_bytes();

            let hello =
                ServerHello::make_server_hello(base, &server_pub_key, keys.local_salt(), profile);

            Ok((hello, peer_version))
        } else {
            Err(TlsError::new(
                ErrorStage::Handshake("Expected ClientHello"),
                ErrorAction::Drop,
                Bytes::new(),
            ))
        }
    }

    /// Обернуть готовый шифртекст кадра в TLS-запись `ApplicationData` (`0x17`).
    pub fn pack_app_data(buffer: Bytes) -> Bytes {
        TlsRecord::build_application_data(buffer)
    }

    /// Байты фиктивной записи `ChangeCipherSpec` — обе наши стороны шлют её
    /// сразу после своего Hello ради middlebox-совместимости TLS 1.3 (RFC 8446
    /// Appendix D.4), как это делают настоящие браузеры (см. doc на
    /// [`ContentType::ChangeCipherSpec`](crate::tlseng::ContentType)).
    pub fn build_middlebox_ccs() -> Bytes {
        TlsRecord::build_change_cipher_spec()
    }

    /// Дождаться (если нужно больше байт — `Ok(None)`) и вырезать из буфера
    /// `ChangeCipherSpec`, присланный пиром сразу после его Hello. Пир — наша
    /// же реализация на другом конце, поэтому запись всегда присутствует;
    /// её отсутствие/искажение — рассинхрон протокола ([`ErrorAction::Drop`]).
    pub fn unpack_middlebox_ccs(buffer: &mut BytesMut) -> Result<Option<()>, TlsError> {
        Ok(ChangeCipherSpecMarker::start_process(buffer)?.map(|_| ()))
    }
}
