use std::{
    error::Error,
    future::IntoFuture,
    ops::Deref,
    sync::{
        Arc, Mutex as SyncMutex,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::{Buf, Bytes};
use futures::{Stream, StreamExt, future::BoxFuture};
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{AsHeaderName, IntoHeaderName},
    uri::Authority,
};
use snafu::{Report, ResultExt, Snafu};
use tokio::sync::Mutex as AsyncMutex;

use super::H3Endpoint;
use crate::{
    endpoint::client::request_error::StreamInitSnafu,
    error::Code,
    message::{
        stream::{InitialMessageStreamError, MessageStreamError, ReadStream, WriteStream},
        unify::{MalformedMessageError, Message, ReadToStringError},
    },
    pool::ConnectError,
    qpack::field::MalformedHeaderSection,
    quic::{self, agent},
};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RequestError<E: Error + 'static> {
    #[snafu(display("failed to connect endpoint"))]
    Connect { source: Arc<ConnectError<E>> },
    #[snafu(transparent)]
    Connection { source: quic::ConnectionError },
    #[snafu(display("request stream error"))]
    RequestStream { source: quic::StreamError },
    #[snafu(display("response stream error"))]
    ResponseStream { source: quic::StreamError },
    #[snafu(display("request cannot be sent due to malformed header"))]
    MalformedRequestHeader { source: Arc<MalformedHeaderSection> },
    #[snafu(display(
        "header section too large to fit into a single frame, maybe too many header fields"
    ))]
    HeaderTooLarge,
    #[snafu(display(
        "trailer section too large to fit into a single frame, maybe too many header fields"
    ))]
    TrailerTooLarge,
    #[snafu(display("data frame payload too large, try smaller chunk size"))]
    DataFrameTooLarge,
    #[snafu(display("response from peer is malformed"))]
    MalformedResponse,
    #[snafu(transparent)]
    Acquire { source: AcquireError },
    #[snafu(display("failed to open initial message stream"))]
    StreamInit { source: InitialMessageStreamError },
    #[snafu(transparent)]
    MessageStream { source: MessageStreamError },
}

impl<E: Error + 'static> From<ConnectError<E>> for RequestError<E> {
    fn from(source: ConnectError<E>) -> Self {
        Self::Connect {
            source: Arc::new(source),
        }
    }
}
impl<E: Error + 'static> Clone for RequestError<E> {
    fn clone(&self) -> Self {
        match self {
            Self::Connect { source } => Self::Connect {
                source: Arc::clone(source),
            },
            Self::Connection { source } => Self::Connection {
                source: source.clone(),
            },
            Self::RequestStream { source } => Self::RequestStream {
                source: source.clone(),
            },
            Self::ResponseStream { source } => Self::ResponseStream {
                source: source.clone(),
            },
            Self::MalformedRequestHeader { source } => Self::MalformedRequestHeader {
                source: Arc::clone(source),
            },
            Self::HeaderTooLarge => Self::HeaderTooLarge,
            Self::TrailerTooLarge => Self::TrailerTooLarge,
            Self::DataFrameTooLarge => Self::DataFrameTooLarge,
            Self::MalformedResponse => Self::MalformedResponse,
            Self::Acquire { source } => Self::Acquire {
                source: source.clone(),
            },
            Self::StreamInit { source } => Self::StreamInit {
                source: source.clone(),
            },
            Self::MessageStream { source } => Self::MessageStream {
                source: source.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module)]
pub enum AcquireError {
    #[snafu(display("resource already taken by another clone"))]
    AlreadyTaken,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum AuthorityFrozen {
    #[snafu(display("authority is frozen — uri() called after stream initialization"))]
    InitComplete,
}

pub(crate) type Arbiter<Q, EP> = RequestState<Q, EP>;

pub(crate) struct RequestState<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q, Q::Connection>>> {
    message: SyncMutex<Message>,
    write_stream: AsyncMutex<Option<WriteStream>>,
    read_stream: AsyncMutex<Option<ReadStream>>,
    init_state: AsyncMutex<Option<Result<(), RequestError<Q::Error>>>>,
    endpoint: EP,
    authority: SyncMutex<Option<Authority>>,
    init_done: AtomicBool,
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q, Q::Connection>>> RequestState<Q, EP> {
    pub(crate) fn new(endpoint: EP, message: Message) -> Self {
        Self {
            message: SyncMutex::new(message),
            write_stream: AsyncMutex::new(None),
            read_stream: AsyncMutex::new(None),
            init_state: AsyncMutex::new(None),
            endpoint,
            authority: SyncMutex::new(None),
            init_done: AtomicBool::new(false),
        }
    }

    pub(crate) fn set_authority(&self, auth: Authority) -> Result<(), AuthorityFrozen> {
        if self.init_done.load(Ordering::Acquire) {
            return Err(AuthorityFrozen::InitComplete);
        }
        *self.authority.lock().expect("lock poisoned") = Some(auth);
        Ok(())
    }

    fn message(&self) -> std::sync::MutexGuard<'_, Message> {
        self.message.lock().expect("lock poisoned")
    }

    fn mark_message_failed_unless_malformed(&self) {
        let mut message = self.message();
        if !message.is_malformed() {
            message.set_failed();
        }
    }

    fn operate_message(
        &self,
        operation: &'static str,
        operate: impl FnOnce(&mut Message) -> Result<(), MalformedMessageError>,
    ) {
        let mut message = self.message();
        if message.is_malformed() {
            tracing::warn!(
                operation,
                "request is malformed, operation will not affect the request stream"
            );
            return;
        }
        if let Err(error) = operate(&mut message) {
            let report = Report::from_error(&error);
            tracing::warn!(
                operation,
                error = %report,
                "operation malformed the request message, request stream will be cancelled"
            );
            message.set_malformed();
        }
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q, Q::Connection>>> RequestState<Q, EP>
where
    Q::Error: std::error::Error + Send + Sync + 'static,
{
    async fn ensure_stream_init(&self) -> Result<(), RequestError<Q::Error>> {
        if self.init_done.load(Ordering::Acquire) {
            return self
                .init_state
                .lock()
                .await
                .as_ref()
                .expect("init_state is Some when init_done is true")
                .clone();
        }

        let mut guard = self.init_state.lock().await;
        if let Some(cached) = guard.as_ref() {
            return cached.clone();
        }

        let authority = self
            .authority
            .lock()
            .expect("lock poisoned")
            .clone()
            .ok_or_else(|| RequestError::MalformedRequestHeader {
                source: Arc::new(MalformedHeaderSection::EmptyAuthorityOrHost),
            })?;

        let result: Result<(), RequestError<Q::Error>> = async {
            let connection = self.endpoint.connect(authority).await?;
            let (read_stream, write_stream) = connection
                .initial_message_stream()
                .await
                .context(StreamInitSnafu)?;
            *self.read_stream.lock().await = Some(read_stream);
            *self.write_stream.lock().await = Some(write_stream);
            Ok(())
        }
        .await;

        *guard = Some(result.clone());
        self.init_done.store(true, Ordering::Release);
        result
    }

    async fn take_read_stream(&self) -> Result<ReadStream, RequestError<Q::Error>> {
        self.ensure_stream_init().await?;
        self.read_stream
            .lock()
            .await
            .take()
            .ok_or(RequestError::Acquire {
                source: AcquireError::AlreadyTaken,
            })
    }

    async fn read_response(&self) -> Result<Response, RequestError<Q::Error>> {
        let mut stream = self.take_read_stream().await?;
        let mut message = Message::unresolved_response();
        stream.read_message_header(&mut message).await?;

        let agent = stream.connection().remote_agent().await?.expect(
            "remote agent should be present(should be guaranteed by h3 connection establishment)",
        );
        Ok(Response {
            message,
            agent,
            stream,
        })
    }

    async fn send_request_header(&self) -> Result<(), RequestError<Q::Error>> {
        self.ensure_stream_init().await?;
        let mut write_guard = self.write_stream.lock().await;
        let write_stream = write_guard.as_mut().ok_or(RequestError::Acquire {
            source: AcquireError::AlreadyTaken,
        })?;

        let result = {
            let mut message = self.message();
            write_stream.send_message_header(&mut message)
        }
        .await;
        if result.is_err() {
            self.mark_message_failed_unless_malformed();
        }
        result?;
        Ok(())
    }

    async fn write_body_chunk(
        &self,
        content: impl Buf + Send,
    ) -> Result<(), RequestError<Q::Error>> {
        self.ensure_stream_init().await?;
        let mut write_guard = self.write_stream.lock().await;
        let write_stream = write_guard.as_mut().ok_or(RequestError::Acquire {
            source: AcquireError::AlreadyTaken,
        })?;

        let result = {
            let mut message = self.message();
            write_stream.send_message_streaming_body(&mut message, content)
        }
        .await;
        if result.is_err() {
            self.mark_message_failed_unless_malformed();
        }
        result?;
        Ok(())
    }

    async fn flush_request(&self) -> Result<(), RequestError<Q::Error>> {
        self.send_buffered_request().await?;
        let mut write_guard = self.write_stream.lock().await;
        let write_stream = write_guard.as_mut().ok_or(RequestError::Acquire {
            source: AcquireError::AlreadyTaken,
        })?;
        write_stream.flush().await?;
        Ok(())
    }

    async fn close_request(&self) -> Result<(), RequestError<Q::Error>> {
        self.send_buffered_request().await?;
        let mut write_guard = self.write_stream.lock().await;
        let write_stream = write_guard.as_mut().ok_or(RequestError::Acquire {
            source: AcquireError::AlreadyTaken,
        })?;
        write_stream.close().await?;
        Ok(())
    }

    async fn cancel_request(&self, code: Code) -> Result<(), RequestError<Q::Error>> {
        self.ensure_stream_init().await?;
        let mut write_guard = self.write_stream.lock().await;
        let write_stream = write_guard.as_mut().ok_or(RequestError::Acquire {
            source: AcquireError::AlreadyTaken,
        })?;
        write_stream.cancel(code).await?;
        Ok(())
    }

    async fn send_buffered_request(&self) -> Result<(), RequestError<Q::Error>> {
        self.ensure_stream_init().await?;
        let mut write_guard = self.write_stream.lock().await;
        let write_stream = write_guard.as_mut().ok_or(RequestError::Acquire {
            source: AcquireError::AlreadyTaken,
        })?;

        loop {
            let stage = { self.message().stage() };
            match stage {
                crate::message::unify::MessageStage::Header => {
                    let result = {
                        let mut message = self.message();
                        write_stream.send_message_header(&mut message)
                    }
                    .await;
                    if result.is_err() {
                        self.mark_message_failed_unless_malformed();
                    }
                    result?;
                }
                crate::message::unify::MessageStage::Body => {
                    let is_chunked = { self.message().is_chunked() };

                    let result = {
                        let mut message = self.message();
                        write_stream.send_message_header(&mut message)
                    }
                    .await;
                    if result.is_err() {
                        self.mark_message_failed_unless_malformed();
                    }
                    result?;

                    if !is_chunked {
                        return Ok(());
                    }
                    let sent = {
                        let mut message = self.message();
                        write_stream.send_message_chunked_body_chunk(&mut message)
                    }
                    .await;
                    if sent.is_err() {
                        self.mark_message_failed_unless_malformed();
                    }
                    if !sent? {
                        continue;
                    }
                }
                crate::message::unify::MessageStage::Trailer => {
                    let has_trailers = { !self.message().trailers().is_empty() };
                    if !has_trailers {
                        return Ok(());
                    }
                    let result = {
                        let mut message = self.message();
                        write_stream.send_message_trailer_frame(&mut message)
                    }
                    .await;
                    if result.is_err() {
                        self.mark_message_failed_unless_malformed();
                    }
                    result?;
                }
                crate::message::unify::MessageStage::Complete => return Ok(()),
                crate::message::unify::MessageStage::Malformed => {
                    write_stream.cancel(Code::H3_REQUEST_CANCELLED).await?;
                    return Ok(());
                }
                crate::message::unify::MessageStage::Failed => {
                    return Err(MessageStreamError::MessageSendFailed.into());
                }
                crate::message::unify::MessageStage::Dropped => {
                    unreachable!("Message used after destroyed, this is a bug")
                }
            }
        }
    }

    async fn into_response(self) -> Result<Response, RequestError<Q::Error>> {
        self.close_request().await?;
        let mut read_stream = self.take_read_stream().await?;
        let mut response_message = Message::unresolved_response();
        read_stream
            .read_message_header(&mut response_message)
            .await?;

        let agent = read_stream.connection().remote_agent().await?.expect(
            "remote agent should be present(should be guaranteed by h3 connection establishment)",
        );
        Ok(Response {
            message: response_message,
            agent,
            stream: read_stream,
        })
    }
}

pub struct Request<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q, Q::Connection>>> {
    state: Arc<RequestState<Q, EP>>,
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q, Q::Connection>>> Request<Q, EP> {
    pub(crate) fn new(state: Arc<RequestState<Q, EP>>) -> Self {
        Self { state }
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q, Q::Connection>>> Clone for Request<Q, EP> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q, Q::Connection>>> Request<Q, EP>
where
    Q::Error: std::error::Error + Send + Sync + 'static,
{
    pub fn set_method(&self, method: Method) -> &Self {
        self.state.operate_message("set_method", |message| {
            message.header_mut()?.set_method(method);
            Ok(())
        });
        self
    }

    pub fn set_uri(&self, uri: Uri) -> &Self {
        let authority = uri.authority().cloned();
        self.state.operate_message("set_uri", |message| {
            message.header_mut()?;
            if let Some(auth) = authority
                && let Err(error) = self.state.set_authority(auth)
            {
                let report = Report::from_error(&error);
                tracing::warn!(
                    operation = "set_uri",
                    error = %report,
                    "operation malformed the request message, request stream will be cancelled"
                );
                message.set_malformed();
                return Ok(());
            }
            message.header_mut()?.set_uri(uri);
            Ok(())
        });
        self
    }

    pub fn set_header(&self, name: impl IntoHeaderName, value: HeaderValue) -> &Self {
        self.state.operate_message("set_header", |message| {
            message.header_mut()?.header_map_mut().insert(name, value);
            Ok(())
        });
        self
    }

    pub fn set_headers(&self, headers: HeaderMap) -> &Self {
        self.state.operate_message("set_headers", |message| {
            message.header_mut()?.header_map_mut().extend(headers);
            Ok(())
        });
        self
    }

    pub fn set_body(&self, content: impl Buf + Send) -> &Self {
        self.state.operate_message("set_body", |message| {
            message.set_body(content)?;
            Ok(())
        });
        self
    }

    pub fn set_trailer(&self, name: impl IntoHeaderName, value: HeaderValue) -> &Self {
        self.state.operate_message("set_trailer", |message| {
            message.trailers_mut()?.insert(name, value);
            Ok(())
        });
        self
    }

    pub fn set_trailers(&self, trailers: HeaderMap) -> &Self {
        self.state.operate_message("set_trailers", |message| {
            message.trailers_mut()?.extend(trailers);
            Ok(())
        });
        self
    }

    pub fn method(self, method: Method) -> Self {
        self.set_method(method);
        self
    }

    pub fn uri(self, uri: Uri) -> Self {
        self.set_uri(uri);
        self
    }

    pub fn header(self, name: impl IntoHeaderName, value: HeaderValue) -> Self {
        self.set_header(name, value);
        self
    }

    pub fn headers(self, headers: HeaderMap) -> Self {
        self.set_headers(headers);
        self
    }

    // impl IntoBody ( for &str String Vec<u8> etc)
    pub fn body(self, content: impl Buf + Send) -> Self {
        self.set_body(content);
        self
    }

    pub fn trailer(self, name: impl IntoHeaderName, value: HeaderValue) -> Self {
        self.set_trailer(name, value);
        self
    }

    pub fn trailers(self, trailers: HeaderMap) -> Self {
        self.set_trailers(trailers);
        self
    }

    pub async fn write(&self, content: impl Buf + Send) -> Result<&Self, RequestError<Q::Error>> {
        self.state.write_body_chunk(content).await?;
        Ok(self)
    }

    pub async fn flush(&self) -> Result<&Self, RequestError<Q::Error>> {
        self.state.flush_request().await?;
        Ok(self)
    }

    pub async fn close(&self) -> Result<(), RequestError<Q::Error>> {
        self.state.close_request().await
    }

    pub async fn cancel(&self, code: Code) -> Result<(), RequestError<Q::Error>> {
        self.state.cancel_request(code).await
    }

    pub async fn response(&self) -> Result<Response, RequestError<Q::Error>> {
        self.state.send_request_header().await?;
        self.state.read_response().await
    }

    pub async fn into_response(self) -> Result<Response, RequestError<Q::Error>> {
        match Arc::try_unwrap(self.state) {
            Ok(state) => state.into_response().await,
            Err(state) => {
                let request = Request { state };
                request.response().await
            }
        }
    }
}

// Two concrete IntoFuture impls because the generic `'ep` lifetime on EP cannot be
// constrained by the impl header (Rust requires every lifetime parameter to appear in
// the concrete type or a bound on a type in the impl header). Rather than forcing callers
// to annotate lifetimes, we cover both concrete endpoint types that h3x produces:
//
//   - `&'a H3Endpoint<Q, Q::Connection>` — borrowed reference (used by H3Endpoint::new_request)
//   - `Arc<H3Endpoint<Q, Q::Connection>>` — shared ownership (used by H3Endpoint::get/post/… & new_request_owned)
impl<'a, Q> IntoFuture for Request<Q, &'a H3Endpoint<Q, Q::Connection>>
where
    Q: quic::Connect + Sync + 'static,
    Q::Connection: Send + 'static,
    Q::Error: std::error::Error + Send + Sync + 'static,
    <Q::Connection as quic::ManageStream>::StreamReader: Send,
    <Q::Connection as quic::ManageStream>::StreamWriter: Send,
{
    type Output = Result<Response, RequestError<Q::Error>>;
    type IntoFuture = BoxFuture<'a, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.into_response())
    }
}

impl<Q> IntoFuture for Request<Q, Arc<H3Endpoint<Q, Q::Connection>>>
where
    Q: quic::Connect + Sync + 'static,
    Q::Connection: Send + 'static,
    Q::Error: std::error::Error + Send + Sync + 'static,
    <Q::Connection as quic::ManageStream>::StreamReader: Send,
    <Q::Connection as quic::ManageStream>::StreamWriter: Send,
{
    type Output = Result<Response, RequestError<Q::Error>>;
    type IntoFuture = BoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.into_response())
    }
}

pub struct Response {
    message: Message,
    stream: ReadStream,
    agent: Arc<dyn agent::RemoteAgent>,
}

impl Response {
    pub async fn next_response(&mut self) -> Result<&mut Self, MessageStreamError> {
        self.stream.read_message_header(&mut self.message).await?;
        Ok(self)
    }

    pub fn status(&self) -> http::StatusCode {
        self.message.header().status()
    }

    pub fn headers(&mut self) -> &HeaderMap {
        self.message.header().header_map()
    }

    pub fn header(&mut self, name: impl AsHeaderName) -> Option<&HeaderValue> {
        self.headers().get(name)
    }

    pub async fn read(&mut self) -> Option<Result<Bytes, MessageStreamError>> {
        self.stream.read_message(&mut self.message).await
    }

    pub async fn read_all(&mut self) -> Result<impl Buf, MessageStreamError> {
        self.stream.read_message_full_body(&mut self.message).await
    }

    pub async fn read_to_bytes(&mut self) -> Result<Bytes, MessageStreamError> {
        self.stream
            .read_message_body_to_bytes(&mut self.message)
            .await
    }

    pub async fn read_to_string(&mut self) -> Result<String, ReadToStringError> {
        self.stream
            .read_message_body_to_string(&mut self.message)
            .await
    }

    pub async fn as_stream(&mut self) -> impl Stream<Item = Result<Bytes, MessageStreamError>> {
        futures::stream::unfold(self, async |this| {
            this.read().await.map(|item| (item, this))
        })
        .fuse()
    }

    pub async fn into_stream(self) -> impl Stream<Item = Result<Bytes, MessageStreamError>> {
        futures::stream::unfold(self, async |mut this| {
            this.read().await.map(|item| (item, this))
        })
        .fuse()
    }

    pub async fn trailers(&mut self) -> Result<&HeaderMap, MessageStreamError> {
        self.stream.read_message_trailer(&mut self.message).await
    }

    pub async fn stop(&mut self, code: Code) -> Result<(), MessageStreamError> {
        self.stream.stop(code).await
    }

    /// Low level access to the underlying read stream
    pub fn read_stream(&mut self) -> &mut ReadStream {
        &mut self.stream
    }

    pub fn agent(&self) -> &Arc<dyn agent::RemoteAgent> {
        &self.agent
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::Ordering};

    use http::{Uri, uri::Authority};

    use super::*;
    use crate::connection::tests::MockConnection;

    struct TestConnect;

    impl quic::Connect for TestConnect {
        type Connection = MockConnection;
        type Error = quic::ConnectionError;

        async fn connect(&self, _server: &Authority) -> Result<Arc<MockConnection>, Self::Error> {
            Ok(Arc::new(MockConnection::new()))
        }
    }

    type TestEndpoint = H3Endpoint<TestConnect, MockConnection>;
    type TestRequest = Request<TestConnect, Arc<TestEndpoint>>;
    type TestRequestState = Arc<RequestState<TestConnect, Arc<TestEndpoint>>>;

    fn test_request() -> (TestRequest, TestRequestState) {
        let endpoint = Arc::new(H3Endpoint::new(TestConnect));
        let state = Arc::new(RequestState::new(endpoint, Message::unresolved_request()));
        state
            .set_authority(Authority::from_static("example.com"))
            .expect("set authority");
        (Request::new(Arc::clone(&state)), state)
    }

    #[test]
    fn clone_shares_request_state() {
        let (request, state) = test_request();
        let clone = request.clone();

        clone.set_method(Method::POST);

        assert_eq!(request.state.message().header().method(), Method::POST);
        assert!(Arc::ptr_eq(&request.state, &clone.state));
        assert!(Arc::ptr_eq(&request.state, &state));
    }

    #[test]
    fn set_body_keeps_shared_message_in_header_stage_before_io() {
        let (request, state) = test_request();

        request.set_body(&b"abc"[..]);

        assert_eq!(
            state.message().stage(),
            crate::message::unify::MessageStage::Header
        );
    }

    #[test]
    fn set_header_after_body_before_io_keeps_message_valid() {
        let (request, state) = test_request();

        request
            .set_body(&b"abc"[..])
            .set_header("x-after-body", HeaderValue::from_static("1"));

        let message = state.message();
        assert!(!message.is_malformed());
        assert_eq!(
            message.header().header_map().get("x-after-body"),
            Some(&HeaderValue::from_static("1"))
        );
    }

    #[tokio::test]
    async fn test_set_authority_after_init_frozen() {
        let (_request, state) = test_request();
        state.init_done.store(true, Ordering::Release);

        let result = state.set_authority(Authority::from_static("new.example.com"));
        assert!(matches!(result, Err(AuthorityFrozen::InitComplete)));
    }

    #[tokio::test]
    async fn test_uri_authority_sync() {
        let (request, state) = test_request();
        let uri: Uri = "https://sync.example.com/path".parse().expect("valid URI");

        request.set_uri(uri);

        let stored = state.authority.lock().expect("lock poisoned").clone();
        assert_eq!(
            stored.as_ref().map(|a| a.as_str()),
            Some("sync.example.com")
        );
    }

    #[tokio::test]
    async fn test_uri_poisons_on_frozen() {
        let (request, state) = test_request();
        state.init_done.store(true, Ordering::Release);

        let uri: Uri = "https://different.example.com/path"
            .parse()
            .expect("valid URI");
        request.set_uri(uri);

        assert!(state.message().is_malformed());
    }

    #[test]
    fn test_request_error_clone() {
        let err = RequestError::<quic::ConnectionError>::HeaderTooLarge;
        let cloned = err.clone();
        match (&err, &cloned) {
            (RequestError::HeaderTooLarge, RequestError::HeaderTooLarge) => {}
            _ => panic!("clone mismatch: err={err:?} cloned={cloned:?}"),
        }
    }
}
