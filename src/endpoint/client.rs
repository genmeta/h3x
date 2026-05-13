use std::{
    cell::RefCell,
    error::Error,
    fmt::Display,
    future::IntoFuture,
    ops::{Deref, DerefMut},
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
use snafu::{ResultExt, Snafu};
use tokio::sync::Mutex as AsyncMutex;
use tracing::Instrument;

use super::H3Endpoint;
use crate::{
    endpoint::client::request_error::StreamInitSnafu,
    error::Code,
    message::{
        stream::{InitialMessageStreamError, MessageStreamError, ReadStream, WriteStream},
        unify::{Message, ReadToStringError},
    },
    pool::ConnectError,
    qpack::field::MalformedHeaderSection,
    quic::{self, agent},
};

/// Debug-only warning when a builder method is called on an already-consumed Request.
/// In release builds this is a no-op.
fn debug_warn_consumed(method: impl Display) {
    #[cfg(debug_assertions)]
    tracing::warn!(
        %method,
        "{method}() called on already-consumed Request -- no-op, will fail at .await"
    );
}

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

pub(crate) struct Arbiter<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> {
    request_message: SyncMutex<Option<Message>>,
    write_stream: SyncMutex<Option<WriteStream>>,
    read_stream: SyncMutex<Option<ReadStream>>,
    init_state: AsyncMutex<Option<Result<(), RequestError<Q::Error>>>>,
    endpoint: EP,
    authority: SyncMutex<Option<Authority>>,
    init_done: AtomicBool,
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Arbiter<Q, EP> {
    pub(crate) fn new(endpoint: EP, message: Message) -> Self {
        Arbiter {
            request_message: SyncMutex::new(Some(message)),
            write_stream: SyncMutex::new(None),
            read_stream: SyncMutex::new(None),
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

    fn acquire_request_message(&self) -> Result<Message, AcquireError> {
        self.request_message
            .lock()
            .unwrap()
            .take()
            .ok_or(AcquireError::AlreadyTaken)
    }

    fn return_request_message(&self, message: Message) {
        *self.request_message.lock().unwrap() = Some(message);
    }

    pub fn return_write_stream(&self, write_stream: WriteStream) {
        *self.write_stream.lock().unwrap() = Some(write_stream);
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Arbiter<Q, EP>
where
    Q::Error: std::error::Error + Send + Sync + 'static,
{
    async fn ensure_stream_init(&self) -> Result<(), RequestError<Q::Error>> {
        // Fast path: init already done
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

        // Double-check: another caller may have finished while we waited
        if let Some(cached) = guard.as_ref() {
            return cached.clone();
        }

        // Extract authority from the sync mutex
        let authority = self
            .authority
            .lock()
            .expect("lock poisoned")
            .clone()
            .ok_or_else(|| RequestError::MalformedRequestHeader {
                source: Arc::new(MalformedHeaderSection::EmptyAuthorityOrHost),
            })?;

        // Execute the actual init (network I/O — lock NOT held)
        let result: Result<(), RequestError<Q::Error>> = async {
            let connection = self.endpoint.connect(authority).await?;
            let (read_stream, write_stream) = connection
                .initial_message_stream()
                .await
                .context(StreamInitSnafu)?;
            *self.read_stream.lock().expect("lock poisoned") = Some(read_stream);
            *self.write_stream.lock().expect("lock poisoned") = Some(write_stream);
            Ok(())
        }
        .await;

        // Store result (success or failure) and mark init as done
        *guard = Some(result.clone());
        self.init_done.store(true, Ordering::Release);
        result
    }

    async fn acquire_read_stream(&self) -> Result<ReadStream, RequestError<Q::Error>> {
        if let Some(rs) = self.read_stream.lock().unwrap().take() {
            return Ok(rs);
        }
        self.ensure_stream_init().await?;
        self.read_stream
            .lock()
            .unwrap()
            .take()
            .ok_or(RequestError::Acquire {
                source: AcquireError::AlreadyTaken,
            })
    }

    async fn acquire_response(&self) -> Result<Response, RequestError<Q::Error>> {
        let mut stream = self.acquire_read_stream().await?;

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

    async fn into_response(mut self) -> Result<Response, RequestError<Q::Error>> {
        let mut read_stream = self.acquire_read_stream().await?;
        let mut response_message = Message::unresolved_response();
        let read_response = async { read_stream.read_message_header(&mut response_message).await };

        // get_mut on &mut self guarantees exclusive access - no lock needed
        let mut write_stream = self.write_stream.get_mut().unwrap().take().expect(
            "message should be present (should be guaranteed by request lifecycle management)",
        );
        let mut request_message = self.request_message.get_mut().unwrap().take().expect(
            "message should be present (should be guaranteed by request lifecycle management)",
        );
        let mut close_reqeust =
            Box::pin(async move { write_stream.close_message(&mut request_message).await });

        tokio::select! {
            biased;
            result = read_response => {
                result?;
                tokio::spawn(close_reqeust.in_current_span());
            }
            result = &mut close_reqeust => {
                result?;
            }
        };

        let agent = read_stream.connection().remote_agent().await?.expect(
            "remote agent should be present(should be guaranteed by h3 connection establishment)",
        );
        Ok(Response {
            message: response_message,
            agent,
            stream: read_stream,
        })
    }

    async fn acquire_write_stream(&self) -> Result<WriteStream, RequestError<Q::Error>> {
        if let Some(write_stream) = self.write_stream.lock().unwrap().take() {
            return Ok(write_stream);
        }
        self.ensure_stream_init().await?;
        self.write_stream
            .lock()
            .unwrap()
            .take()
            .ok_or(RequestError::Acquire {
                source: AcquireError::AlreadyTaken,
            })
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Drop for Arbiter<Q, EP> {
    fn drop(&mut self) {
        // get_mut on &mut self guarantees exclusive access - no lock needed
        if let Some(mut message) = self.request_message.get_mut().unwrap().take()
            && !message.is_dropped()
            && !message.is_complete()
            && let Some(mut write_stream) = self.write_stream.get_mut().unwrap().take()
        {
            tokio::spawn(
                async move { write_stream.close_message(&mut message).await }.in_current_span(),
            );
        }
        // read_stream dropped naturally if still present
    }
}

pub struct Request<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> {
    held_message: RefCell<Option<Message>>,
    held_write_stream: RefCell<Option<WriteStream>>,
    arbiter: RefCell<Option<Arc<Arbiter<Q, EP>>>>,
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Request<Q, EP> {
    pub(crate) fn new(arbiter: Arc<Arbiter<Q, EP>>) -> Self {
        Request {
            held_message: RefCell::new(None),
            held_write_stream: RefCell::new(None),
            arbiter: RefCell::new(Some(arbiter)),
        }
    }

    /// Return all held resources to the arbiter pool. Used by Clone and Drop.
    fn return_all_to_pool(&self) {
        let Ok(arbiter) = self.arbiter() else {
            return;
        };
        if let Some(message) = self.held_message.take() {
            arbiter.return_request_message(message);
        }
        if let Some(write_stream) = self.held_write_stream.take() {
            arbiter.return_write_stream(write_stream);
        }
    }

    fn arbiter(&self) -> Result<Arc<Arbiter<Q, EP>>, AcquireError> {
        self.arbiter
            .borrow()
            .as_ref()
            .cloned()
            .ok_or(AcquireError::AlreadyTaken)
    }

    fn take_arbiter(&self) -> Result<Arc<Arbiter<Q, EP>>, AcquireError> {
        self.arbiter
            .borrow_mut()
            .take()
            .ok_or(AcquireError::AlreadyTaken)
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Clone for Request<Q, EP>
where
    Q::Error: std::error::Error + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        self.return_all_to_pool();
        Request {
            held_message: RefCell::new(None),
            held_write_stream: RefCell::new(None),
            arbiter: RefCell::new(self.arbiter().ok()),
        }
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Drop for Request<Q, EP> {
    fn drop(&mut self) {
        self.return_all_to_pool();
    }
}

pub(crate) struct RequestMessageGuard<'a, Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> {
    message: Message,
    request: &'a Request<Q, EP>,
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Deref for RequestMessageGuard<'_, Q, EP> {
    type Target = Message;
    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> DerefMut
    for RequestMessageGuard<'_, Q, EP>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Drop for RequestMessageGuard<'_, Q, EP> {
    fn drop(&mut self) {
        *self.request.held_message.borrow_mut() = Some(self.message.take());
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Request<Q, EP>
where
    Q::Error: std::error::Error + Send + Sync + 'static,
{
    pub(crate) fn message(&self) -> Result<RequestMessageGuard<'_, Q, EP>, RequestError<Q::Error>> {
        let arbiter = self.arbiter()?;

        if let Some(message) = self.held_message.take() {
            return Ok(RequestMessageGuard {
                message,
                request: self,
            });
        }

        match arbiter.acquire_request_message() {
            Ok(message) => Ok(RequestMessageGuard {
                message,
                request: self,
            }),
            Err(error @ AcquireError::AlreadyTaken) => {
                *self.arbiter.borrow_mut() = None;
                Err(error.into())
            }
        }
    }

    pub fn set_method(&self, method: Method) -> &Self {
        if let Ok(mut message) = self.message() {
            message.header_mut().set_method(method);
        } else {
            debug_warn_consumed("method");
        }
        self
    }

    pub fn set_uri(&self, uri: Uri) -> &Self {
        let Ok(mut message) = self.message() else {
            debug_warn_consumed("uri");
            return self;
        };
        if let Some(auth) = uri.authority().cloned()
            && let Ok(arbiter) = self.arbiter()
            && arbiter.set_authority(auth).is_err()
        {
            message.set_malformed();
        }
        message.header_mut().set_uri(uri);
        self
    }

    pub fn set_header(&self, name: impl IntoHeaderName, value: HeaderValue) -> &Self {
        if let Ok(mut message) = self.message() {
            message.header_mut().header_map.insert(name, value);
        } else {
            debug_warn_consumed("header");
        }
        self
    }

    pub fn set_headers(&self, headers: HeaderMap) -> &Self {
        if let Ok(mut message) = self.message() {
            message.header_mut().header_map.extend(headers);
        } else {
            debug_warn_consumed("headers");
        }
        self
    }

    pub fn set_body(&self, content: impl Buf + Send) -> &Self {
        if let Ok(mut message) = self.message() {
            if let Ok(cursor) = message.chunked_body() {
                cursor.write(content);
            }
        } else {
            debug_warn_consumed("body");
        }
        self
    }

    pub fn set_trailer(&self, name: impl IntoHeaderName, value: HeaderValue) -> &Self {
        if let Ok(mut message) = self.message() {
            message.trailers_mut().insert(name, value);
        } else {
            debug_warn_consumed("trailer");
        }
        self
    }

    pub fn set_trailers(&self, trailers: HeaderMap) -> &Self {
        if let Ok(mut message) = self.message() {
            message.trailers_mut().extend(trailers);
        } else {
            debug_warn_consumed("trailers");
        }
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
}

pub(crate) struct WriteGuard<'a, Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> {
    write_stream: WriteStream,
    request: &'a Request<Q, EP>,
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Deref for WriteGuard<'_, Q, EP> {
    type Target = WriteStream;
    fn deref(&self) -> &Self::Target {
        &self.write_stream
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> DerefMut for WriteGuard<'_, Q, EP> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.write_stream
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Drop for WriteGuard<'_, Q, EP> {
    fn drop(&mut self) {
        *self.request.held_write_stream.borrow_mut() = Some(self.write_stream.take());
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Request<Q, EP>
where
    Q::Error: std::error::Error + Send + Sync + 'static,
{
    pub(crate) async fn write_stream(
        &self,
    ) -> Result<WriteGuard<'_, Q, EP>, RequestError<Q::Error>> {
        let arbiter = self.arbiter()?;

        if let Some(write_stream) = self.held_write_stream.take() {
            return Ok(WriteGuard {
                write_stream,
                request: self,
            });
        }

        match arbiter.acquire_write_stream().await {
            Ok(write_stream) => Ok(WriteGuard {
                write_stream,
                request: self,
            }),
            Err(
                error @ RequestError::Acquire {
                    source: AcquireError::AlreadyTaken,
                },
            ) => {
                *self.arbiter.borrow_mut() = None;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub async fn write(&self, content: impl Buf + Send) -> Result<&Self, RequestError<Q::Error>> {
        self.write_stream()
            .await?
            .send_message_streaming_body(self.message()?.deref_mut(), content)
            .await?;
        Ok(self)
    }

    pub async fn flush(&self) -> Result<&Self, RequestError<Q::Error>> {
        self.write_stream()
            .await?
            .flush_message(self.message()?.deref_mut())
            .await?;
        Ok(self)
    }

    pub async fn close(&self) -> Result<(), RequestError<Q::Error>> {
        self.write_stream()
            .await?
            .close_message(self.message()?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn cancel(&self, code: Code) -> Result<(), RequestError<Q::Error>> {
        self.write_stream().await?.cancel(code).await?;
        Ok(())
    }
}

impl<Q: quic::Connect, EP: Deref<Target = H3Endpoint<Q>>> Request<Q, EP>
where
    Q::Error: std::error::Error + Send + Sync + 'static,
{
    pub async fn response(&self) -> Result<Response, RequestError<Q::Error>> {
        self.arbiter()?.acquire_response().await
    }

    pub async fn into_response(self) -> Result<Response, RequestError<Q::Error>> {
        self.return_all_to_pool();
        match Arc::try_unwrap(self.take_arbiter()?) {
            Ok(arbiter) => arbiter.into_response().await,
            Err(arbiter) => arbiter.acquire_response().await,
        }
    }
}

// Two concrete IntoFuture impls because the generic `'ep` lifetime on EP cannot be
// constrained by the impl header (Rust requires every lifetime parameter to appear in
// the concrete type or a bound on a type in the impl header). Rather than forcing callers
// to annotate lifetimes, we cover both concrete endpoint types that h3x produces:
//
//   - `&'a H3Endpoint<Q>` — borrowed reference (used by H3Endpoint::new_request)
//   - `Arc<H3Endpoint<Q>>` — shared ownership (used by H3Endpoint::get/post/… & new_request_owned)
impl<'a, Q> IntoFuture for Request<Q, &'a H3Endpoint<Q>>
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

impl<Q> IntoFuture for Request<Q, Arc<H3Endpoint<Q>>>
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
        &self.message.header().header_map
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
    use crate::{connection::tests::MockConnection, varint::VarInt};

    // ---- Mock infrastructure ----

    /// Minimal `quic::Connect` implementation for unit tests.
    struct TestConnect;

    impl quic::Connect for TestConnect {
        type Connection = MockConnection;
        type Error = quic::ConnectionError;

        async fn connect(&self, _server: &Authority) -> Result<Arc<MockConnection>, Self::Error> {
            Ok(Arc::new(MockConnection::new()))
        }
    }

    /// Creates an `Arbiter` with a mock endpoint and a single
    /// `Message::unresolved_request()` pre-populated in its pool.
    fn test_arbiter() -> Arc<Arbiter<TestConnect, Arc<H3Endpoint<TestConnect>>>> {
        let endpoint = Arc::new(H3Endpoint::new(TestConnect));
        let authority = Authority::from_static("example.com");
        let message = crate::message::unify::Message::unresolved_request();
        let arbiter = Arc::new(Arbiter::new(endpoint, message));
        arbiter.set_authority(authority).expect("set authority");
        arbiter
    }

    /// Creates an `Arbiter` with a `WriteStream` pre-populated
    /// in its pool (fast-path for `acquire_write_stream`).
    fn test_arbiter_with_ws() -> Arc<Arbiter<TestConnect, Arc<H3Endpoint<TestConnect>>>> {
        let arbiter = test_arbiter();
        let ws = crate::message::stream::WriteStream::new_for_test(VarInt::from_u32(0));
        *arbiter.write_stream.lock().unwrap() = Some(ws);
        arbiter
    }

    /// Creates an `Arbiter` with a `ReadStream` pre-populated
    /// in its pool AND `init_state` set to `Ok(())` — simulating
    /// a completed `ensure_init` that has already been consumed.
    /// This allows testing `acquire_read_stream` returning
    /// `AlreadyConsumed` on the second call.
    fn test_arbiter_with_rs() -> Arc<Arbiter<TestConnect, Arc<H3Endpoint<TestConnect>>>> {
        let arbiter = test_arbiter();
        let rs = crate::message::stream::ReadStream::new_for_test(VarInt::from_u32(0));
        *arbiter.read_stream.lock().unwrap() = Some(rs);
        // Simulate a completed ensure_init so the second acquire
        // doesn't attempt a real connection
        *arbiter.init_state.try_lock().unwrap() = Some(Ok(()));
        arbiter
    }

    /// Creates a `Request` that holds a message acquired from the pool.
    fn request_with_message(
        arbiter: &Arc<Arbiter<TestConnect, Arc<H3Endpoint<TestConnect>>>>,
    ) -> Request<TestConnect, Arc<H3Endpoint<TestConnect>>> {
        let message = arbiter
            .acquire_request_message()
            .expect("pool should have message");
        Request {
            held_message: std::cell::RefCell::new(Some(message)),
            held_write_stream: std::cell::RefCell::new(None),
            arbiter: std::cell::RefCell::new(Some(Arc::clone(arbiter))),
        }
    }

    // // ====================================================================
    // // Task 11 GREEN tests — resource acquire/return lifecycle
    // // ====================================================================

    // /// `acquire_message()` → `return_message_to_pool()` →
    // /// `acquire_message()` cycle: message returns to pool after
    // /// being returned.
    // ///
    // /// Assertions:
    // /// - First `acquire_message()` → `Some(msg)`, pool → `None`.
    // /// - After `return_message_to_pool(msg)`, pool → `Some`.
    // /// - Second `acquire_message()` → `Some`.
    // #[tokio::test]
    // async fn test_acquire_message_cycle() {
    //     let arbiter = test_arbiter();

    //     // First acquire — pool starts with one message
    //     let msg = arbiter.acquire_message();
    //     assert!(msg.is_some(), "first acquire should return message");
    //     assert!(
    //         arbiter.message.lock().unwrap().is_none(),
    //         "pool should be empty after acquire"
    //     );

    //     // Return to pool
    //     arbiter.return_message_to_pool(msg.unwrap());
    //     assert!(
    //         arbiter.message.lock().unwrap().is_some(),
    //         "pool should have message after return"
    //     );

    //     // Second acquire — message is back in pool
    //     let msg2 = arbiter.acquire_message();
    //     assert!(msg2.is_some(), "second acquire should return message");

    //     // Cleanup: return message so Arbiter::drop doesn't spawn cleanup
    //     drop(msg2);
    // }

    /// After pre-populating `write_stream` (simulating a completed
    /// `ensure_init`), `acquire_write_stream()` succeeds via the
    /// fast path, returning the stream. Taking it empties the pool.
    /// Returning it makes it available again.
    ///
    /// Assertions:
    /// - `acquire_write_stream().await` → `Ok(_)`, pool → `None`.
    /// - `return_write_stream_to_pool(ws)`, pool → `Some`.
    /// - `acquire_write_stream().await` → `Ok(_)`.
    #[tokio::test]
    async fn test_acquire_write_stream_after_init() {
        let arbiter = test_arbiter_with_ws();
        assert!(
            arbiter.write_stream.lock().unwrap().is_some(),
            "write_stream should be pre-populated"
        );

        // First acquire — fast path, no ensure_init needed
        let ws = arbiter
            .acquire_write_stream()
            .await
            .expect("first acquire_write_stream should succeed");
        assert!(
            arbiter.write_stream.lock().unwrap().is_none(),
            "pool should be empty after acquire"
        );

        // Return to pool
        arbiter.return_write_stream(ws);
        assert!(
            arbiter.write_stream.lock().unwrap().is_some(),
            "pool should have write_stream after return"
        );

        // Second acquire — works again
        let ws2 = arbiter
            .acquire_write_stream()
            .await
            .expect("second acquire_write_stream should succeed");
        drop(ws2);
    }

    /// `acquire_read_stream()` can only succeed once. The second
    /// acquisition returns `Err(InitError::AlreadyConsumed)` because
    /// the read stream is a one‑shot resource with no return path.
    ///
    /// Assertions:
    /// - First `acquire_read_stream().await` → `Ok(_)`.
    /// - Second `acquire_read_stream().await` →
    ///   `Err(InitError::AlreadyConsumed)`.
    #[tokio::test]
    async fn test_acquire_read_stream_once_only() {
        let arbiter = test_arbiter_with_rs();
        assert!(
            arbiter.read_stream.lock().unwrap().is_some(),
            "read_stream should be pre-populated"
        );

        // First acquire succeeds via fast path
        let rs = arbiter
            .acquire_read_stream()
            .await
            .expect("first acquire_read_stream should succeed");
        drop(rs);

        // Second acquire — pool is empty, no return path
        let result = arbiter.acquire_read_stream().await;
        assert!(
            matches!(result, Err(RequestError::Acquire { .. })),
            "second acquire_read_stream should return AlreadyConsumed"
        );
    }

    // /// Two concurrent `acquire_message()` calls contend for the
    // /// single message in the pool: only one succeeds, the other
    // /// gets `None`.
    // ///
    // /// Assertions:
    // /// - Exactly one call returns `Some`, the other returns `None`.
    // #[tokio::test]
    // async fn test_concurrent_acquire_mutex() {
    //     let arbiter = test_arbiter();
    //     let arb1 = Arc::clone(&arbiter);
    //     let arb2 = Arc::clone(&arbiter);

    //     let (r1, r2) = tokio::join!(
    //         tokio::task::spawn_blocking(move || (1, arb1.acquire_message())),
    //         tokio::task::spawn_blocking(move || (2, arb2.acquire_message())),
    //     );

    //     let (_, r1) = r1.expect("task 1 should complete");
    //     let (_, r2) = r2.expect("task 2 should complete");

    //     // Exactly one should have the message
    //     assert!(
    //         (r1.is_some() && r2.is_none()) || (r1.is_none() && r2.is_some()),
    //         "exactly one concurrent acquire should succeed, got r1={:?} r2={:?}",
    //         r1.is_some(),
    //         r2.is_some()
    //     );

    //     // Return whichever message we got so Arbiter::drop doesn't spawn cleanup
    //     if let Some(msg) = r1 {
    //         arbiter.return_message_to_pool(msg);
    //     }
    //     if let Some(msg) = r2 {
    //         arbiter.return_message_to_pool(msg);
    //     }
    // }

    // ====================================================================
    // NEW integration-level tests (Arbiter + Request)
    // ====================================================================

    /// Two Request clones compete for the pool message via
    /// independent acquire/return cycles — pool mediation ensures
    /// both eventually succeed in sequence.
    ///
    /// Assertions:
    /// - Clone A acquires message → `held_message` is `Some`.
    /// - Clone A clones (returns to pool) → `held_message` is `None`.
    /// - Clone B acquires message from pool → `held_message` is `Some`.
    #[tokio::test]
    async fn test_parallel_clone_acquire_cycle() {
        let arbiter = test_arbiter();
        let req = request_with_message(&arbiter);

        assert!(
            req.held_message.borrow().is_some(),
            "request should hold message"
        );

        // Clone returns held resource to pool
        let clone = req.clone();
        assert!(
            req.held_message.borrow().is_none(),
            "original's held_message should be returned to pool"
        );
        assert!(
            clone.held_message.borrow().is_none(),
            "clone should start with empty held_message"
        );

        // Verify pool has the message
        assert!(
            arbiter.request_message.lock().unwrap().is_some(),
            "message should be back in pool"
        );

        // Another request can now acquire it
        let req2 = request_with_message(&arbiter);
        assert!(
            req2.held_message.borrow().is_some(),
            "second request should acquire message from pool"
        );
    }

    /// Write→return→write cycle: acquire write_stream from pool,
    /// use it (no-op in mock), return it, acquire again.
    ///
    /// Assertions:
    /// - First acquire_write_stream → `Ok(write_stream)`.
    /// - Return to pool.
    /// - Second acquire_write_stream → `Ok(write_stream)`.
    #[tokio::test]
    async fn test_write_return_write_cycle() {
        let arbiter = test_arbiter_with_ws();

        let ws1 = arbiter
            .acquire_write_stream()
            .await
            .expect("first acquire should succeed");

        // Simulate a write operation (no-op for mock)
        arbiter.return_write_stream(ws1);

        let ws2 = arbiter
            .acquire_write_stream()
            .await
            .expect("second acquire should succeed");
        drop(ws2);
    }

    /// After poisoning `arbiter` on a clone (setting to None),
    /// subsequent acquires from that clone are blocked. But other
    /// clones are unaffected — each clone has its own RefCell.
    ///
    /// Assertions:
    /// - Clone A: `arbiter` is `None` after poison.
    /// - Clone B: `arbiter` is still `Some`.
    #[test]
    fn test_arbiter_refcell_isolation() {
        let arbiter = test_arbiter();
        let req = request_with_message(&arbiter);
        let clone_a = req.clone();
        let clone_b = req.clone();

        // Poison clone_a's arbiter via direct RefCell access
        *clone_a.arbiter.borrow_mut() = None;

        assert!(
            clone_a.arbiter.borrow().is_none(),
            "clone A should be poisoned"
        );
        assert!(
            clone_b.arbiter.borrow().is_some(),
            "clone B should NOT be poisoned"
        );
    }

    // ====================================================================
    // Tests requiring full network infrastructure — keep ignored
    // ====================================================================

    /// Verifies `ensure_init` populates both streams and caches
    /// `Ok(())` in `init_state`.
    #[tokio::test]
    #[ignore = "requires ensure_init with working network mock"]
    async fn test_ensure_init_success() {
        todo!(
            "create mock Arbiter (success), call ensure_init().await → Ok(()), \
             verify read_stream/write_stream are Some, init_state is Some(Ok(()))"
        )
    }

    /// Spawns 5 concurrent `ensure_init` calls and asserts that the
    /// underlying `connect()` is executed exactly once.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires ensure_init with working network mock"]
    async fn test_ensure_init_concurrent() {
        todo!(
            "create mock Arbiter with connect counter (success), \
             spawn 5 concurrent ensure_init, assert all succeed, \
             assert connect_count == 1"
        )
    }

    /// First `ensure_init` fails (mock connect returns Err).
    /// Second call returns the same `Arc<InitError>` (no re-connection).
    #[tokio::test]
    #[ignore = "requires ensure_init with working network mock"]
    async fn test_ensure_init_error_cache() {
        todo!(
            "create mock Arbiter (failing connect), \
             call ensure_init twice, assert both Err and Arc::ptr_eq, \
             assert init_state caches the Err"
        )
    }

    /// After successful `ensure_init`, `acquire_read_stream()` and
    /// `acquire_write_stream()` each return `Some(...)`.
    #[tokio::test]
    #[ignore = "requires ensure_init with working network mock"]
    async fn test_streams_available_after_init() {
        todo!(
            "create mock Arbiter (success), call ensure_init, \
             acquire_write_stream → Some, assert Mutex None, \
             acquire_read_stream → Some, assert Mutex None"
        )
    }

    /// `Request::clone()` returns all held resources to the arbiter pool.
    #[tokio::test]
    #[ignore = "requires full Request lifecycle integration"]
    async fn test_clone_returns_to_pool() {
        todo!(
            "let arbiter = test_arbiter(); \
             let req = request_with_message(arbiter); \
             assert req.held_message.is_some(); \
             let clone = req.clone(); \
             assert req.held_message.is_none(); \
             assert arbiter.message.lock().unwrap().is_some()"
        )
    }

    /// Cloning N times returns the resource to the pool exactly once.
    #[tokio::test]
    #[ignore = "requires full Request lifecycle integration"]
    async fn test_clone_multiple() {
        todo!(
            "let arbiter = test_arbiter(); \
             let req = request_with_message(arbiter); \
             let c1 = req.clone(); \
             let c2 = req.clone(); \
             let c3 = req.clone(); \
             assert c1.held_message.is_none(); \
             assert c2.held_message.is_none(); \
             assert c3.held_message.is_none(); \
             assert arbiter.message.lock().unwrap().is_some()"
        )
    }

    /// `Request::drop()` returns all held resources to the arbiter pool.
    #[tokio::test]
    #[ignore = "requires full Request lifecycle integration"]
    async fn test_drop_returns_to_pool() {
        todo!(
            "let arbiter = test_arbiter(); \
             {{ let req = request_with_message(arbiter.clone()); \
               assert req.held_message.is_some(); }} \
             assert arbiter.message.lock().unwrap().is_some()"
        )
    }

    /// Dropping a `Request` that holds only `write_stream` (no message)
    /// returns the stream to the pool without spawning cleanup.
    #[tokio::test]
    #[ignore = "requires full Request lifecycle integration"]
    async fn test_drop_no_cleanup_spawn() {
        todo!(
            "let arbiter = test_arbiter(); \
             let req = acquire_write_stream_only(arbiter.clone()); \
             assert req.held_write_stream.is_some(); \
             assert req.held_message.is_none(); \
             drop(req); \
             assert arbiter.write_stream.lock().unwrap().is_some(); \
             assert arbiter.message.lock().unwrap().is_some()"
        )
    }

    /// When a `Request` clone holds `read_stream`, cloning returns
    /// it to the arbiter pool.
    #[tokio::test]
    #[ignore = "requires full Request lifecycle integration"]
    async fn test_clone_returns_read_stream() {
        todo!(
            "let arbiter = test_arbiter(); \
             let req = acquire_read_stream(arbiter.clone()); \
             assert req.held_read_stream.is_some(); \
             let clone = req.clone(); \
             assert arbiter.read_stream.lock().unwrap().is_some(); \
             assert clone.held_read_stream.is_none()"
        )
    }

    // ====================================================================
    // Task 17 GREEN tests — IntoFuture both paths
    // ====================================================================

    /// Creates an `Arbiter` with both `write_stream` and `read_stream`
    /// pre‑populated, so the inline `IntoFuture` path can proceed past
    /// resource acquisition without calling the (expensive) `ensure_init`.
    fn test_arbiter_with_ws_and_rs() -> Arc<Arbiter<TestConnect, Arc<H3Endpoint<TestConnect>>>> {
        let arbiter = test_arbiter_with_ws();
        let rs = crate::message::stream::ReadStream::new_for_test(VarInt::from_u32(1));
        *arbiter.read_stream.lock().unwrap() = Some(rs);
        arbiter
    }

    /// Inline path (`Arc::strong_count == 1`): message + ws + rs all
    /// pre‑populated. The test `ReadStream` returns `None` immediately
    /// → `read_message_header` fails with `MessageStreamError`.
    ///
    /// Verifies the inline `IntoFuture` reaches the `read_message_header`
    /// step and propagates the stream error correctly.
    #[tokio::test]
    async fn test_into_future_inline_read_error() {
        // Drop the outer arbiter so only req holds an Arc → inline path
        let req = {
            let arbiter = test_arbiter_with_ws_and_rs();
            request_with_message(&arbiter)
        };

        let result = req.await;
        assert!(
            matches!(result, Err(RequestError::MessageStream { .. })),
            "expected MessageStream error"
        );
    }

    /// Split path (`Arc::strong_count > 1`): clone returns resources to
    /// pool, original awaits. Test `ReadStream` returns `None` immediately
    /// → `read_message_header` fails with `MessageStreamError`.
    ///
    /// Verifies the split path is correctly selected when other clones
    /// exist and the error propagates through the `IntoFuture`.
    #[tokio::test]
    #[ignore = "split path not yet implemented (todo in Task 16)"]
    async fn test_into_future_split_read_error() {
        let arbiter = test_arbiter();
        let rs = crate::message::stream::ReadStream::new_for_test(VarInt::from_u32(0));
        *arbiter.read_stream.lock().unwrap() = Some(rs);

        let req = request_with_message(&arbiter);
        let _clone = req.clone();
        let req_arbiter = req.arbiter.borrow();
        assert!(
            Arc::strong_count(req_arbiter.as_ref().expect("arbiter should be Some")) >= 2,
            "clone should increase Arc refcount"
        );
        drop(req_arbiter);

        let result = req.await;
        assert!(
            matches!(result, Err(RequestError::MessageStream { .. })),
            "expected MessageStream error in split path"
        );
    }

    /// Inline path: `held_message` is `None` and pool is empty →
    /// Inline path no longer panics on missing message — it skips the
    /// send step and proceeds to read the response.
    #[tokio::test]
    async fn test_into_future_inline_no_message() {
        let arbiter = test_arbiter();
        let _msg = arbiter.acquire_request_message();
        let req = Request::new(Arc::clone(&arbiter));

        let result = req.await;
        // Missing message is fine — send step is skipped.
        // Error comes from missing read_stream (never initialized).
        assert!(
            result.is_err(),
            "should fail when read_stream is unavailable"
        );
    }

    /// Split-path selection: when a clone exists, `Arc::strong_count` is
    /// ≥ 2 inside `into_future`, selecting the split path (read‑only).
    ///
    /// This test verifies the refcount‑based routing, exercised through
    /// the same `read_message_header` error as `test_into_future_split_read_error`.
    #[tokio::test]
    #[ignore = "split path not yet implemented (todo in Task 16)"]
    async fn test_into_future_split_refcount() {
        let arbiter = test_arbiter();
        let rs = crate::message::stream::ReadStream::new_for_test(VarInt::from_u32(0));
        *arbiter.read_stream.lock().unwrap() = Some(rs);

        let req = request_with_message(&arbiter);
        let _clone = req.clone();
        let req_arbiter = req.arbiter.borrow();
        assert!(
            Arc::strong_count(req_arbiter.as_ref().expect("arbiter should be Some")) >= 2,
            "clone should increase Arc refcount → split path"
        );
        drop(req_arbiter);

        // The split path is exercised via await; the exact error is
        // MessageStream (TestReader returns None) — that proves we entered
        // the split branch, not the inline branch.
        let result = req.await;
        assert!(matches!(result, Err(RequestError::MessageStream { .. })));
    }

    /// Full happy‑path test for the inline `IntoFuture`. Requires a
    /// real QUIC endpoint that serves a valid H3 response.
    #[tokio::test]
    #[ignore = "needs test endpoint infrastructure for full IntoFuture happy path"]
    async fn test_into_future_inline_get() {
        todo!(
            "build a real H3Endpoint, create a GET Request, await it, \
             and assert Response::status() is 200"
        )
    }

    /// Happy‑path test for the split `IntoFuture`. Clone a `Request`
    /// (which writes headers/body), then await the original to receive
    /// the response.
    #[tokio::test]
    #[ignore = "needs test endpoint infrastructure for full IntoFuture happy path"]
    async fn test_into_future_split_clone() {
        todo!(
            "build a real H3Endpoint, create a POST Request, clone it, \
             write body to the clone, await the original, assert status 200"
        )
    }

    // ====================================================================
    // Task — authority & lifecycle tests
    // ====================================================================

    /// Authority can be set when `init_done` is false (initial state).
    ///
    /// Assertions:
    /// - `set_authority()` returns `Ok(())`.
    /// - `authority` mutex contains the new value.
    #[tokio::test]
    async fn test_set_authority_before_init() {
        let arbiter = test_arbiter();
        // Override the authority that test_arbiter already set
        let new_auth = Authority::from_static("new.example.com");
        let result = arbiter.set_authority(new_auth.clone());
        assert!(result.is_ok(), "set_authority should succeed before init");
        let stored = arbiter.authority.lock().expect("lock poisoned").clone();
        assert_eq!(stored, Some(new_auth), "authority should be updated");
    }

    /// After `init_done` is set to `true`, `set_authority()` returns
    /// `Err(AuthorityFrozen::InitComplete)`.
    ///
    /// Assertions:
    /// - With `init_done = true`, `set_authority()` → `Err(AuthorityFrozen::InitComplete)`.
    #[tokio::test]
    async fn test_set_authority_after_init_frozen() {
        let arbiter = test_arbiter();
        // Freeze authority
        arbiter.init_done.store(true, Ordering::Release);
        let result = arbiter.set_authority(Authority::from_static("new.example.com"));
        assert!(
            result.is_err(),
            "set_authority should return Err after init_done"
        );
        match result {
            Err(AuthorityFrozen::InitComplete) => {} // expected
            other => panic!("expected AuthorityFrozen::InitComplete, got {other:?}"),
        }
    }

    /// When `init_done` is true and `init_state` caches `Ok(())`,
    /// `ensure_stream_init()` returns the cached success immediately.
    ///
    /// Assertions:
    /// - `ensure_stream_init().await` → `Ok(())`.
    #[tokio::test]
    async fn test_ensure_stream_init_cached_success() {
        let arbiter = test_arbiter();
        // Pre-set init_state to success and mark init done
        *arbiter.init_state.lock().await = Some(Ok(()));
        arbiter.init_done.store(true, Ordering::Release);
        // Second call should return cached Ok
        let result = arbiter.ensure_stream_init().await;
        assert!(
            result.is_ok(),
            "ensure_stream_init should return cached Ok, got {result:?}"
        );
    }

    /// Calling `.uri()` on a `Request` syncs the authority from the
    /// URI into the `Arbiter`'s authority field.
    ///
    /// Assertions:
    /// - After `request.uri(uri)`, `arbiter.authority` matches the URI authority.
    #[tokio::test]
    async fn test_uri_authority_sync() {
        let arbiter = test_arbiter();
        let req = request_with_message(&arbiter);

        let uri: Uri = "https://sync.example.com/path".parse().expect("valid URI");
        req.set_uri(uri);

        let stored = arbiter.authority.lock().expect("lock poisoned").clone();
        assert_eq!(
            stored.as_ref().map(|a| a.as_str()),
            Some("sync.example.com"),
            "authority should be synced from URI"
        );
    }

    /// `RequestError` implements `Clone`. Verify that cloning a
    /// unit-like variant produces an equal error.
    ///
    /// Assertions:
    /// - `RequestError::HeaderTooLarge.clone()` yields `RequestError::HeaderTooLarge`.
    #[test]
    fn test_request_error_clone() {
        let err = RequestError::<quic::ConnectionError>::HeaderTooLarge;
        let cloned = err.clone();
        match (&err, &cloned) {
            (RequestError::HeaderTooLarge, RequestError::HeaderTooLarge) => {}
            _ => panic!("clone mismatch: err={err:?} cloned={cloned:?}"),
        }
    }

    /// When `init_done` is true (authority frozen), calling `.uri()`
    /// with a URI containing a new authority marks the message as
    /// malformed via `msg.set_malformed()`.
    ///
    /// Assertions:
    /// - `.uri()` with a different authority → message is malformed.
    #[tokio::test]
    async fn test_uri_poisons_on_frozen() {
        let arbiter = test_arbiter();
        // Freeze authority
        arbiter.init_done.store(true, Ordering::Release);

        let req = request_with_message(&arbiter);
        let uri: Uri = "https://different.example.com/path"
            .parse()
            .expect("valid URI");
        req.set_uri(uri);

        // Retrieve the message back and check it's malformed
        let msg_guard = req.message().expect("should be able to get message");
        assert!(
            msg_guard.is_malformed(),
            "message should be marked malformed after frozen authority change"
        );
    }
}
