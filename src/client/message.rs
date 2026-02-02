use std::error::Error;

use bytes::{Buf, Bytes};
use futures::{Sink, Stream, sink, stream};
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{AsHeaderName, IntoHeaderName},
    uri::{Authority, PathAndQuery, Scheme},
};
use snafu::{Report, ResultExt, Snafu};
use tracing::Instrument;

use crate::{
    agent::{LocalAgent, RemoteAgent},
    client::Client,
    connection::InitialRequestStreamError,
    error::Code,
    message::{
        MalformedMessageError, Message, MessageStage,
        stream::{ReadStream, ReadToStringError, StreamError, WriteStream},
    },
    pool::ConnectError,
    qpack::field_section::MalformedHeaderSection,
    quic,
};

#[derive(Clone)]
pub struct PendingRequest<'c, C: quic::Connect> {
    client: &'c Client<C>,
    request: Message,
    auto_close: bool,
}

impl<'c, C: quic::Connect> std::fmt::Debug for PendingRequest<'c, C>
where
    Client<C>: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRequest")
            .field("client", &self.client)
            .field("request", &self.request)
            .field("auto_close", &self.auto_close)
            .finish()
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RequestError<E: Error + 'static> {
    #[snafu(transparent)]
    Connect { source: ConnectError<E> },
    #[snafu(transparent)]
    Stream { source: quic::StreamError },
    #[snafu(display("request cannot be send due to malformed header"))]
    MalformedRequestHeader { source: MalformedHeaderSection },
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
    #[snafu(display("expected HTTPS scheme"))]
    NotHttpsScheme,
}

impl<E: Error + 'static> From<quic::ConnectionError> for RequestError<E> {
    fn from(error: quic::ConnectionError) -> Self {
        quic::StreamError::from(error).into()
    }
}

impl<C: quic::Connect> Client<C> {
    pub fn new_request(&self) -> PendingRequest<'_, C> {
        PendingRequest {
            client: self,
            request: Message::unresolved_request(),
            auto_close: true,
        }
    }
}

impl<C: quic::Connect> PendingRequest<'_, C> {
    pub fn with_method(mut self, method: Method) -> Self {
        self.request.header_mut().set_method(method);
        self
    }

    pub fn with_scheme(mut self, scheme: Scheme) -> Self {
        self.request.header_mut().set_scheme(scheme);
        self
    }

    pub fn with_authority(mut self, authority: Authority) -> Self {
        self.request.header_mut().set_authority(authority);
        self
    }

    pub fn with_path(mut self, path: PathAndQuery) -> Self {
        self.request.header_mut().set_path(path);
        self
    }

    pub fn with_uri(mut self, uri: Uri) -> Self {
        self.request.header_mut().set_uri(uri);
        self
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.request.header().header_map
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.request.header_mut().header_map
    }

    pub fn with_header(mut self, name: impl IntoHeaderName, value: HeaderValue) -> Self {
        self.headers_mut().insert(name, value);
        self
    }

    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        *self.headers_mut() = headers;
        self
    }

    pub fn with_body(mut self, body: impl Buf) -> Self {
        self.request.set_body(body);
        self
    }

    /// Whether to automatically close the request stream when the pending request is chunked.
    ///
    /// Default is `true` to adapt most use cases.
    pub fn auto_close(mut self, auto_close: bool) -> Self {
        self.auto_close = auto_close;
        self
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.request.trailers()
    }

    pub fn trailers_mut(&mut self) -> &mut HeaderMap {
        self.request.trailers_mut()
    }

    pub fn with_trailer(mut self, name: impl IntoHeaderName, value: HeaderValue) -> Self {
        self.trailers_mut().insert(name, value);
        self
    }

    pub fn with_trailers(mut self, trailers: HeaderMap) -> Self {
        *self.trailers_mut() = trailers;
        self
    }
}

impl<C: quic::Connect> PendingRequest<'_, C>
where
    C::Connection: Send + 'static,
    <C::Connection as quic::ManageStream>::StreamReader: Send,
    <C::Connection as quic::ManageStream>::StreamWriter: Send,
{
    /// Execute the request and return the response
    #[tracing::instrument(
        level = "debug",
        target = "h3x::client",
        name = "execute_request",
        skip_all,
        err
    )]
    pub async fn execute(mut self) -> Result<(Request, Response), RequestError<C::Error>> {
        self.request
            .header()
            .check_pseudo()
            .context(request_error::MalformedRequestHeaderSnafu)?;
        if self.request.header().scheme() != Some(Scheme::HTTPS) {
            return Err(RequestError::NotHttpsScheme);
        }

        if tracing::enabled!(tracing::Level::DEBUG) {
            tracing::Span::current()
                .record("method", self.request.header().method().as_str())
                .record("uri", self.request.header().uri().to_string());
        }

        let authority = self.request.header().authority().expect("checked");

        loop {
            let connection = self.client.connect(authority.clone()).await?;
            tracing::debug!(target: "h3x::client", %authority, "Connected");

            let (mut read_stream, mut write_stream) = match connection.open_request_stream().await {
                Ok(pair) => pair,
                Err(InitialRequestStreamError::Quic { source: error }) => return Err(error.into()),
                Err(InitialRequestStreamError::Goaway { .. }) => {
                    tracing::debug!(target: "h3x::client", "Connection goaway, retrying...");
                    continue;
                }
            };

            let local_agent = connection.local_agent().await?;
            let remote_agent = connection
                .remote_agent()
                .await?
                .expect("chekced by Client::connect");

            let send_request = async {
                if self.auto_close && self.request.is_chunked() {
                    write_stream.close_message(&mut self.request).await
                } else {
                    write_stream.send_message(&mut self.request).await
                }
            };

            let mut response = Message::unresolved_response();

            return match tokio::try_join!(
                send_request,
                read_stream.read_message_header(&mut response)
            ) {
                Ok(..) => {
                    let request = Request {
                        message: self.request,
                        stream: write_stream,
                        agent: local_agent,
                    };
                    let response = Response {
                        message: response,
                        stream: read_stream,
                        agent: remote_agent,
                    };
                    return Ok((request, response));
                }
                Err(StreamError::HeaderTooLarge) => Err(RequestError::HeaderTooLarge),
                Err(StreamError::TrailerTooLarge) => Err(RequestError::TrailerTooLarge),
                Err(StreamError::DataFrameTooLarge) => Err(RequestError::DataFrameTooLarge),
                Err(StreamError::MalformedIncomingMessage) => Err(RequestError::MalformedResponse),
                Err(StreamError::Quic { source }) => Err(source.into()),
                Err(StreamError::Goaway { .. }) => {
                    tracing::debug!(target: "h3x::client", "Connection goaway, retrying...");
                    continue;
                }
            };
        }
    }

    pub async fn get(self, uri: Uri) -> Result<(Request, Response), RequestError<C::Error>> {
        self.with_method(Method::GET).with_uri(uri).execute().await
    }

    pub async fn post(self, uri: Uri) -> Result<(Request, Response), RequestError<C::Error>> {
        self.with_method(Method::POST).with_uri(uri).execute().await
    }

    pub async fn put(self, uri: Uri) -> Result<(Request, Response), RequestError<C::Error>> {
        self.with_method(Method::PUT).with_uri(uri).execute().await
    }

    pub async fn delete(self, uri: Uri) -> Result<(Request, Response), RequestError<C::Error>> {
        self.with_method(Method::DELETE)
            .with_uri(uri)
            .execute()
            .await
    }

    pub async fn head(self, uri: Uri) -> Result<(Request, Response), RequestError<C::Error>> {
        self.with_method(Method::HEAD).with_uri(uri).execute().await
    }

    pub async fn options(self, uri: Uri) -> Result<(Request, Response), RequestError<C::Error>> {
        self.with_method(Method::OPTIONS)
            .with_uri(uri)
            .execute()
            .await
    }

    pub async fn connect(self, uri: Uri) -> Result<(Request, Response), RequestError<C::Error>> {
        self.with_method(Method::CONNECT)
            .with_uri(uri)
            .execute()
            .await
    }

    pub async fn patch(self, uri: Uri) -> Result<(Request, Response), RequestError<C::Error>> {
        self.with_method(Method::PATCH)
            .with_uri(uri)
            .execute()
            .await
    }

    pub async fn trace(self, uri: Uri) -> Result<(Request, Response), RequestError<C::Error>> {
        self.with_method(Method::TRACE)
            .with_uri(uri)
            .execute()
            .await
    }
}

pub struct Request {
    message: Message,
    stream: WriteStream,
    agent: Option<LocalAgent>,
}

impl Request {
    pub fn method(&self) -> Method {
        self.message.header().method()
    }

    pub fn scheme(&self) -> Option<Scheme> {
        self.message.header().scheme()
    }

    pub fn authority(&self) -> Option<Authority> {
        self.message.header().authority()
    }

    pub fn path(&self) -> Option<PathAndQuery> {
        self.message.header().path()
    }

    pub fn uri(&self) -> Uri {
        self.message.header().uri()
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.message.header().header_map
    }

    fn check_message_operation(
        &mut self,
        operation: &str,
        operate: impl FnOnce(&mut Self) -> Result<(), MalformedMessageError>,
    ) {
        if self.message.is_malformed() {
            tracing::warn!(
                target: "h3x::client", operation,
                "Request is malformed, operation will not affect the request stream",
            );
        }
        if let Err(error) = operate(self) {
            tracing::warn!(
                target: "h3x::client", operation, error = %Report::from_error(error),
                "Operation malformed the request message, request stream will be cancelled with H3_REQUEST_CANCELLED",
            );
            self.message.set_malformed();
        }
    }

    pub async fn write(&mut self, content: impl Buf) -> Result<&mut Self, StreamError> {
        self.check_message_operation("write_streaming_body", |this| {
            // header is checked in pending request
            this.message.streaming_body()?;
            Ok(())
        });
        self.stream
            .send_message_streaming_body(&mut self.message, content)
            .await?;
        Ok(self)
    }

    pub async fn flush(&mut self) -> Result<&mut Self, StreamError> {
        // header is checked in pending request
        self.stream.flush_message(&mut self.message).await?;
        Ok(self)
    }

    pub fn as_sink<B: Buf>(&mut self) -> impl Sink<B, Error = StreamError> {
        sink::unfold(self, async |this, item: B| this.write(item).await)
    }

    pub fn into_sink<B: Buf>(self) -> impl Sink<B, Error = StreamError> {
        sink::unfold(self, async |mut this, item: B| {
            this.write(item).await?;
            Ok(this)
        })
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.message.trailers()
    }

    pub fn trailers_mut(&mut self) -> &mut HeaderMap {
        self.check_message_operation("modify_trailers", |this| {
            if this.message.stage() >= MessageStage::Trailer {
                return Err(MalformedMessageError::TrailerAlreadySent);
            }
            Ok(())
        });
        self.message.trailers_mut()
    }

    pub fn set_trailer(&mut self, name: impl IntoHeaderName, value: HeaderValue) -> &mut Self {
        self.trailers_mut().insert(name, value);
        self
    }

    pub fn set_trailers(&mut self, map: HeaderMap) -> &mut Self {
        *self.trailers_mut() = map;
        self
    }

    pub async fn close(&mut self) -> Result<(), StreamError> {
        self.stream.close_message(&mut self.message).await
    }

    pub async fn cancel(&mut self, code: Code) -> Result<(), StreamError> {
        self.stream.cancel(code).await
    }

    /// Low level access to the underlying write stream
    pub fn write_stream(&mut self) -> &mut WriteStream {
        &mut self.stream
    }

    pub fn agent(&self) -> Option<&LocalAgent> {
        self.agent.as_ref()
    }

    /// Async drop the request properly
    pub(crate) fn drop(&mut self) -> Option<impl Future<Output = ()> + Send + use<>> {
        if self.message.is_complete() || self.message.is_dropped() {
            return None;
        }
        let mut stream = self.stream.take();
        let mut message = self.message.take();

        // if !message.is_malformed() {
        //     let check = || {
        //         // There is no check that could fail
        //         Ok(())
        //     };
        //     if let Err(error) = check() {
        //         message.set_malformed();
        //         tracing::warn!(
        //             target: "h3x::client", error = %Report::from_error(error),
        //             "Request stream cannot be closed properly as its malformed",
        //         );
        //     }
        // }

        Some(async move { _ = stream.close_message(&mut message).await })
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if let Some(future) = self.drop() {
            tokio::spawn(future.in_current_span());
        }
    }
}

pub struct Response {
    message: Message,
    stream: ReadStream,
    agent: RemoteAgent,
}

impl Response {
    pub async fn next_response(&mut self) -> Result<&mut Self, StreamError> {
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

    pub async fn read(&mut self) -> Option<Result<Bytes, StreamError>> {
        self.stream.read_message(&mut self.message).await
    }

    pub async fn read_all(&mut self) -> Result<impl Buf, StreamError> {
        self.stream.read_message_full_body(&mut self.message).await
    }

    pub async fn read_to_bytes(&mut self) -> Result<Bytes, StreamError> {
        self.stream
            .read_message_body_to_bytes(&mut self.message)
            .await
    }

    pub async fn read_to_string(&mut self) -> Result<String, ReadToStringError> {
        self.stream
            .read_message_body_to_string(&mut self.message)
            .await
    }

    pub async fn as_stream(&mut self) -> impl Stream<Item = Result<Bytes, StreamError>> {
        stream::unfold(self, async |this| {
            this.read().await.map(|item| (item, this))
        })
    }

    pub async fn into_stream(self) -> impl Stream<Item = Result<Bytes, StreamError>> {
        stream::unfold(self, async |mut this| {
            this.read().await.map(|item| (item, this))
        })
    }

    pub async fn trailers(&mut self) -> Result<&HeaderMap, StreamError> {
        self.stream.read_message_trailer(&mut self.message).await
    }

    /// Low level access to the underlying read stream
    pub fn read_stream(&mut self) -> &mut ReadStream {
        &mut self.stream
    }

    pub fn agent(&self) -> &RemoteAgent {
        &self.agent
    }
}
