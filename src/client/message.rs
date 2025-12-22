use std::error::Error;

use bytes::{Buf, Bytes};
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{AsHeaderName, IntoHeaderName},
    uri::{Authority, PathAndQuery, Scheme},
};
use snafu::{Report, Snafu};
use tracing::Instrument;

use crate::{
    agent::{LocalAgent, RemoteAgent},
    client::Client,
    connection::InitialRequestStreamError,
    message::{
        Message, MessageError, MessageStage,
        stream::{ReadStream, ReadToStringError, StreamError, WriteStream},
    },
    pool::ConnectError,
    qpack::field_section::MalformedHeaderSection,
    quic,
    varint::VarInt,
};

#[derive(Clone)]
pub struct PendingRequest<'c, C: quic::Connect> {
    client: &'c Client<C>,
    request: Message,
}

impl<'c, C: quic::Connect + std::fmt::Debug> std::fmt::Debug for PendingRequest<'c, C>
where
    C::Connection: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRequest")
            .field("client", &self.client)
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Debug, Snafu)]
pub enum RequestError<E: Error + 'static> {
    #[snafu(transparent)]
    Connect { source: ConnectError<E> },
    #[snafu(transparent)]
    Stream { source: quic::StreamError },
    #[snafu(transparent)]
    MalformedHeader { source: MalformedHeaderSection },
    #[snafu(display("Expected HTTPS scheme"))]
    NotHttpsScheme,
}

impl<E: Error + 'static> From<quic::ConnectionError> for RequestError<E> {
    fn from(error: quic::ConnectionError) -> Self {
        quic::StreamError::from(error).into()
    }
}

impl<C: quic::Connect> Client<C> {
    pub fn new_request(&self) -> PendingRequest<'_, C> {
        let mut request = Message::unresolved_request();
        _ = request.enable_streaming();
        PendingRequest {
            client: self,
            request,
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
        self.request
            .set_body(body)
            .expect("Request in Header stage as it unsend");
        self
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.request.trailers()
    }

    pub fn trailers_mut(&mut self) -> &mut HeaderMap {
        self.request
            .trailers_mut()
            .expect("Request never be interim_response")
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
        self.request.header().check_pseudo()?;
        if self.request.header().scheme() != Some(Scheme::HTTPS) {
            return Err(RequestError::NotHttpsScheme);
        }

        if tracing::enabled!(tracing::Level::DEBUG) {
            tracing::Span::current()
                .record("method", self.request.header().method().as_str())
                .record("uri", self.request.header().uri().to_string());
        }

        let authority = self.request.header().authority().expect("Checked");

        loop {
            let connection = self.client.connect(authority.clone()).await?;
            tracing::debug!(%authority, "Connected");

            let (mut read_stream, mut write_stream) = match connection.open_request_stream().await {
                Ok(pair) => pair,
                Err(InitialRequestStreamError::Quic { source: error }) => return Err(error.into()),
                Err(InitialRequestStreamError::Goaway { .. }) => {
                    tracing::debug!("Connection goaway, retrying...");
                    continue;
                }
            };

            let local_agent = connection.local_agent().await?;
            let remote_agent = connection
                .remote_agent()
                .await?
                .expect("chekced by Client::connect");

            let mut response = Message::unresolved_response();

            match tokio::try_join!(
                write_stream.send_header(&mut self.request),
                read_stream.read_header(&mut response)
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
                Err(StreamError::MessageOperation { .. }) => {
                    unreachable!("Header should be checked before sending")
                }
                Err(StreamError::Quic { source }) => {
                    return Err(source.into());
                }
                Err(StreamError::Goaway { .. }) => {
                    tracing::debug!("Connection goaway, retrying...");
                    continue;
                }
            }
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

    pub async fn write(&mut self, content: impl Buf) -> Result<&mut Self, StreamError> {
        self.stream
            .send_streaming_body(&mut self.message, content)
            .await?;
        Ok(self)
    }

    pub async fn flush(&mut self) -> Result<&mut Self, StreamError> {
        self.stream.flush(&mut self.message).await?;
        Ok(self)
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.message.trailers()
    }

    pub fn trailers_mut(&mut self) -> Result<&mut HeaderMap, StreamError> {
        if self.message.stage() > MessageStage::Trailer {
            return Err(MessageError::TrailerAlreadySent.into());
        }
        Ok(self.message.trailers_mut()?)
    }

    pub fn set_trailer(
        &mut self,
        name: impl IntoHeaderName,
        value: HeaderValue,
    ) -> Result<&mut Self, StreamError> {
        self.trailers_mut()?.insert(name, value);
        Ok(self)
    }

    pub fn set_trailers(&mut self, map: HeaderMap) -> Result<&mut Self, StreamError> {
        *self.trailers_mut()? = map;
        Ok(self)
    }

    pub async fn close(&mut self) -> Result<(), StreamError> {
        self.stream.close(&mut self.message).await
    }

    pub async fn cancel(&mut self, code: VarInt) -> Result<(), StreamError> {
        self.stream.cancel(code).await
    }

    pub fn agent(&self) -> Option<&LocalAgent> {
        self.agent.as_ref()
    }

    /// Async drop the request properly
    pub(crate) fn drop(&mut self) -> Option<impl Future<Output = ()> + Send + use<>> {
        if self.message.is_complete() || self.message.is_destroyed() {
            return None;
        }
        let mut stream = self.stream.take();
        let mut entity = self.message.take();
        Some(async move {
            if let Err(StreamError::MessageOperation { source }) = stream.close(&mut entity).await {
                tracing::warn!(
                    target: "h3x::client", error = %Report::from_error(source),
                    "Request stream cannot be closed properly"
                );
            }
        })
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
    pub fn streaming(mut self) -> Result<Self, StreamError> {
        self.message.enable_streaming()?;
        Ok(self)
    }

    pub async fn next_response(&mut self) -> Result<&mut Self, StreamError> {
        self.stream.read_header(&mut self.message).await?;
        Ok(self)
    }

    pub fn status(&mut self) -> http::StatusCode {
        self.message.header().status()
    }

    pub fn headers(&mut self) -> &HeaderMap {
        &self.message.header().header_map
    }

    pub fn header(&mut self, name: impl AsHeaderName) -> Option<&HeaderValue> {
        self.headers().get(name)
    }

    pub async fn read(&mut self) -> Option<Result<Bytes, StreamError>> {
        self.stream.read(&mut self.message).await
    }

    pub async fn read_all(&mut self) -> Result<impl Buf, StreamError> {
        self.stream.read_all(&mut self.message).await
    }

    pub async fn read_to_bytes(&mut self) -> Result<Bytes, StreamError> {
        self.stream.read_to_bytes(&mut self.message).await
    }

    pub async fn read_to_string(&mut self) -> Result<String, ReadToStringError> {
        self.stream.read_to_string(&mut self.message).await
    }

    pub async fn trailers(&mut self) -> Result<&HeaderMap, StreamError> {
        self.stream.read_trailer(&mut self.message).await
    }

    pub fn agent(&self) -> &RemoteAgent {
        &self.agent
    }
}
