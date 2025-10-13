use std::{
    collections::VecDeque,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll, ready},
};

use bon::Builder;
use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt, future::BoxFuture};
use tokio::io;

/// 考虑到自定义Method，不允许Copy
pub enum Method {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    CONNECT,
    TRACE,
    PATCH,
    Custom(String),
}

pub struct Uri {
    schema: String,
    authority: String,
    path: String,
}

impl FromStr for Uri {
    type Err = ();

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl TryFrom<&str> for Uri {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

pub enum FieldName {}

pub struct FieldValue {}

type FieldLine = (FieldName, FieldValue);

#[derive(Default)]
pub struct FieldSection {
    lines: VecDeque<FieldLine>,
}

pub struct Message<C> {
    header: FieldSection,
    context: C,
    trailer: FieldSection,
}

mod request_builder {
    use super::*;

    #[derive(Builder)]
    pub struct RequestHeader {
        #[builder(field)]
        headers: FieldSection,
        #[builder(into)]
        method: Method,
        #[builder(into)]
        schema: String,
        #[builder(into)]
        authority: String,
        #[builder(into)]
        path: String,
    }

    impl<M, U> TryFrom<(M, U)> for RequestHeader
    where
        M: TryInto<Method>,
        U: TryInto<Uri>,
    {
        type Error = ();

        fn try_from(value: (M, U)) -> Result<Self, Self::Error> {
            todo!()
        }
    }

    impl From<RequestHeader> for FieldSection {
        fn from(value: RequestHeader) -> Self {
            todo!()
        }
    }

    impl<S: request_header_builder::State> RequestHeaderBuilder<S> {
        pub fn uri(
            self,
            (scheme, authority, path): (String, String, String),
        ) -> RequestHeaderBuilder<
            request_header_builder::SetPath<
                request_header_builder::SetAuthority<request_header_builder::SetSchema<S>>,
            >,
        >
        where
            S::Schema: request_header_builder::IsUnset,
            S::Authority: request_header_builder::IsUnset,
            S::Path: request_header_builder::IsUnset,
        {
            self.schema(scheme).authority(authority).path(path)
        }
    }

    #[derive(Builder)]
    #[builder(finish_fn(name= body_inner, vis=""))]
    pub struct Request<T> {
        #[builder(field)]
        headers: FieldSection,
        #[builder(field)]
        trailers: FieldSection,
        #[builder(finish_fn)]
        context: T,
        #[builder(into)]
        method: Method,
        #[builder(into)]
        schema: String,
        #[builder(into)]
        authority: String,
        #[builder(into)]
        path: String,
    }

    impl<T, S: request_builder::State> RequestBuilder<T, S> {
        pub fn header(mut self, line: FieldLine) -> Self {
            self.headers.lines.push_back(line);
            self
        }

        pub fn headers(mut self, lines: impl IntoIterator<Item = FieldLine>) -> Self {
            self.headers.lines.extend(lines);
            self
        }

        pub fn trailer(mut self, line: FieldLine) -> Self {
            self.trailers.lines.push_back(line);
            self
        }

        pub fn trailers(mut self, lines: impl IntoIterator<Item = FieldLine>) -> Self {
            self.trailers.lines.extend(lines);
            self
        }

        pub fn body(self, body: T) -> super::Request<T>
        where
            S: request_builder::IsComplete,
        {
            todo!()
        }
    }

    impl<S: request_builder::State> RequestBuilder<(), S> {
        pub fn streaming(self) -> ((), super::Request<()>)
        where
            S: request_builder::IsComplete,
        {
            ((), self.body(()))
        }
    }
}

pub struct IncomingMessage<S> {
    // status: (),
    stream: S,

    header: Option<FieldSection>,
    context: Vec<Bytes>,
    read_offset: (usize, usize),
    trailer: Option<FieldSection>,
}

impl<S: Unpin> IncomingMessage<S> {
    // 解帧
    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<Result<Option<()>, ()>> {
        todo!()
    }

    pub fn poll_header<'s>(
        &'s mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<&'s FieldSection, ()>> {
        match self.header {
            Some(ref header) => Poll::Ready(Ok(header)),
            None => {
                ready!(self.poll(cx))?;
                self.poll_header(cx)
            }
        }
    }

    pub fn poll_trailer<'s>(
        &'s mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<&'s FieldSection, ()>> {
        match self.trailer {
            Some(ref trailer) => Poll::Ready(Ok(trailer)),
            None => {
                ready!(self.poll(cx))?;
                self.poll_trailer(cx)
            }
        }
    }

    pub async fn bytes(&mut self) -> Result<Bytes, ()> {
        let fold = |acc: Result<BytesMut, ()>, chunk| async move {
            acc.and_then(|mut acc| {
                acc.extend(chunk?);
                Ok(acc)
            })
        };
        Ok(self.fold(Ok(BytesMut::new()), fold).await?.freeze())
    }
}

impl<S: Unpin> Stream for IncomingMessage<S> {
    type Item = Result<Bytes, ()>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.read_offset.0 < self.context.len()
            && self.read_offset.1 < self.context[self.read_offset.0].len()
        {
            let bytes = self.context[self.read_offset.0].slice(self.read_offset.1..);
            self.read_offset = (self.read_offset.0 + 1, 0);
            return Poll::Ready(Some(Ok(bytes)));
        }

        match ready!(self.as_mut().poll(cx)) {
            Ok(Some(_)) => Poll::Ready(None),
            Ok(None) => self.poll_next(cx),
            Err(e) => Poll::Ready(Some(Err(e))),
        }
    }
}

impl<S: Unpin> io::AsyncRead for IncomingMessage<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_offset.0 < self.context.len()
            && self.read_offset.1 < self.context[self.read_offset.0].len()
        {
            let part_remaining = self.context[self.read_offset.0].len() - self.read_offset.1;
            let len = std::cmp::min(buf.remaining(), part_remaining);
            buf.put_slice(&self.context[self.read_offset.0][self.read_offset.1..][..len]);
            if part_remaining == len {
                self.get_mut().read_offset = (self.read_offset.0 + 1, 0);
            } else {
                self.get_mut().read_offset.1 += len;
            }

            return Poll::Ready(Ok(()));
        }

        match ready!(self.poll(cx)) {
            Ok(Some(_)) => Poll::Ready(Ok(())),
            Ok(None) => self.poll_read(cx, buf),
            Err(_) => Poll::Ready(Err(io::Error::other("error..."))),
        }
    }
}

pub struct IncomingResponse<S>(IncomingMessage<S>);

impl<S> IncomingResponse<S> {
    pub async fn header(&mut self) -> Result<&FieldSection, ()> {
        todo!()
    }

    pub async fn trailer(&mut self) -> Result<&FieldSection, ()> {
        todo!()
    }
}

impl<S: Unpin> Stream for IncomingResponse<S> {
    type Item = Result<Bytes, ()>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}

impl<S: Unpin> io::AsyncRead for IncomingResponse<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

/// Each message is either a request or a response.
pub struct Request<C> {
    message: Message<C>,
}

pub struct Response<C> {
    message: Message<C>,
}

pub struct Connection<C> {
    quic_conn: C,
}

/// Note: shutdown() must be called or stream will be reset when [`RequestWriter`] dropped.
pub struct RequestWriter<S> {
    pending_header: FieldSection,
    pending_data: VecDeque<Bytes>,
    stream: S,
    pending_tailer: FieldSection,
}

impl<S> RequestWriter<S> {
    pub async fn header(&mut self, header: FieldSection) -> Result<&mut Self, ()> {
        self.pending_header.lines.extend(header.lines);
        Ok(self)
    }

    pub async fn data(&mut self, _data: &[u8]) -> Result<&mut Self, ()> {
        Ok(self)
    }

    /// Once trailers are sent, the request is considered complete and no further data can be sent.
    pub async fn trailer(&mut self, _trailer: FieldSection) -> Result<(), ()> {
        Ok(())
    }
}

impl<S> Sink<Bytes> for RequestWriter<S> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        todo!()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        todo!()
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        todo!()
    }
}

pub struct PendingRequest<'c, S, Context, Conn> {
    header: request_builder::RequestHeaderBuilder<S>,
    context: Context,
    connection: &'c mut Connection<Conn>,
}

impl<'c, Context, Conn> PendingRequest<'c, Context, Conn> {
    pub fn header(self, header: FieldSection) -> Self {
        Self { header, ..self }
    }

    pub fn body(self, body: Context) -> Self {
        Self {
            context: body,
            ..self
        }
    }

    pub fn trailer(self, trailer: FieldSection) -> Self {
        Self {
            tailer: trailer,
            ..self
        }
    }
}

impl<'c, Context, Conn: QuicConnection> IntoFuture for PendingRequest<'c, Context, Conn> {
    type Output = (
        RequestWriter<Conn::StreamWriter>,
        IncomingResponse<Conn::StreamRecver>,
    );

    type IntoFuture = BoxFuture<'c, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { todo!() })
    }
}

pub trait QuicConnection {
    type StreamWriter;
    type StreamRecver;

    fn open_bi(&self) -> (Self::StreamWriter, Self::StreamRecver);
}

struct MockQuicConnection;

impl QuicConnection for MockQuicConnection {
    type StreamWriter = ();
    type StreamRecver = ();

    fn open_bi(&self) -> (Self::StreamWriter, Self::StreamRecver) {
        ((), ())
    }
}

impl<C: QuicConnection> Connection<C> {
    pub async fn send_request<Body>(
        &self,
        req: Request<Body>,
    ) -> Result<IncomingMessage<C::StreamRecver>, ()> {
        todo!()
    }

    pub async fn request(
        &self,
        header: impl TryInto<request_builder::RequestHeader>,
    ) -> Result<
        (
            RequestWriter<C::StreamWriter>,
            IncomingResponse<C::StreamRecver>,
        ),
        (),
    > {
        todo!()
    }
}

#[cfg(test)]
mod tests {

    use futures::SinkExt;
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn test_name() -> Result<(), ()> {
        let connection = Connection {
            quic_conn: MockQuicConnection,
        };

        let req = request_builder::Request::builder()
            .method(Method::GET)
            .path("/")
            .schema("https")
            .authority("example.com")
            .body(());

        let mut resp = connection.send_request(req).await?;
        let _resp = resp.bytes().await?;

        let (mut req, mut resp) = connection
            .request((Method::GET, "https://api.reimu.pilot.genmeta.net"))
            .await?;
        req.data(b"hello, world").await?.close().await.unwrap();

        let mut resp_data = vec![];
        resp.header().await?;
        resp.read_to_end(&mut resp_data).await.unwrap();

        Ok(())
    }
}
