use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures::{Sink, Stream};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    codec::{
        error::{DecodeStreamError, EncodeStreamError},
        util::{DecodeFrom, EncodeInto},
    },
    quic::{CancelStream, GetStreamId, StopSending},
    varint::VarInt,
};

pin_project_lite::pin_project! {
    /// Unidirectional streams, in either direction, are used for a range of
    /// purposes. The purpose is indicated by a stream type, which is sent as
    /// a variable-length integer at the start of the stream. The format and
    /// structure of data that follows this integer is determined by the
    /// stream type.
    ///
    /// ``` ignore
    /// Unidirectional Stream Header {
    ///   Stream Type (i),
    /// }
    /// ```
    pub struct UnidirectionalStream<S: ?Sized> {
        r#type: VarInt,
        #[pin]
        stream: S,
    }
}

impl<S: AsyncBufRead + Unpin> DecodeFrom<S> for UnidirectionalStream<S> {
    async fn decode_from(mut stream: S) -> Result<Self, DecodeStreamError> {
        let r#type = VarInt::decode_from(&mut stream).await?;
        Ok(UnidirectionalStream { r#type, stream })
    }
}

impl UnidirectionalStream<()> {
    /// A control stream is indicated by a stream type of 0x00. Data on this
    ///  stream consists of HTTP/3 frames, as defined in Section 7.2.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-control-streams
    pub const CONTROL_STREAM_TYPE: VarInt = VarInt::from_u32(0x00);

    /// A push stream is indicated by a stream type of 0x01, followed by the
    /// push ID of the promise that it fulfills, encoded as a variable-length
    /// integer. The remaining data on this stream consists of HTTP/3 frames,
    /// as defined in Section 7.2, and fulfills a promised server push by
    /// zero or more interim HTTP responses followed by a single final HTTP
    /// response, as defined in Section 4.1. Server push and push IDs are
    /// described in Section 4.6.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-push-streams
    pub const PUSH_STREAM_TYPE: VarInt = VarInt::from_u32(0x01);

    /// An encoder stream is a unidirectional stream of type 0x02. It
    /// carries an unframed sequence of encoder instructions from encoder
    /// to decoder.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-4.2-2.1
    pub const QPACK_ENCODER_STREAM_TYPE: VarInt = VarInt::from_u32(0x02);

    /// A decoder stream is a unidirectional stream of type 0x03. It
    /// carries an unframed sequence of decoder instructions from decoder
    /// to encoder.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-4.2-2.2
    pub const QPACK_DECODER_STREAM_TYPE: VarInt = VarInt::from_u32(0x03);
}

impl<S: ?Sized> UnidirectionalStream<S> {
    pub async fn new(r#type: VarInt, mut stream: S) -> Result<Self, EncodeStreamError>
    where
        S: AsyncWrite + Unpin + Sized,
    {
        r#type.encode_into(&mut stream).await.unwrap();
        stream.flush().await?;
        Ok(Self { r#type, stream })
    }

    pub const fn r#type(&self) -> VarInt {
        self.r#type
    }

    /// Stream types of the format 0x1f * N + 0x21 for non-negative integer
    /// values of N are reserved to exercise the requirement that unknown
    /// types be ignored. These streams have no semantics, and they can be
    /// sent when application-layer padding is desired. They MAY also be sent
    /// on connections where no data is currently being transferred.
    /// Endpoints MUST NOT consider these streams to have any meaning upon
    /// receipt.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-reserved-stream-types
    pub const fn is_reserved_stream(&self) -> bool {
        (self.r#type.into_inner() >= 0x21) && (self.r#type.into_inner() - 0x21).is_multiple_of(0x1f)
    }

    pub fn into_inner(self) -> S
    where
        S: Sized,
    {
        self.stream
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for UnidirectionalStream<S> {
    fn stream_id(&self) -> u64 {
        self.stream.stream_id()
    }
}

impl<S: StopSending + ?Sized> StopSending for UnidirectionalStream<S> {
    fn stop_sending(self: Pin<&mut Self>, code: u64) {
        self.project().stream.stop_sending(code);
    }
}

impl<R: AsyncRead + ?Sized> AsyncRead for UnidirectionalStream<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl<R: AsyncBufRead + ?Sized> AsyncBufRead for UnidirectionalStream<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.project().stream.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.project().stream.consume(amt);
    }
}

impl<S: Stream + ?Sized> Stream for UnidirectionalStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().stream.poll_next(cx)
    }
}

impl<S: CancelStream + ?Sized> CancelStream for UnidirectionalStream<S> {
    fn cancel(self: Pin<&mut Self>, code: u64) {
        self.project().stream.cancel(code)
    }
}

impl<W: AsyncWrite + ?Sized> AsyncWrite for UnidirectionalStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }
}

impl<T, S: Sink<T> + ?Sized> Sink<T> for UnidirectionalStream<S> {
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.project().stream.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_close(cx)
    }
}

pin_project_lite::pin_project! {
    /// A stream that is might be not yet ready, represented by a future that
    /// resolves to the stream.
    #[project = FutureStreamProj]
    #[project_ref = FutureStreamProjRef]
    pub enum FutureStream<S, F> {
        Stream { #[pin] stream: S },
        Future { #[pin] future: F }
    }
}

impl<S, F> From<F> for FutureStream<S, F> {
    fn from(future: F) -> Self {
        FutureStream::Future { future }
    }
}

impl<S, F> FutureStream<S, F> {
    fn poll_ready<'s>(mut self: Pin<&'s mut Self>, cx: &mut Context<'_>) -> Poll<Pin<&'s mut S>>
    where
        F: Future<Output = S>,
    {
        match self.as_mut().project() {
            FutureStreamProj::Stream { .. } => {
                // as_mut() returns short-lived Pin<&mut Self>, so we need to re-project without as_mut()
                Poll::Ready(self.pin_stream_mut())
            }
            FutureStreamProj::Future { future } => {
                let stream = ready!(future.poll(cx));
                self.set(FutureStream::Stream { stream });
                self.poll_ready(cx)
            }
        }
    }

    fn pin_stream_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        match self.project() {
            FutureStreamProj::Stream { stream } => stream,
            FutureStreamProj::Future { .. } => panic!("Stream not yet resolved"),
        }
    }

    fn stream(&self) -> &S {
        match self {
            Self::Stream { stream } => stream,
            Self::Future { .. } => panic!("Stream not yet resolved"),
        }
    }
}

impl<S: GetStreamId, F> GetStreamId for FutureStream<S, F> {
    fn stream_id(&self) -> u64 {
        self.stream().stream_id()
    }
}

impl<S: StopSending, F> StopSending for FutureStream<S, F> {
    fn stop_sending(self: Pin<&mut Self>, code: u64) {
        self.pin_stream_mut().stop_sending(code);
    }
}

impl<S: AsyncRead, F: Future<Output = S>> AsyncRead for FutureStream<S, F> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_ready(cx)).poll_read(cx, buf)
    }
}

impl<S: AsyncBufRead, F: Future<Output = S>> AsyncBufRead for FutureStream<S, F> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        ready!(self.poll_ready(cx)).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.pin_stream_mut().consume(amt);
    }
}

impl<S: Stream, F: Future<Output = S>> Stream for FutureStream<S, F> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        ready!(self.poll_ready(cx)).poll_next(cx)
    }
}

impl<S: CancelStream, F> CancelStream for FutureStream<S, F> {
    fn cancel(self: Pin<&mut Self>, code: u64) {
        self.pin_stream_mut().cancel(code)
    }
}

impl<S: AsyncWrite, F: Future<Output = S>> AsyncWrite for FutureStream<S, F> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_ready(cx)).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_ready(cx)).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_ready(cx)).poll_shutdown(cx)
    }
}

impl<T, S: Sink<T>, F: Future<Output = S>> Sink<T> for FutureStream<S, F> {
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_ready(cx)).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.pin_stream_mut().start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_ready(cx)).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_ready(cx)).poll_close(cx)
    }
}
