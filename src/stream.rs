use std::{
    fmt::Debug,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures::{Sink, Stream};
use snafu::Snafu;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    codec::{
        error::{DecodeStreamError, EncodeStreamError},
        util::{DecodeFrom, EncodeInto},
    },
    error::{Code, H3CriticalStreamClosed, HasErrorCode, StreamError},
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
        r#type.encode_into(&mut stream).await?;
        stream.flush().await?;
        Ok(Self { r#type, stream })
    }

    pub fn into_inner(self) -> S
    where
        S: Sized,
    {
        self.stream
    }

    pub async fn new_qpack_encoder_stream(stream: S) -> Result<Self, EncodeStreamError>
    where
        S: AsyncWrite + Unpin + Sized,
    {
        Self::new(UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE, stream)
            .await
            .map_err(|error| {
                error.map_stream_reset(|_| H3CriticalStreamClosed::QPackEncoder.into())
            })
    }

    pub const fn is_qpack_encoder_stream(&self) -> bool {
        self.r#type.into_inner() == UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE.into_inner()
    }

    pub async fn new_qpack_decoder_stream(stream: S) -> Result<Self, EncodeStreamError>
    where
        S: AsyncWrite + Unpin + Sized,
    {
        Self::new(UnidirectionalStream::QPACK_DECODER_STREAM_TYPE, stream)
            .await
            .map_err(|error| {
                error.map_stream_reset(|_| H3CriticalStreamClosed::QPackDecoder.into())
            })
    }

    pub const fn is_qpack_decoder_stream(&self) -> bool {
        self.r#type.into_inner() == UnidirectionalStream::QPACK_DECODER_STREAM_TYPE.into_inner()
    }

    pub async fn new_control_stream(stream: S) -> Result<Self, EncodeStreamError>
    where
        S: AsyncWrite + Unpin + Sized,
    {
        Self::new(UnidirectionalStream::CONTROL_STREAM_TYPE, stream)
            .await
            .map_err(|error| error.map_stream_reset(|_| H3CriticalStreamClosed::Control.into()))
    }

    pub const fn is_control_stream(&self) -> bool {
        self.r#type.into_inner() == UnidirectionalStream::CONTROL_STREAM_TYPE.into_inner()
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
}

#[derive(Debug, Snafu, Clone, Copy)]
pub enum H3StreamCreationError {
    #[snafu(display("Control stream already exists"))]
    DuplicateControlStream,
    #[snafu(display("QPack encoder stream already exists"))]
    DuplicateQpackEncoderStream,
    #[snafu(display("QPack decoder stream already exists"))]
    DuplicateQpackDecoderStream,
}

impl HasErrorCode for H3StreamCreationError {
    fn code(&self) -> Code {
        Code::H3_STREAM_CREATION_ERROR
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for UnidirectionalStream<S> {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        self.project().stream.poll_stream_id(cx)
    }
}

impl<S: StopSending + ?Sized> StopSending for UnidirectionalStream<S> {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        self.project().stream.poll_stop_sending(cx, code)
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
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        self.project().stream.poll_cancel(cx, code)
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
    /// A lazily opened stream.
    #[project = FutureStreamProj]
    #[project_ref = FutureStreamProjRef]
    pub enum TryFutureStream<S, E, F> {
        Future { #[pin] future: F },
        Stream { #[pin] stream: S },
        Error { error: E },
    }
}

impl<S, E, F: Future<Output = Result<S, E>>> From<F> for TryFutureStream<S, E, F> {
    fn from(future: F) -> Self {
        TryFutureStream::Future { future }
    }
}

impl<S, E, F> TryFutureStream<S, E, F> {
    fn poll_try_stream<'s>(
        mut self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Pin<&'s mut S>, E>>
    where
        F: Future<Output = Result<S, E>>,
        E: Clone,
    {
        match self.as_mut().project() {
            FutureStreamProj::Future { future, .. } => {
                match ready!(future.poll(cx)) {
                    Ok(stream) => self.set(TryFutureStream::Stream { stream }),
                    Err(error) => self.set(TryFutureStream::Error { error }),
                };
                self.poll_try_stream(cx)
            }
            FutureStreamProj::Stream { .. } | FutureStreamProj::Error { .. } => {
                // as_mut() returns short-lived Pin<&mut Self>, so we need to re-project without as_mut()
                Poll::Ready(self.pin_stream_mut().unwrap())
            }
        }
    }

    fn pin_stream_mut(self: Pin<&mut Self>) -> Option<Result<Pin<&mut S>, E>>
    where
        E: Clone,
    {
        match self.project() {
            FutureStreamProj::Future { .. } => None,
            FutureStreamProj::Stream { stream } => Some(Ok(stream)),
            FutureStreamProj::Error { error } => Some(Err(error.clone())),
        }
    }
}

impl<S, E, F> GetStreamId for TryFutureStream<S, E, F>
where
    S: GetStreamId,
    E: Clone,
    StreamError: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        ready!(self.poll_try_stream(cx)?).poll_stream_id(cx)
    }
}

impl<S, E, F> StopSending for TryFutureStream<S, E, F>
where
    S: StopSending,
    E: Clone,
    StreamError: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        ready!(self.poll_try_stream(cx)?).poll_stop_sending(cx, code)
    }
}

impl<S, E, F> AsyncRead for TryFutureStream<S, E, F>
where
    S: AsyncRead,
    E: Clone,
    io::Error: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_try_stream(cx)?).poll_read(cx, buf)
    }
}

impl<S, E, F> AsyncBufRead for TryFutureStream<S, E, F>
where
    S: AsyncBufRead,
    E: Clone + Debug,
    io::Error: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        ready!(self.poll_try_stream(cx)?).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.pin_stream_mut()
            .expect("consume before read")
            .expect("consume on error")
            .consume(amt);
    }
}

impl<S, E, F, T, SE> Stream for TryFutureStream<S, E, F>
where
    S: Stream<Item = Result<T, SE>>,
    E: Clone,
    SE: From<E>,
    F: Future<Output = Result<S, E>>,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        ready!(self.poll_try_stream(cx)?).poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<S, E, F> CancelStream for TryFutureStream<S, E, F>
where
    S: CancelStream,
    E: Clone,
    StreamError: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        ready!(self.poll_try_stream(cx)?).poll_cancel(cx, code)
    }
}

impl<S, E, F> AsyncWrite for TryFutureStream<S, E, F>
where
    S: AsyncWrite,
    E: Clone,
    io::Error: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_try_stream(cx)?).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_try_stream(cx)?).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_try_stream(cx)?).poll_shutdown(cx)
    }
}

impl<E, S, F, T> Sink<T> for TryFutureStream<S, E, F>
where
    S: Sink<T>,
    E: Clone,
    S::Error: From<E>,
    F: Future<Output = Result<S, E>>,
{
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        ready!(self.poll_try_stream(cx)?).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), S::Error> {
        self.pin_stream_mut()
            .expect("start_send before poll_ready completed")?
            .start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        ready!(self.poll_try_stream(cx)?).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        ready!(self.poll_try_stream(cx)?).poll_close(cx)
    }
}

// pin_project_lite::pin_project! {
//     /// A critical stream is a stream that, upon encountering an I/O error,
//     /// causes the connection to be closed with H3_CLOSED_CRITICAL_STREAM.
//     pub struct CriticalStream<S: ?Sized> {
//         #[pin]
//         stream: S,
//     }
// }

// impl<S> CriticalStream<S> {
//     pub const fn new(stream: S) -> Self {
//         Self { stream }
//     }
// }

// impl<S: ?Sized> CriticalStream<S> {
//     fn r#try<'s, T: 's, E>(
//         self: Pin<&'s mut Self>,
//         f: impl FnOnce(Pin<&'s mut S>) -> Result<T, E>,
//     ) -> Result<T, E>
//     where
//         E: TryInto<StreamError, Error = E> + From<StreamError> + From<Code>,
//     {
//         let project = self.project();
//         let code = Code::H3_CLOSED_CRITICAL_STREAM;
//         f(project.stream).map_err(|error| match error.try_into() {
//             Ok(stream_error) => match stream_error {
//                 StreamError::Reset { .. } => E::from(code),
//                 stream_error => E::from(stream_error),
//             },
//             Err(error) => error,
//         })
//     }

//     fn poll_try<'s, T: 's, E: Error + Send + Sync + 'static>(
//         self: Pin<&'s mut Self>,
//         cx: &mut Context<'_>,
//         f: impl FnOnce(Pin<&'s mut S>, &mut Context<'_>) -> Poll<Result<T, StreamError>>,
//     ) -> Poll<Result<T, StreamError>> {
//         let project = self.project();
//         let code = Code::H3_CLOSED_CRITICAL_STREAM;
//         f(project.stream, cx).map_err(|error| match error {
//             StreamError::Reset { .. } => StreamError::Connection {
//                 source: ApplicationError::from(code).into(),
//             },
//             error => error,
//         })
//     }

//     fn poll_try_io<'s, T: 's>(
//         self: Pin<&'s mut Self>,
//         cx: &mut Context<'_>,
//         f: impl FnOnce(Pin<&'s mut S>, &mut Context<'_>) -> Poll<io::Result<T>>,
//     ) -> Poll<io::Result<T>> {
//         self.poll_try(cx, |stream, cx| f(stream, cx).map_err(StreamError::from))
//             .map_err(io::Error::other)
//     }
// }

// impl<C: QuicConnect + Unpin, S: GetStreamId + ?Sized> GetStreamId for CriticalStream<C, S> {
//     fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<u64, StreamError>> {
//         self.poll_try(cx, |stream, cx| stream.poll_stream_id(cx))
//     }
// }

// impl<C: QuicConnect + Unpin, S: StopSending + ?Sized> StopSending for CriticalStream<C, S> {
//     fn poll_stop_sending(
//         self: Pin<&mut Self>,
//         cx: &mut Context,
//         code: VarInt,
//     ) -> Poll<Result<(), StreamError>> {
//         self.poll_try(cx, |stream, cx| stream.poll_stop_sending(cx, code))
//     }
// }

// impl<C: QuicConnect + Unpin, S: AsyncRead + ?Sized> AsyncRead for CriticalStream<C, S> {
//     fn poll_read(
//         self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &mut ReadBuf<'_>,
//     ) -> Poll<io::Result<()>> {
//         self.poll_try_io(cx, |stream, cx| stream.poll_read(cx, buf))
//     }
// }

// impl<C: QuicConnect + Unpin, S: AsyncBufRead + ?Sized> AsyncBufRead for CriticalStream<C, S> {
//     fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
//         self.poll_try_io(cx, |stream, cx| stream.poll_fill_buf(cx))
//     }

//     fn consume(self: Pin<&mut Self>, amt: usize) {
//         self.project().stream.consume(amt);
//     }
// }

// impl<T, E, C, S> Stream for CriticalStream<C, S>
// where
//     E: Error + Send + Sync + 'static,
//     C: QuicConnect + Unpin,
//     S: Stream<Item = Result<T, E>> + ?Sized,
// {
//     type Item = Result<T, ErrorWithCode>;

//     fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         self.poll_try(cx, |stream, cx| {
//             stream.poll_next(cx).map(|option| option.transpose())
//         })
//         .map(|result| result.transpose())
//     }
// }

// impl<C: QuicConnect + Unpin, S: CancelStream + ?Sized> CancelStream for CriticalStream<C, S> {
//     fn poll_cancel(self: Pin<&mut Self>, code: VarInt) {
//         self.project().stream.poll_cancel(code)
//     }
// }

// impl<C: QuicConnect + Unpin, S: AsyncWrite + ?Sized> AsyncWrite for CriticalStream<C, S> {
//     fn poll_write(
//         self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &[u8],
//     ) -> Poll<io::Result<usize>> {
//         self.poll_try_io(cx, |stream, cx| stream.poll_write(cx, buf))
//     }

//     fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
//         self.poll_try_io(cx, |stream, cx| stream.poll_flush(cx))
//     }

//     fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
//         self.poll_try_io(cx, |stream, cx| stream.poll_shutdown(cx))
//     }
// }

// impl<T, C, S> Sink<T> for CriticalStream<C, S>
// where
//     C: QuicConnect + Unpin,
//     S: Sink<T, Error: Error + Send + Sync + 'static>,
// {
//     type Error = ErrorWithCode;

//     fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         self.poll_try(cx, |stream, cx| stream.poll_ready(cx))
//     }

//     fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
//         self.r#try(|stream| stream.start_send(item))
//     }

//     fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         self.poll_try(cx, |stream, cx| stream.poll_flush(cx))
//     }

//     fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         self.poll_try(cx, |stream, cx| stream.poll_close(cx))
//     }
// }
