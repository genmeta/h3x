use std::{
    fmt::Debug,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};
use snafu::Snafu;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    codec::{Decode, DecodeExt, DecodeStreamError, EncodeExt},
    connection::StreamError,
    error::{Code, H3CriticalStreamClosed, HasErrorCode},
    quic::{self, CancelStream, GetStreamId, StopStream},
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

impl<S: AsyncRead + Unpin> Decode<UnidirectionalStream<S>> for S {
    type Error = StreamError;

    async fn decode(mut self) -> Result<UnidirectionalStream<S>, Self::Error> {
        let r#type = self.decode_one::<VarInt>().await.map_err(|error| {
            DecodeStreamError::from(error)
                .map_decode_error(|error| Code::H3_GENERAL_PROTOCOL_ERROR.with(error).into())
        })?;
        Ok(UnidirectionalStream {
            r#type,
            stream: self,
        })
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
    pub async fn new(r#type: VarInt, mut stream: S) -> Result<Self, StreamError>
    where
        S: AsyncWrite + Unpin + Sized,
    {
        stream.encode_one(r#type).await?;
        Ok(Self { r#type, stream })
    }

    pub fn into_inner(self) -> S
    where
        S: Sized,
    {
        self.stream
    }

    pub async fn new_qpack_encoder_stream(stream: S) -> Result<Self, StreamError>
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

    pub async fn new_qpack_decoder_stream(stream: S) -> Result<Self, StreamError>
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

    pub async fn new_control_stream(stream: S) -> Result<Self, StreamError>
    where
        S: AsyncWrite + Unpin + Sized,
    {
        Self::new(UnidirectionalStream::CONTROL_STREAM_TYPE, stream)
            .await
            .map_err(|error| error.map_stream_reset(|_| H3CriticalStreamClosed::Control.into()))
    }

    pub const fn is_control_stream(&self) -> bool {
        self.r#type().into_inner() == UnidirectionalStream::CONTROL_STREAM_TYPE.into_inner()
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
        (self.r#type().into_inner() >= 0x21)
            && (self.r#type.into_inner() - 0x21).is_multiple_of(0x1f)
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Snafu, Clone, Copy)]
pub enum H3StreamCreationError {
    #[snafu(display("control stream already exists"))]
    DuplicateControlStream,
    #[snafu(display("qPack encoder stream already exists"))]
    DuplicateQpackEncoderStream,
    #[snafu(display("qPack decoder stream already exists"))]
    DuplicateQpackDecoderStream,
}

impl HasErrorCode for H3StreamCreationError {
    fn code(&self) -> Code {
        Code::H3_STREAM_CREATION_ERROR
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for UnidirectionalStream<S> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.project().stream.poll_stream_id(cx)
    }
}

impl<S: StopStream + ?Sized> StopStream for UnidirectionalStream<S> {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.project().stream.poll_stop(cx, code)
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
    ) -> Poll<Result<(), quic::StreamError>> {
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
