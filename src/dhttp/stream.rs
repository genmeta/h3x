use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, StreamDecodeError},
    connection::StreamError,
    error::H3GeneralProtocolError,
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

impl<S: AsyncRead + Unpin + Send> DecodeFrom<S> for UnidirectionalStream<S> {
    type Error = StreamError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        UnidirectionalStream::accept(stream).await
    }
}

impl UnidirectionalStream<()> {
    /// A push stream is indicated by a stream type of 0x01, followed by the
    /// push ID of the promise that it fulfills, encoded as a variable-length
    /// integer. The remaining data on this stream consists of HTTP/3 frames,
    /// as defined in Section 7.2, and fulfills a promised server push by
    /// zero or more interim HTTP responses followed by a single final HTTP
    /// response, as defined in Section 4.1. Server push and push IDs are
    /// described in Section 4.6.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9114#name-push-streams>
    pub const PUSH_STREAM_TYPE: VarInt = VarInt::from_u32(0x01);
}

impl<S: ?Sized> UnidirectionalStream<S> {
    pub async fn initial(r#type: VarInt, mut stream: S) -> Result<Self, StreamError>
    where
        S: AsyncWrite + Unpin + Sized + Send,
    {
        stream.encode_one(r#type).await?;
        Ok(Self { r#type, stream })
    }

    pub async fn accept(mut stream: S) -> Result<Self, StreamError>
    where
        S: AsyncRead + Unpin + Sized + Send,
    {
        let r#type = stream.decode_one::<VarInt>().await.map_err(|error| {
            StreamDecodeError::from(error)
                .into_stream_error(|error| H3GeneralProtocolError::Decode { source: error }.into())
        })?;
        Ok(UnidirectionalStream { r#type, stream })
    }

    pub fn into_inner(self) -> S
    where
        S: Sized,
    {
        self.stream
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
    /// <https://datatracker.ietf.org/doc/html/rfc9114#name-reserved-stream-types>
    pub const fn is_reserved_stream(&self) -> bool {
        (self.r#type().into_inner() >= 0x21)
            && (self.r#type.into_inner() - 0x21).is_multiple_of(0x1f)
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use futures::{SinkExt, StreamExt, future::poll_fn};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        buflist::BufList,
        codec::{DecodeExt, EncodeExt},
    };

    #[tokio::test]
    async fn initial_writes_stream_type_and_keeps_payload_writable() {
        let stream_type = VarInt::from_u32(0x21);
        let mut stream = UnidirectionalStream::initial(stream_type, BufList::new())
            .await
            .expect("initial stream");

        assert_eq!(stream.r#type(), stream_type);
        assert!(stream.is_reserved_stream());

        stream.write_all(b"payload").await.expect("payload write");
        AsyncWriteExt::flush(&mut stream)
            .await
            .expect("payload flush");
        AsyncWriteExt::shutdown(&mut stream)
            .await
            .expect("payload shutdown");

        let mut inner = stream.into_inner();
        let decoded_type = inner
            .decode_one::<VarInt>()
            .await
            .expect("stream type prefix");
        let mut payload = Vec::new();
        inner
            .read_to_end(&mut payload)
            .await
            .expect("remaining payload");

        assert_eq!(decoded_type, stream_type);
        assert_eq!(payload, b"payload");
    }

    #[tokio::test]
    async fn accept_reads_stream_type_and_leaves_remaining_payload() {
        let stream_type = VarInt::from_u32(0x02);
        let mut payload = BufList::new();
        payload
            .encode_one(stream_type)
            .await
            .expect("stream type encoding");
        payload.write(Bytes::from_static(b"body"));

        let mut stream = UnidirectionalStream::accept(payload)
            .await
            .expect("accepted stream");
        let mut body = Vec::new();
        stream
            .read_to_end(&mut body)
            .await
            .expect("remaining payload");

        assert_eq!(stream.r#type(), stream_type);
        assert!(!stream.is_reserved_stream());
        assert_eq!(body, b"body");
    }

    #[tokio::test]
    async fn decode_ext_uses_unidirectional_accept_path() {
        let stream_type = VarInt::from_u32(0x03);
        let mut payload = BufList::new();
        payload
            .encode_one(stream_type)
            .await
            .expect("stream type encoding");
        payload.write(Bytes::from_static(b"after-type"));

        let mut stream = payload
            .decode::<UnidirectionalStream<_>>()
            .await
            .expect("decoded unidirectional stream");

        assert_eq!(stream.r#type(), stream_type);
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.expect("body");
        assert_eq!(body, b"after-type");
    }

    #[tokio::test]
    async fn accept_rejects_missing_stream_type() {
        let error = UnidirectionalStream::accept(BufList::new())
            .await
            .err()
            .expect("stream type is mandatory");

        assert!(matches!(
            error,
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source },
            } if source.code() == crate::error::Code::H3_GENERAL_PROTOCOL_ERROR
        ));
    }

    #[tokio::test]
    async fn async_buf_read_delegates_fill_and_consume_to_inner_stream() {
        let mut payload = BufList::new();
        payload.write(Bytes::from_static(b"abc"));
        payload.write(Bytes::from_static(b"def"));
        let mut stream = UnidirectionalStream {
            r#type: VarInt::from_u32(0),
            stream: payload,
        };

        assert_eq!(stream.fill_buf().await.expect("fill buf"), b"abc");
        stream.consume(2);
        assert_eq!(
            stream.fill_buf().await.expect("remaining first chunk"),
            b"c"
        );
        stream.consume(1);
        assert_eq!(stream.fill_buf().await.expect("second chunk"), b"def");
        stream.consume(3);
        assert_eq!(stream.fill_buf().await.expect("eof"), b"");
    }

    #[test]
    fn reserved_stream_detection_matches_http3_grease_pattern() {
        for value in [0x21, 0x40, 0x5f, 0x7e] {
            let stream = UnidirectionalStream {
                r#type: VarInt::from_u32(value),
                stream: (),
            };
            assert!(stream.is_reserved_stream(), "{value:#x} is reserved");
        }

        for value in [0x00, 0x20, 0x22, 0x41] {
            let stream = UnidirectionalStream {
                r#type: VarInt::from_u32(value),
                stream: (),
            };
            assert!(!stream.is_reserved_stream(), "{value:#x} is not reserved");
        }
    }

    #[tokio::test]
    async fn stream_and_sink_delegate_to_inner_value() {
        let mut stream = UnidirectionalStream {
            r#type: VarInt::from_u32(0),
            stream: futures::stream::iter([Ok::<_, quic::StreamError>(Bytes::from_static(
                b"chunk",
            ))]),
        };

        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            Bytes::from_static(b"chunk")
        );
        assert!(stream.next().await.is_none());

        let mut sink = UnidirectionalStream {
            r#type: VarInt::from_u32(0),
            stream: futures::sink::drain::<Bytes>(),
        };
        sink.send(Bytes::from_static(b"ignored"))
            .await
            .expect("sink forwards to inner drain");
        sink.close()
            .await
            .expect("sink close forwards to inner drain");
    }

    #[derive(Debug)]
    struct ControlStream {
        stream_id: VarInt,
        stopped: Arc<Mutex<Option<VarInt>>>,
        cancelled: Arc<Mutex<Option<VarInt>>>,
    }

    impl GetStreamId for ControlStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl StopStream for ControlStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            *self.stopped.lock().expect("stop state poisoned") = Some(code);
            Poll::Ready(Ok(()))
        }
    }

    impl CancelStream for ControlStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            *self.cancelled.lock().expect("cancel state poisoned") = Some(code);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn control_traits_delegate_to_inner_stream() {
        let stopped = Arc::new(Mutex::new(None));
        let cancelled = Arc::new(Mutex::new(None));
        let stream_id = VarInt::from_u32(17);
        let stop_code = VarInt::from_u32(23);
        let cancel_code = VarInt::from_u32(29);
        let mut stream = UnidirectionalStream {
            r#type: VarInt::from_u32(0),
            stream: ControlStream {
                stream_id,
                stopped: stopped.clone(),
                cancelled: cancelled.clone(),
            },
        };

        assert_eq!(
            poll_fn(|cx| Pin::new(&mut stream).poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );
        poll_fn(|cx| Pin::new(&mut stream).poll_stop(cx, stop_code))
            .await
            .expect("stop forwarded");
        poll_fn(|cx| Pin::new(&mut stream).poll_cancel(cx, cancel_code))
            .await
            .expect("cancel forwarded");

        assert_eq!(
            *stopped.lock().expect("stop state poisoned"),
            Some(stop_code)
        );
        assert_eq!(
            *cancelled.lock().expect("cancel state poisoned"),
            Some(cancel_code)
        );
    }
}
