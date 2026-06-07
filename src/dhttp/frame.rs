pub mod stream;

use std::{
    pin::{Pin, pin},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{Sink, SinkExt, Stream, TryStream, TryStreamExt};
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    buflist::BufList,
    codec::{
        DecodeExt, DecodeFrom, EncodeError, EncodeExt, EncodeInto, FixedLengthReader,
        StreamDecodeError, StreamEncodeError, StreamReader,
    },
    connection::StreamError,
    error::H3FrameDecodeError,
    quic::{self, GetStreamId, StopStream},
    varint::{self, VARINT_MAX, VarInt},
};

pin_project_lite::pin_project! {
    /// All frames have the following format:
    ///
    /// ``` plaintext
    /// HTTP/3 Frame Format {
    ///   Type (i),
    ///   Length (i),
    ///   Frame Payload (..),
    /// }
    /// ```
    ///
    /// Frame Payload has a generic type `P`, it could be:
    /// ### A buffer that implements [`Buf`]
    ///
    /// Crate such a frame with [`Frame::new`], encode it to the stream with [`Frame::encode`].
    ///
    /// ### A [Stream] of bytes
    ///
    /// You can decode a frame on the stream by calling [`Frame::decode`],
    /// and then you can asynchronously read the frame payload using [`AsyncRead`], [`AsyncBufRead`] or [`Stream`]
    ///
    /// A maximum of the frame length in bytes can be retrieved from the frame;
    /// if the amount of data in the stream is less than the frame length, reading the frame will result in an error.
    ///
    /// Once the payload of the current frame has been fully read,
    /// calling [`Frame::decode_next`] will retrieve the next new frame in the stream.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Frame<P: ?Sized> {
        r#type: VarInt,
        length: VarInt,
        #[pin]
        payload: P,
    }
}

impl Frame<()> {
    pub const DATA_FRAME_TYPE: VarInt = VarInt::from_u32(0x00);
    pub const HEADERS_FRAME_TYPE: VarInt = VarInt::from_u32(0x01);
    pub const CANCEL_PUSH_FRAME_TYPE: VarInt = VarInt::from_u32(0x03);
    pub const SETTINGS_FRAME_TYPE: VarInt = VarInt::from_u32(0x04);
    pub const PUSH_PROMISE_FRAME_TYPE: VarInt = VarInt::from_u32(0x05);
    pub const GOAWAY_FRAME_TYPE: VarInt = VarInt::from_u32(0x07);
    pub const MAX_PUSH_ID_FRAME_TYPE: VarInt = VarInt::from_u32(0x0d);
}

impl<P: ?Sized> Frame<P> {
    /// Create a new frame.
    ///
    /// Length is calculated from the payload
    pub fn new(r#type: VarInt, payload: P) -> Result<Self, varint::err::Overflow>
    where
        P: Buf + Sized,
    {
        let length = VarInt::try_from(payload.remaining())?;
        Ok(Self {
            r#type,
            length,
            payload,
        })
    }

    pub const fn r#type(&self) -> VarInt {
        self.r#type
    }

    /// Frame types of the format 0x1f * N + 0x21 for non-negative integer
    /// values of N are reserved to exercise the requirement that unknown
    /// types be ignored (Section 9). These frames have no semantics, and
    /// they MAY be sent on any stream where frames are allowed to be sent.
    /// This enables their use for application-layer padding. Endpoints MUST
    /// NOT consider these frames to have any meaning upon receipt.
    ///
    /// The payload and length of the frames are selected in any manner the
    /// implementation chooses.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9114#name-reserved-frame-types>
    pub const fn is_reserved_frame(&self) -> bool {
        (self.r#type.into_inner() >= 0x21) && (self.r#type.into_inner() - 0x21).is_multiple_of(0x1f)
    }

    pub const fn length(&self) -> VarInt {
        self.length
    }

    pub const fn payload(&self) -> &P {
        &self.payload
    }

    pub fn into_payload(self) -> P
    where
        P: Sized,
    {
        self.payload
    }

    pub fn map<U>(self, map: impl FnOnce(P) -> U) -> Frame<U>
    where
        P: Sized,
    {
        Frame {
            r#type: self.r#type,
            length: self.length,
            payload: map(self.payload),
        }
    }
}

impl<P: AsyncWrite + ?Sized> AsyncWrite for Frame<P> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let project = self.project();
        match project.length.into_inner().checked_add(buf.len() as u64) {
            Some(new_length) if new_length > VARINT_MAX => {
                return Poll::Ready(Err(EncodeError::FramePayloadTooLarge.into()));
            }
            Some(new_length) => {
                *project.length =
                    VarInt::from_u64(new_length).expect("length checked to be within VarInt range");
            }
            None => return Poll::Ready(Err(EncodeError::FramePayloadTooLarge.into())),
        }

        project.payload.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().payload.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().payload.poll_shutdown(cx)
    }
}

impl<P: Sink<B> + ?Sized, B: Buf> Sink<B> for Frame<P>
where
    StreamEncodeError: From<P::Error>,
{
    type Error = StreamEncodeError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .payload
            .poll_ready(cx)
            .map_err(StreamEncodeError::from)
    }

    fn start_send(self: Pin<&mut Self>, item: B) -> Result<(), Self::Error> {
        let project = self.project();
        let len = item.remaining() as u64;
        match project.length.into_inner().checked_add(len) {
            Some(new_length) if new_length > VARINT_MAX => {
                return Err(EncodeError::FramePayloadTooLarge.into());
            }
            Some(new_length) => {
                *project.length =
                    VarInt::from_u64(new_length).expect("length checked to be within VarInt range");
            }
            None => return Err(EncodeError::FramePayloadTooLarge.into()),
        }
        project.payload.start_send(item)?;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .payload
            .poll_flush(cx)
            .map_err(StreamEncodeError::from)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .payload
            .poll_close(cx)
            .map_err(StreamEncodeError::from)
    }
}

impl<P: Buf + Send, S: AsyncWrite + Sink<Bytes, Error = quic::StreamError> + Send> EncodeInto<S>
    for Frame<P>
{
    type Output = ();

    type Error = quic::StreamError;

    async fn encode_into(self, stream: S) -> Result<Self::Output, Self::Error> {
        let Frame {
            r#type,
            length,
            mut payload,
        } = self;
        let mut stream = pin!(stream);
        stream.as_mut().encode(r#type).await?;
        stream.as_mut().encode(length).await?;
        while payload.has_remaining() {
            let bytes = payload.copy_to_bytes(payload.chunk().len());
            stream.as_mut().feed(bytes).await?;
        }
        stream.as_mut().flush().await?;
        Ok(())
    }
}

impl<P1, P> DecodeFrom<Frame<P>> for Frame<P1>
where
    P1: DecodeFrom<P> + Send,
    P: Send,
{
    type Error = <P1 as DecodeFrom<P>>::Error;

    async fn decode_from(stream: Frame<P>) -> Result<Self, Self::Error> {
        let Frame {
            r#type,
            length,
            payload,
        } = stream;
        let payload = P1::decode_from(payload).await?;
        Ok(Frame {
            r#type,
            length,
            payload,
        })
    }
}

impl<S> DecodeFrom<&mut StreamReader<S>> for Frame<BufList>
where
    S: TryStream<Ok = Bytes, Error = quic::StreamError> + Unpin + Send,
{
    type Error = StreamError;

    async fn decode_from(stream: &mut StreamReader<S>) -> Result<Self, Self::Error> {
        let decode = async move {
            let r#type = stream.decode_one::<VarInt>().await?;
            let length = stream.decode_one::<VarInt>().await?;

            let mut payload = BufList::new();
            let mut reader = FixedLengthReader::new(stream, length.into_inner());
            while let Some(bytes) = reader.try_next().await? {
                payload.write(bytes);
            }
            Ok(Frame {
                r#type,
                length,
                payload,
            })
        };

        decode.await.map_err(|error: StreamDecodeError| {
            error.into_stream_error(|decode_error| {
                H3FrameDecodeError {
                    source: decode_error,
                }
                .into()
            })
        })
    }
}

impl<P: AsyncRead + ?Sized> AsyncRead for Frame<P> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().payload.poll_read(cx, buf)
    }
}

impl<P: AsyncBufRead + ?Sized> AsyncBufRead for Frame<P> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.project().payload.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.project().payload.consume(amt);
    }
}

impl<P: TryStream<Ok = Bytes, Error = StreamDecodeError> + ?Sized> Stream for Frame<P> {
    type Item = Result<Bytes, StreamDecodeError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().payload.try_poll_next(cx)
    }
}

impl<P: GetStreamId + ?Sized> GetStreamId for Frame<P> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.project().payload.poll_stream_id(cx)
    }
}

impl<P: StopStream + ?Sized> StopStream for Frame<P> {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.project().payload.poll_stop(cx, code)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use futures::{
        Sink, SinkExt,
        future::poll_fn,
        stream::{self, Stream, StreamExt},
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
        time::timeout,
    };
    use tracing::Instrument;

    use super::*;
    use crate::{
        buflist::BufList,
        codec::{
            DecodeError, DecodeExt, DecodeFrom, EncodeError, EncodeExt, SinkWriter,
            StreamDecodeError,
        },
        dhttp::frame::stream::FrameStream,
        error::{Code, H3FrameDecodeError},
        varint::VARINT_MAX,
    };

    fn to_pre_byte_stream(
        data: impl IntoIterator<Item = u8>,
    ) -> impl Stream<Item = Result<Bytes, quic::StreamError>> {
        stream::iter(
            data.into_iter()
                .map(|byte| vec![byte])
                .map(Bytes::from_owner)
                .map(Ok),
        )
    }

    #[derive(Debug, Default, Clone)]
    struct SinkRecorder {
        chunks: Arc<Mutex<Vec<Bytes>>>,
    }

    impl SinkRecorder {
        fn new() -> (Self, Arc<Mutex<Vec<Bytes>>>) {
            let chunks = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    chunks: chunks.clone(),
                },
                chunks,
            )
        }
    }

    impl futures::Sink<Bytes> for SinkRecorder {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.chunks.lock().expect("chunks lock poisoned").push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct FailingEncodeStream {
        reset_code: VarInt,
        fail_write_at: Option<usize>,
        fail_start_send: bool,
        write_calls: usize,
    }

    impl FailingEncodeStream {
        fn fail_write_at(call: usize, reset_code: VarInt) -> Self {
            Self {
                reset_code,
                fail_write_at: Some(call),
                fail_start_send: false,
                write_calls: 0,
            }
        }

        fn fail_start_send(reset_code: VarInt) -> Self {
            Self {
                reset_code,
                fail_write_at: None,
                fail_start_send: true,
                write_calls: 0,
            }
        }

        fn reset(&self) -> quic::StreamError {
            quic::StreamError::Reset {
                code: self.reset_code,
            }
        }
    }

    impl AsyncWrite for FailingEncodeStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.write_calls += 1;
            if this.fail_write_at == Some(this.write_calls) {
                return Poll::Ready(Err(io::Error::from(this.reset())));
            }
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for FailingEncodeStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            if self.fail_start_send {
                return Err(self.reset());
            }
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CapturedPayload(Vec<u8>);

    impl DecodeFrom<BufList> for CapturedPayload {
        type Error = StreamDecodeError;

        async fn decode_from(mut stream: BufList) -> Result<Self, Self::Error> {
            let mut bytes = Vec::new();
            while stream.has_remaining() {
                let chunk = stream.chunk();
                bytes.extend_from_slice(chunk);
                stream.advance(chunk.len());
            }
            Ok(Self(bytes))
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[derive(Debug)]
    struct HugeBuf;

    #[cfg(target_pointer_width = "64")]
    impl bytes::Buf for HugeBuf {
        fn remaining(&self) -> usize {
            VARINT_MAX as usize + 1
        }

        fn chunk(&self) -> &[u8] {
            &[]
        }

        fn advance(&mut self, _cnt: usize) {}
    }

    #[test]
    fn new_frame() {
        Frame::new(Frame::DATA_FRAME_TYPE, Bytes::new()).unwrap();
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn new_rejects_payload_larger_than_varint() {
        let error = Frame::new(Frame::DATA_FRAME_TYPE, HugeBuf)
            .expect_err("frame payload length must fit in varint");

        assert_eq!(
            error.to_string(),
            format!(
                "value({}) too large for varint encoding",
                VARINT_MAX as u128 + 1
            )
        );
    }

    #[test]
    fn known_frame_type_constants() {
        assert_eq!(Frame::DATA_FRAME_TYPE, VarInt::from_u32(0x00));
        assert_eq!(Frame::HEADERS_FRAME_TYPE, VarInt::from_u32(0x01));
        assert_eq!(Frame::CANCEL_PUSH_FRAME_TYPE, VarInt::from_u32(0x03));
        assert_eq!(Frame::SETTINGS_FRAME_TYPE, VarInt::from_u32(0x04));
        assert_eq!(Frame::PUSH_PROMISE_FRAME_TYPE, VarInt::from_u32(0x05));
        assert_eq!(Frame::GOAWAY_FRAME_TYPE, VarInt::from_u32(0x07));
        assert_eq!(Frame::MAX_PUSH_ID_FRAME_TYPE, VarInt::from_u32(0x0d));
    }

    #[test]
    fn reserved_frame_type_detection() {
        let non_reserved = Frame::new(VarInt::from_u32(0x1f), Bytes::new()).unwrap();
        assert!(!non_reserved.is_reserved_frame());

        for i in 0u64..3 {
            let frame_type = 0x21 + (i * 0x1f);
            let frame = Frame::new(
                VarInt::from_u64(frame_type).expect("frame type in range"),
                Bytes::new(),
            )
            .unwrap();
            assert!(frame.is_reserved_frame());
            assert_ne!(frame.r#type(), Frame::DATA_FRAME_TYPE);
        }

        assert!(
            !Frame::new(
                VarInt::from_u64(0x20).expect("frame type in range"),
                Bytes::new()
            )
            .unwrap()
            .is_reserved_frame()
        );
    }

    #[test]
    fn map_preserves_frame_meta() {
        let frame = Frame::new(Frame::HEADERS_FRAME_TYPE, Bytes::from_static(b"hello")).unwrap();
        let mapped = frame.map(|payload| payload.len() * 2);
        assert_eq!(mapped.r#type(), Frame::HEADERS_FRAME_TYPE);
        assert_eq!(mapped.length().into_inner(), 5);
        assert_eq!(mapped.into_payload(), 10);
    }

    #[tokio::test]
    async fn async_write_updates_length_and_delegates_io() {
        let (payload, mut reader) = tokio::io::duplex(64);
        let mut frame = Frame {
            r#type: Frame::DATA_FRAME_TYPE,
            length: VarInt::from_u32(0),
            payload,
        };

        frame.write_all(b"abc").await.expect("payload write");
        assert_eq!(frame.length().into_inner(), 3);
        AsyncWriteExt::flush(&mut frame)
            .await
            .expect("payload flush");
        AsyncWriteExt::shutdown(&mut frame)
            .await
            .expect("payload shutdown");

        let mut payload = Vec::new();
        reader
            .read_to_end(&mut payload)
            .await
            .expect("payload forwarded");
        assert_eq!(payload, b"abc");
    }

    #[tokio::test]
    async fn async_write_rejects_frame_payload_overflow() {
        let payload = tokio::io::sink();
        let mut frame = Frame {
            r#type: Frame::DATA_FRAME_TYPE,
            length: VarInt::MAX,
            payload,
        };

        let error = frame
            .write_all(b"x")
            .await
            .expect_err("payload beyond varint max is invalid");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(matches!(
            EncodeError::try_from(error),
            Ok(EncodeError::FramePayloadTooLarge)
        ));
    }

    #[tokio::test]
    async fn async_buf_read_delegates_to_payload() {
        let mut payload = BufList::new();
        payload.write(Bytes::from_static(b"abc"));
        let mut frame = Frame::new(Frame::DATA_FRAME_TYPE, payload).expect("frame");

        assert_eq!(frame.fill_buf().await.expect("fill buf"), b"abc");
        frame.consume(1);
        assert_eq!(frame.fill_buf().await.expect("fill buf"), b"bc");
    }

    #[tokio::test]
    async fn incomplete_type_varint() {
        let mut stream = StreamReader::new(to_pre_byte_stream([0x40]));

        assert!(matches!(
            stream.decode_one::<Frame<_>>().await,
            Err(StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source },
            }) if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn incomplete_length_varint() {
        let mut stream = StreamReader::new(to_pre_byte_stream([0x00, 0x40]));

        assert!(matches!(
            stream.decode_one::<Frame<_>>().await,
            Err(StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source },
            }) if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn incomplete_type() {
        let mut stream = StreamReader::new(to_pre_byte_stream(vec![
            // 0x00, // Type: DATA
            // 0x05, // Length: 5
            // b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
        ]));

        assert!(matches!(
            stream.decode_one::<Frame<_>>().await,
            Err(StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source },
            }) if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn incomplete_length() {
        let mut stream = StreamReader::new(to_pre_byte_stream(vec![
            0x00, // Type: DATA
                 // 0x05, // Length: 5
                 // b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
        ]));

        assert!(matches!(
            stream.decode_one::<Frame<_>>().await,
            Err(StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source },
            }) if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn incomplete_payload() {
        let stream = StreamReader::new(to_pre_byte_stream(vec![
            0x00, // Type: DATA
            0x05, // Length: 5
            b'H', b'e', b'l', b'l', /* b'o', */ // Payload: "Hello"
        ]));

        let stream = pin!(FrameStream::new(stream));
        let mut frame1 = stream.next_frame().await.unwrap().unwrap();
        assert_eq!(frame1.r#type().into_inner(), 0);
        assert_eq!(frame1.length().into_inner(), 5);
        let mut payload = vec![];
        assert!(matches!(
            StreamDecodeError::from(frame1.read_to_end(&mut payload).await.unwrap_err()),
            StreamDecodeError::Decode {
                source: DecodeError::Incomplete
            }
        ));
        assert_eq!(payload.as_slice(), b"Hell");
    }

    #[tokio::test]
    async fn zero_length_payload_stays_empty() {
        let stream = StreamReader::new(to_pre_byte_stream([0x00, 0x00]));

        let stream = pin!(FrameStream::new(stream));
        let mut frame = stream.next_frame().await.unwrap().unwrap();
        let mut payload = vec![];
        frame.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload.len(), 0);
        assert_eq!(frame.length().into_inner(), 0);
    }

    #[tokio::test]
    async fn test_data_frames() {
        let stream = StreamReader::new(to_pre_byte_stream(vec![
            0x00, // Type: DATA
            0x05, // Length: 5
            b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
            0x00, // Type: DATA
            0x05, // Length: 5
            b'W', b'o', b'r', b'l', b'd', // Payload: "World"
        ]));

        let mut stream = pin!(FrameStream::new(stream));
        let mut frame1 = stream.as_mut().next_frame().await.unwrap().unwrap();
        assert_eq!(frame1.r#type().into_inner(), 0);
        assert_eq!(frame1.length().into_inner(), 5);
        let mut payload = vec![];
        frame1.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"Hello");

        let mut frame2 = stream.next_frame().await.unwrap().unwrap();
        let mut payload = vec![];
        frame2.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"World");
        assert_eq!(frame2.length().into_inner(), 5);
        assert_eq!(frame2.r#type().into_inner(), 0);
    }

    #[tokio::test]
    async fn decode_to_custom_payload() {
        let mut stream = StreamReader::new(to_pre_byte_stream([
            0x00, // DATA
            0x03, // len 3
            b'a', b'b', b'c',
        ]));

        let frame = stream.decode_one::<Frame<_>>().await.unwrap();
        let frame = Frame::<CapturedPayload>::decode_from(frame).await.unwrap();
        assert_eq!(frame.r#type(), Frame::DATA_FRAME_TYPE);
        assert_eq!(frame.length().into_inner(), 3);
        assert_eq!(frame.payload().0, b"abc");
    }

    #[tokio::test]
    async fn decode_to_buflist_collects_payload() {
        let mut stream = StreamReader::new(to_pre_byte_stream([
            0x01, // HEADERS
            0x03, // len 3
            b'a', b'b', b'c',
        ]));

        let frame = Frame::<BufList>::decode_from(&mut stream)
            .await
            .expect("frame");

        assert_eq!(frame.r#type(), Frame::HEADERS_FRAME_TYPE);
        assert_eq!(frame.length().into_inner(), 3);
        let mut payload = frame.into_payload();
        let mut decoded = Vec::new();
        while payload.has_remaining() {
            let chunk = payload.chunk();
            decoded.extend_from_slice(chunk);
            payload.advance(chunk.len());
        }
        assert_eq!(decoded, b"abc");
    }

    #[tokio::test]
    async fn decode_to_buflist_incomplete_payload_returns_h3_frame_error() {
        let mut stream = StreamReader::new(to_pre_byte_stream([
            0x00, // DATA
            0x05, // len 5
            b'H', b'e', b'l', b'l',
        ]));

        assert!(matches!(
            Frame::<BufList>::decode_from(&mut stream).await,
            Err(StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source },
            }) if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn sink_updates_length_and_reports_overflow() {
        let (sink, chunks) = SinkRecorder::new();
        let mut frame = Frame {
            r#type: Frame::DATA_FRAME_TYPE,
            length: VarInt::from_u32(0),
            payload: sink,
        };

        frame.send(Bytes::from_static(b"abc")).await.unwrap();
        assert_eq!(frame.length().into_inner(), 3);
        assert_eq!(chunks.lock().expect("chunks lock")[0].as_ref(), b"abc");
        frame.close().await.expect("sink close forwarded");

        let (sink, chunks) = SinkRecorder::new();
        let mut frame = Frame {
            r#type: Frame::DATA_FRAME_TYPE,
            length: VarInt::from_u64(VARINT_MAX - 1).expect("length in range"),
            payload: sink,
        };

        let error = frame.send(Bytes::from_static(b"ab")).await.unwrap_err();
        assert!(matches!(
            error,
            crate::codec::StreamEncodeError::Encode {
                source: EncodeError::FramePayloadTooLarge,
            }
        ));
        assert!(chunks.lock().expect("chunks lock").is_empty());
    }

    #[tokio::test]
    async fn sink_start_send_propagates_payload_error() {
        let mut frame = Frame {
            r#type: Frame::DATA_FRAME_TYPE,
            length: VarInt::from_u32(0),
            payload: FailingEncodeStream::fail_start_send(VarInt::from_u32(41)),
        };

        let error = frame
            .send(Bytes::from_static(b"abc"))
            .await
            .expect_err("payload start_send should fail");

        assert!(matches!(
            error,
            crate::codec::StreamEncodeError::Reset { code } if code == VarInt::from_u32(41)
        ));
    }

    #[tokio::test]
    async fn encode_into_propagates_type_length_and_payload_errors() {
        let frame = Frame::new(Frame::DATA_FRAME_TYPE, Bytes::from_static(b"abc")).unwrap();

        let error = frame
            .clone()
            .encode_into(FailingEncodeStream::fail_write_at(1, VarInt::from_u32(43)))
            .await
            .expect_err("frame type write should fail");
        assert!(matches!(
            error,
            quic::StreamError::Reset { code } if code == VarInt::from_u32(43)
        ));

        let error = frame
            .clone()
            .encode_into(FailingEncodeStream::fail_write_at(2, VarInt::from_u32(47)))
            .await
            .expect_err("frame length write should fail");
        assert!(matches!(
            error,
            quic::StreamError::Reset { code } if code == VarInt::from_u32(47)
        ));

        let error = frame
            .encode_into(FailingEncodeStream::fail_start_send(VarInt::from_u32(53)))
            .await
            .expect_err("payload feed should fail");
        assert!(matches!(
            error,
            quic::StreamError::Reset { code } if code == VarInt::from_u32(53)
        ));
    }

    #[tokio::test]
    async fn failing_encode_stream_allows_nonfailing_io_and_sink_paths() {
        let mut stream = FailingEncodeStream {
            reset_code: VarInt::from_u32(59),
            fail_write_at: None,
            fail_start_send: false,
            write_calls: 0,
        };

        stream.write_all(b"ok").await.expect("write");
        AsyncWriteExt::flush(&mut stream).await.expect("flush");
        AsyncWriteExt::shutdown(&mut stream)
            .await
            .expect("shutdown");

        stream.send(Bytes::from_static(b"ok")).await.expect("send");
        SinkExt::flush(&mut stream).await.expect("sink flush");
        stream.close().await.expect("sink close");
    }

    #[tokio::test]
    async fn payload_stream_is_forwarded() {
        let payload = stream::iter([
            Ok::<Bytes, StreamDecodeError>(Bytes::from_static(b"one")),
            Ok::<Bytes, StreamDecodeError>(Bytes::from_static(b"two")),
        ]);

        let mut frame = Frame {
            r#type: Frame::DATA_FRAME_TYPE,
            length: VarInt::from_u32(6),
            payload,
        };

        let mut chunks = Vec::new();
        while let Some(item) = frame.next().await {
            chunks.push(item.expect("payload chunk"));
        }
        assert_eq!(chunks[0].as_ref(), b"one");
        assert_eq!(chunks[1].as_ref(), b"two");
    }

    #[derive(Debug)]
    struct ControlPayload {
        stream_id: VarInt,
        stopped: Arc<Mutex<Option<VarInt>>>,
    }

    impl GetStreamId for ControlPayload {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl StopStream for ControlPayload {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            *self.stopped.lock().expect("stop state poisoned") = Some(code);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn control_traits_delegate_to_payload() {
        let stopped = Arc::new(Mutex::new(None));
        let stream_id = VarInt::from_u32(17);
        let stop_code = VarInt::from_u32(23);
        let mut frame = Frame {
            r#type: Frame::DATA_FRAME_TYPE,
            length: VarInt::from_u32(0),
            payload: ControlPayload {
                stream_id,
                stopped: stopped.clone(),
            },
        };

        assert_eq!(
            poll_fn(|cx| Pin::new(&mut frame).poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );
        poll_fn(|cx| Pin::new(&mut frame).poll_stop(cx, stop_code))
            .await
            .expect("stop");

        assert_eq!(
            *stopped.lock().expect("stop state poisoned"),
            Some(stop_code)
        );
    }

    #[tokio::test]
    async fn can_decode_with_multi_byte_type_varint() {
        let stream = StreamReader::new(to_pre_byte_stream([
            0x40, 0x40, // type: 64 encoded as 2-byte varint
            0x01, // length: 1
            b'z',
        ]));

        let stream = pin!(FrameStream::new(stream));
        let mut frame = stream.next_frame().await.unwrap().unwrap();
        assert_eq!(frame.r#type().into_inner(), 64);
        let mut payload = vec![];
        frame.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"z");
    }

    #[test]
    fn h3_frame_decode_error_display_and_debug() {
        let error = H3FrameDecodeError {
            source: DecodeError::Incomplete,
        };

        assert_eq!(format!("{}", error), "frame decode error");
        assert!(format!("{:?}", error).contains("H3FrameDecodeError"));
    }

    fn channel() -> (
        impl Sink<Bytes, Error = quic::StreamError>,
        impl Stream<Item = Result<Bytes, quic::StreamError>>,
    ) {
        let (sink, stream) = futures::channel::mpsc::channel(8);
        (sink.sink_map_err(|_e| unreachable!()), stream.map(Ok))
    }

    #[tokio::test]
    async fn encode_into_flushes_zero_length_frame() {
        let (sink, stream) = channel();
        let mut sink = SinkWriter::new(sink);
        let frame = Frame::new(Frame::SETTINGS_FRAME_TYPE, Bytes::new()).expect("settings frame");

        sink.encode_one(frame)
            .await
            .expect("frame encode should flush");

        let stream = StreamReader::new(stream);
        let mut stream = pin!(FrameStream::new(stream));
        let frame = timeout(Duration::from_millis(100), stream.as_mut().next_frame())
            .await
            .expect("flushed frame should be observable")
            .expect("frame should be present")
            .expect("frame should decode");

        assert_eq!(frame.r#type(), Frame::SETTINGS_FRAME_TYPE);
        assert_eq!(frame.length(), VarInt::from_u32(0));
    }

    #[tokio::test]
    async fn encode_and_decode() {
        let (sink, stream) = channel();

        let decode = tokio::spawn(
            async move {
                let stream = StreamReader::new(stream);

                let mut stream = pin!(FrameStream::new(stream));
                let mut frame1 = stream.as_mut().next_frame().await.unwrap().unwrap();
                assert_eq!(frame1.r#type().into_inner(), 0);
                assert_eq!(frame1.length().into_inner(), 5);
                let mut payload = vec![];
                frame1.read_to_end(&mut payload).await.unwrap();
                assert_eq!(&payload[..], b"Hello");

                let mut frame2 = stream.next_frame().await.unwrap().unwrap();
                let mut payload = vec![];
                frame2.read_to_end(&mut payload).await.unwrap();
                assert_eq!(&payload[..], b"World");
                assert_eq!(frame2.length().into_inner(), 5);
                assert_eq!(frame2.r#type().into_inner(), 0);
            }
            .in_current_span(),
        );
        let encode = tokio::spawn(
            async move {
                let mut sink = SinkWriter::new(sink);

                let frame1 = Frame::new(VarInt::from_u32(0), Bytes::from_static(b"Hello")).unwrap();
                assert!(frame1.r#type().into_inner() == 0);
                assert!(frame1.length().into_inner() == 5);
                assert!(frame1.payload().as_ref() == b"Hello");
                sink.encode_one(frame1).await.unwrap();

                let frame2 = Frame::new(VarInt::from_u32(0), Bytes::from_static(b"World")).unwrap();
                assert!(frame2.r#type().into_inner() == 0);
                assert!(frame2.length().into_inner() == 5);
                assert!(frame2.payload().as_ref() == b"World");
                sink.encode_one(frame2).await.unwrap();

                Pin::new(&mut sink).flush_buffer().await.unwrap();
            }
            .in_current_span(),
        );
        tokio::try_join!(encode, decode).unwrap();
    }
}
