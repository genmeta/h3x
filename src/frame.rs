use std::{
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{Sink, SinkExt, Stream, TryStream};
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    codec::{
        BufStreamReader, FixedLengthReader,
        error::{DecodeStreamError, EncodeError, EncodeStreamError},
        util::{DecodeFrom, EncodeInto},
    },
    quic::{GetStreamId, StopSending},
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
    /// ### A sequence of bytes (such as `Vec<B>`, `[B]` where B: `[Buf]`).
    ///
    /// Crate such a frame with [`Frame::new`], encode it to the stream with [`Frame::encode`].
    ///
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
    pub fn new<B>(r#type: VarInt, payload: P) -> Result<Self, varint::err::Overflow>
    where
        for<'c> &'c P: IntoIterator<Item = &'c B>,
        B: Buf,
        P: Sized,
    {
        let length = (&payload)
            .into_iter()
            .map(|b| b.remaining() as u64)
            .sum::<u64>();
        let length = VarInt::from_u64(length)?;

        Ok(Self {
            r#type,
            length,
            payload,
        })
    }

    pub fn r#type(&self) -> VarInt {
        self.r#type
    }

    pub fn length(&self) -> VarInt {
        self.length
    }

    pub fn payload(&self) -> &P {
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
                return Poll::Ready(Err(io::Error::from(EncodeError::FramePayloadTooLarge)));
            }
            Some(new_length) => {
                *project.length = VarInt::from_u64(new_length).unwrap();
            }
            None => return Poll::Ready(Err(io::Error::from(EncodeError::FramePayloadTooLarge))),
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
    EncodeStreamError: From<P::Error>,
{
    type Error = EncodeStreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .payload
            .poll_ready(cx)
            .map_err(EncodeStreamError::from)
    }

    fn start_send(self: Pin<&mut Self>, item: B) -> Result<(), Self::Error> {
        let project = self.project();
        let len = item.remaining() as u64;
        match project.length.into_inner().checked_add(len) {
            Some(new_length) if new_length > VARINT_MAX => {
                return Err(EncodeError::FramePayloadTooLarge.into());
            }
            Some(new_length) => {
                *project.length = VarInt::from_u64(new_length).unwrap();
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
            .map_err(EncodeStreamError::from)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .payload
            .poll_close(cx)
            .map_err(EncodeStreamError::from)
    }
}

impl<C, B, S> EncodeInto<S> for Frame<C>
where
    C: IntoIterator<Item = B>,
    B: Buf,
    S: AsyncWrite + Sink<Bytes>,
    EncodeStreamError: From<S::Error>,
{
    async fn encode_into(self, stream: S) -> Result<(), EncodeStreamError> {
        tokio::pin!(stream);
        self.r#type.encode_into(&mut stream).await?;
        self.length.encode_into(&mut stream).await?;
        for mut bytes in self.payload {
            stream.feed(bytes.copy_to_bytes(bytes.remaining())).await?;
        }

        Ok(())
    }
}

impl<S> DecodeFrom<BufStreamReader<S>> for Frame<FixedLengthReader<BufStreamReader<S>>>
where
    S: TryStream<Ok = Bytes>,
    BufStreamReader<S>: Unpin,
    io::Error: From<S::Error>,
    DecodeStreamError: From<S::Error>,
{
    async fn decode_from(mut stream: BufStreamReader<S>) -> Result<Self, DecodeStreamError> {
        let r#type = VarInt::decode_from(&mut stream).await?;
        let length = VarInt::decode_from(&mut stream).await?;
        let payload = FixedLengthReader::new(stream, length.into_inner());
        Ok(Frame {
            r#type,
            length,
            payload,
        })
    }
}

impl<R: AsyncRead + ?Sized> AsyncRead for Frame<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().payload.poll_read(cx, buf)
    }
}

impl<R: AsyncBufRead + ?Sized> AsyncBufRead for Frame<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.project().payload.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.project().payload.consume(amt);
    }
}

impl<S: Stream + ?Sized> Stream for Frame<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().payload.poll_next(cx)
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for Frame<S> {
    fn stream_id(&self) -> u64 {
        self.payload.stream_id()
    }
}

impl<S: StopSending + ?Sized> StopSending for Frame<S> {
    fn stop_sending(self: Pin<&mut Self>, code: u64) {
        self.project().payload.stop_sending(code)
    }
}

impl<S> Frame<FixedLengthReader<BufStreamReader<S>>>
where
    S: TryStream<Ok = Bytes>,
    BufStreamReader<S>: Unpin,
    io::Error: From<S::Error>,
    DecodeStreamError: From<S::Error>,
{
    pub async fn into_next_frame(self) -> Option<Result<Self, DecodeStreamError>> {
        assert!(
            self.payload.remaining() == 0,
            "Current frame should be completed read before decoding next one"
        );

        let mut stream = self.payload.into_inner();
        match Pin::new(&mut stream).has_remaining().await {
            Ok(true) => Some(Frame::decode_from(stream).await),
            Ok(false) => None,
            Err(error) => Some(Err(error.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::stream::{self, StreamExt};
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::{
        codec::{BufSinkWriter, error::DecodeError},
        error::StreamError,
    };

    fn to_pre_byte_stream(
        data: impl IntoIterator<Item = u8>,
    ) -> impl Stream<Item = Result<Bytes, StreamError>> {
        stream::iter(
            data.into_iter()
                .map(|byte| vec![byte])
                .map(Bytes::from_owner)
                .map(Ok),
        )
    }

    #[test]
    fn new_frame() {
        Frame::new(Frame::DATA_FRAME_TYPE, [Bytes::new()]).unwrap();
    }

    #[tokio::test]
    async fn test_data_frames() {
        let stream = BufStreamReader::new(to_pre_byte_stream(vec![
            0x00, // Type: DATA
            0x05, // Length: 5
            b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
            0x00, // Type: DATA
            0x05, // Length: 5
            b'W', b'o', b'r', b'l', b'd', // Payload: "World"
        ]));

        let mut frame1 = Frame::decode_from(stream).await.unwrap();
        assert_eq!(frame1.r#type().into_inner(), 0);
        assert_eq!(frame1.length().into_inner(), 5);
        let mut payload = vec![];
        frame1.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"Hello");

        let mut frame2 = frame1.into_next_frame().await.unwrap().unwrap();
        let mut payload = vec![];
        frame2.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"World");
        assert_eq!(frame2.length().into_inner(), 5);
        assert_eq!(frame2.r#type().into_inner(), 0);
    }

    #[tokio::test]
    async fn incomplete_type() {
        let stream = BufStreamReader::new(to_pre_byte_stream(vec![
            // 0x00, // Type: DATA
            // 0x05, // Length: 5
            // b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
        ]));

        assert!(matches!(
            Frame::decode_from(stream).await,
            Err(DecodeStreamError::Decode {
                source: DecodeError::Incomplete
            })
        ));
    }

    #[tokio::test]
    async fn incomplete_length() {
        let stream = BufStreamReader::new(to_pre_byte_stream(vec![
            0x00, // Type: DATA
                 // 0x05, // Length: 5
                 // b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
        ]));

        assert!(matches!(
            Frame::decode_from(stream).await,
            Err(DecodeStreamError::Decode {
                source: DecodeError::Incomplete
            })
        ));
    }

    #[tokio::test]
    async fn incomplete_payload() {
        let stream = BufStreamReader::new(to_pre_byte_stream(vec![
            0x00, // Type: DATA
            0x05, // Length: 5
            b'H', b'e', b'l', b'l', /* b'o', */ // Payload: "Hello"
        ]));

        let mut frame1 = Frame::decode_from(stream).await.unwrap();
        assert_eq!(frame1.r#type().into_inner(), 0);
        assert_eq!(frame1.length().into_inner(), 5);
        let mut payload = vec![];
        assert!(matches!(
            DecodeStreamError::from(frame1.read_to_end(&mut payload).await.unwrap_err()),
            DecodeStreamError::Decode {
                source: DecodeError::Incomplete
            }
        ));
        assert_eq!(payload.as_slice(), b"Hell")
    }

    fn channel() -> (
        impl Sink<Bytes, Error = StreamError>,
        impl Stream<Item = Result<Bytes, StreamError>>,
    ) {
        let (sink, stream) = futures::channel::mpsc::channel(8);
        (sink.sink_map_err(|_e| unreachable!()), stream.map(Ok))
    }

    #[tokio::test]
    async fn encode_and_decode() {
        let (sink, stream) = channel();

        let decode = tokio::spawn(async move {
            let stream = BufStreamReader::new(stream);

            let mut frame1 = Frame::decode_from(stream).await.unwrap();
            assert_eq!(frame1.r#type().into_inner(), 0);
            assert_eq!(frame1.length().into_inner(), 5);
            let mut payload = vec![];
            frame1.read_to_end(&mut payload).await.unwrap();
            assert_eq!(&payload[..], b"Hello");

            let mut frame2 = frame1.into_next_frame().await.unwrap().unwrap();
            let mut payload = vec![];
            frame2.read_to_end(&mut payload).await.unwrap();
            assert_eq!(&payload[..], b"World");
            assert_eq!(frame2.length().into_inner(), 5);
            assert_eq!(frame2.r#type().into_inner(), 0);
        });
        let encode = tokio::spawn(async move {
            let mut sink = BufSinkWriter::new(sink);

            let frame1 = Frame::new(VarInt::from_u32(0), [Bytes::from_static(b"Hello")]).unwrap();
            assert!(frame1.r#type().into_inner() == 0);
            assert!(frame1.length().into_inner() == 5);
            assert!(frame1.payload()[0].as_ref() == b"Hello");
            frame1.encode_into(&mut sink).await.unwrap();

            let frame2 =
                Frame::new(VarInt::from_u32(0), vec![Bytes::from_static(b"World")]).unwrap();
            assert!(frame2.r#type().into_inner() == 0);
            assert!(frame2.length().into_inner() == 5);
            assert!(frame2.payload()[0].as_ref() == b"World");
            frame2.encode_into(&mut sink).await.unwrap();

            sink.flush_buffer().await.unwrap();
        });
        tokio::try_join!(encode, decode).unwrap();
    }
}
