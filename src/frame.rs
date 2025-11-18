use std::{
    pin::{Pin, pin},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{Sink, SinkExt, Stream, StreamExt, TryStream, sink};
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    codec::{Decode, DecodeExt, Encode, FixedLengthReader, StreamReader, error::DecodeStreamError},
    error::{Code, Error, StreamError},
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
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-reserved-frame-types
    pub const fn is_reversed_frame(&self) -> bool {
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
                panic!("Frame too large")
            }
            Some(new_length) => {
                *project.length = VarInt::from_u64(new_length).unwrap();
            }
            None => panic!("Frame too large"),
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

impl<P: Sink<B> + ?Sized, B: Buf> Sink<B> for Frame<P> {
    type Error = P::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().payload.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: B) -> Result<(), Self::Error> {
        let project = self.project();
        let len = item.remaining() as u64;
        match project.length.into_inner().checked_add(len) {
            Some(new_length) if new_length > VARINT_MAX => {
                panic!("Frame too large")
            }
            Some(new_length) => {
                *project.length = VarInt::from_u64(new_length).unwrap();
            }
            None => panic!("Frame too large"),
        }
        project.payload.start_send(item)?;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().payload.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().payload.poll_close(cx)
    }
}

impl<P: Buf, S: AsyncWrite + Sink<Bytes, Error = StreamError>> Encode<Frame<P>> for S {
    type Output = ();

    type Error = StreamError;

    async fn encode(self, mut frame: Frame<P>) -> Result<Self::Output, Self::Error> {
        let mut stream = pin!(self);
        stream.as_mut().encode(frame.r#type).await?;
        stream.as_mut().encode(frame.length).await?;
        while frame.payload.has_remaining() {
            let bytes = frame.payload.copy_to_bytes(frame.payload.chunk().len());
            stream.as_mut().feed(bytes).await?;
        }
        Ok(())
    }
}

impl<S> Decode<Frame<FixedLengthReader<StreamReader<S>>>> for StreamReader<S>
where
    S: TryStream<Ok = Bytes, Error = StreamError>,
    StreamReader<S>: Unpin,
{
    type Error = Error;

    async fn decode(mut self) -> Result<Frame<FixedLengthReader<StreamReader<S>>>, Self::Error> {
        let decode = async move {
            let r#type = self.decode_one::<VarInt>().await?;
            let length = self.decode_one::<VarInt>().await?;
            let payload = FixedLengthReader::new(self, length.into_inner());
            Ok(Frame {
                r#type,
                length,
                payload,
            })
        };

        decode.await.map_err(|error: DecodeStreamError| {
            error.map_decode_error(|decode_error| Code::H3_FRAME_ERROR.with(decode_error).into())
        })
    }
}

impl<S> AsyncRead for Frame<FixedLengthReader<StreamReader<S>>>
where
    S: TryStream<Ok = Bytes>,
    io::Error: From<S::Error>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().payload.poll_read(cx, buf).map_err(|error| {
            DecodeStreamError::from(error)
                .map_decode_error(|decode_error| Code::H3_FRAME_ERROR.with(decode_error).into())
                .into()
        })
    }
}

impl<S> AsyncBufRead for Frame<FixedLengthReader<StreamReader<S>>>
where
    S: TryStream<Ok = Bytes>,
    io::Error: From<S::Error>,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.project().payload.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.project().payload.consume(amt);
    }
}

impl<S: Stream + ?Sized> Stream for Frame<FixedLengthReader<StreamReader<S>>>
where
    S: TryStream<Ok = Bytes, Error = StreamError>,
{
    type Item = Result<Bytes, DecodeStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().payload.poll_next(cx)
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for Frame<S> {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        self.project().payload.poll_stream_id(cx)
    }
}

impl<S: StopSending + ?Sized> StopSending for Frame<S> {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        self.project().payload.poll_stop_sending(cx, code)
    }
}

impl<S> Frame<FixedLengthReader<StreamReader<S>>>
where
    S: TryStream<Ok = Bytes, Error = StreamError>,
    StreamReader<S>: Unpin,
{
    pub async fn into_next_frame(mut self) -> Option<Result<Self, Error>> {
        if self.payload.remaining() > 0 {
            let drain = sink::drain().sink_map_err(|never| match never {});
            if let Err(error) = (&mut self.payload).forward(drain).await {
                return Some(Err(error.map_decode_error(|decode_error| {
                    Code::H3_FRAME_ERROR.with(decode_error).into()
                })));
            }
        }

        let mut stream = self.payload.into_inner();
        match Pin::new(&mut stream).has_remaining().await {
            Ok(true) => Some(stream.into_decoded().await),
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
        codec::{EncodeExt, SinkWriter, error::DecodeError},
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
        Frame::new(Frame::DATA_FRAME_TYPE, Bytes::new()).unwrap();
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

        let mut frame1: Frame<_> = stream.into_decoded().await.unwrap();
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
        let stream = StreamReader::new(to_pre_byte_stream(vec![
            // 0x00, // Type: DATA
            // 0x05, // Length: 5
            // b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
        ]));

        assert!(matches!(
            stream.into_decoded::<Frame<_>>().await,
            Err(Error::Code { source }) if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn incomplete_length() {
        let stream = StreamReader::new(to_pre_byte_stream(vec![
            0x00, // Type: DATA
                 // 0x05, // Length: 5
                 // b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
        ]));

        assert!(matches!(
            stream.into_decoded::<Frame<_>>().await,
            Err(Error::Code { source }) if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn incomplete_payload() {
        let stream = StreamReader::new(to_pre_byte_stream(vec![
            0x00, // Type: DATA
            0x05, // Length: 5
            b'H', b'e', b'l', b'l', /* b'o', */ // Payload: "Hello"
        ]));

        let mut frame1 = stream.into_decoded::<Frame<_>>().await.unwrap();
        assert_eq!(frame1.r#type().into_inner(), 0);
        assert_eq!(frame1.length().into_inner(), 5);
        let mut payload = vec![];
        assert!(matches!(
            Error::from(frame1.read_to_end(&mut payload).await.unwrap_err()),
            Error::Code { source } if source.code() == Code::H3_FRAME_ERROR &&
                matches!(
                    source.source().unwrap().downcast_ref::<DecodeError>(),
                    Some(DecodeError::Incomplete)
                )
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
            let stream = StreamReader::new(stream);

            let mut frame1 = stream.into_decoded::<Frame<_>>().await.unwrap();
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
        });
        tokio::try_join!(encode, decode).unwrap();
    }
}
