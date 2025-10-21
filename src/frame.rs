use std::{
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt, ready};
use tokio::io::{self, AsyncRead};

use crate::{
    codec::{
        SinkWriter, StreamReader,
        error::{DecodeError, DecodeStreamError, EncodeStreamError},
    },
    error::StreamError,
    varint::{self, VarInt, decode_varint, encode_varint},
};

pin_project_lite::pin_project! {
    /// Asynchronous HTTP3 [`Frame`] decoder.
    ///
    pub struct FrameDecoder<S> {
        r#type: Option<VarInt>,
        length: Option<VarInt>,
        #[pin]
        payload: StreamReader<S>,
        read_offset: u64,
    }
}

impl<S> FrameDecoder<S>
where
    S: Stream<Item = Result<Bytes, StreamError>> + Unpin,
{
    pub const fn new(stream: StreamReader<S>) -> Self {
        Self {
            payload: stream,
            r#type: None,
            length: None,
            read_offset: 0,
        }
    }

    pub async fn r#type(&mut self) -> Result<VarInt, DecodeStreamError> {
        match self.r#type {
            Some(r#type) => Ok(r#type),
            None => {
                let varint = decode_varint(&mut self.payload).await?;
                self.r#type = Some(varint);
                Ok(varint)
            }
        }
    }

    pub async fn length(&mut self) -> Result<VarInt, DecodeStreamError>
    where
        S: Unpin,
    {
        self.r#type().await?;
        match self.length {
            Some(length) => Ok(length),
            None => {
                let varint = decode_varint(&mut self.payload).await?;
                self.length = Some(varint);
                Ok(varint)
            }
        }
    }

    pub async fn payload<'s>(&'s mut self) -> Result<FramePayloadReader<'s, S>, DecodeStreamError> {
        self.length().await?;
        Ok(FramePayloadReader::new(Pin::new(self)).expect("Length is known"))
    }

    fn check_frame_completely_decoded_and_read(&self) {
        debug_assert!(self.r#type.is_some(), "Frame type not decoded yet");
        debug_assert!(self.length.is_some(), "Frame length not decoded yet");
        debug_assert_eq!(
            self.length.unwrap().into_inner(),
            self.read_offset,
            "Frame payload not fully read yet"
        );
    }

    /// Create a new decoder for the next frame on the same stream.
    ///
    /// Panic: The current decoder must have completely decoded current frame,
    /// and all payload of the current frame must have been read from the decoder.
    pub async fn next_frame(&mut self) -> Result<bool, DecodeStreamError> {
        self.check_frame_completely_decoded_and_read();
        self.r#type = None;
        self.length = None;
        self.read_offset = 0;
        let has_next = poll_fn(|cx| {
            Pin::new(&mut self.payload)
                .poll_peek_chunk(cx, None)
                .map_ok(|slice| !slice.is_empty())
        })
        .await?;
        Ok(has_next)
    }

    pub fn complete(self) -> Result<(), DecodeError> {
        self.check_frame_completely_decoded_and_read();
        Ok(())
    }
}

pub struct FramePayloadReader<'f, S> {
    frame: Pin<&'f mut FrameDecoder<S>>,
}

impl<'f, S> FramePayloadReader<'f, S>
where
    S: Stream<Item = Result<Bytes, StreamError>> + Unpin,
{
    pub fn new(frame: Pin<&'f mut FrameDecoder<S>>) -> Option<Self> {
        frame.length.is_some().then_some(Self { frame })
    }

    fn length(&self) -> u64 {
        self.frame.length.unwrap().into_inner()
    }

    pub fn into_inner(self) -> Pin<&'f mut FrameDecoder<S>> {
        self.frame
    }
}

impl<'s, S> Stream for FramePayloadReader<'s, S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    type Item = Result<Bytes, DecodeStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut frame = self.frame.as_mut().project();
        let length = frame.length.unwrap().into_inner();
        if *frame.read_offset == length {
            return Poll::Ready(None);
        }

        let cap = (length - *frame.read_offset).min(usize::MAX as u64) as usize;
        match ready!(frame.payload.as_mut().poll_consume_bytes(cx, Some(cap))?) {
            Some(chunk) => {
                *frame.read_offset += chunk.len() as u64;
                Poll::Ready(Some(Ok(chunk)))
            }
            None => Poll::Ready(Some(Err(DecodeError::Incomplete.into()))),
        }
    }
}

impl<'s, S> AsyncRead for FramePayloadReader<'s, S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut frame = self.frame.as_mut().project();
        let length = frame.length.unwrap().into_inner();

        if *frame.read_offset == length {
            return Poll::Ready(Ok(()));
        }

        let cap = (length - *frame.read_offset).min(buf.remaining() as u64) as usize;
        let chunk = match ready!(frame.payload.as_mut().poll_consume_bytes(cx, Some(cap))?) {
            Some(chunk) => chunk,
            None => return Poll::Ready(Err(DecodeError::Incomplete.into())),
        };
        buf.put_slice(&chunk);
        *frame.read_offset += chunk.len() as u64;
        Poll::Ready(Ok(()))
    }
}

pub struct DataFramesReader<'f, S> {
    payload_reader: FramePayloadReader<'f, S>,
}

impl<'f, S> DataFramesReader<'f, S>
where
    S: Stream<Item = Result<Bytes, StreamError>> + Unpin,
{
    pub async fn new(frame: &'f mut FrameDecoder<S>) -> Result<Option<Self>, DecodeStreamError> {
        if frame.r#type().await.unwrap().into_inner() != 0 {
            return Ok(None);
        }
        Ok(Some(Self {
            payload_reader: frame.payload().await?,
        }))
    }

    pub async fn next(mut self) -> Option<Result<(Bytes, Self), DecodeStreamError>> {
        loop {
            match self.payload_reader.next().await {
                Some(chunk) => return Some(chunk.map(|chunk| (chunk, self))),
                None => {
                    let frame = Pin::into_inner(self.payload_reader.into_inner());
                    match frame.next_frame().await {
                        Ok(true) => {}
                        Ok(false) => return None,
                        Err(error) => return Some(Err(error)),
                    }
                    match DataFramesReader::new(frame).await {
                        Ok(Some(next_reader)) => self = next_reader,
                        Ok(None) => return None,
                        Err(error) => return Some(Err(error)),
                    }
                }
            }
        }
    }
}

/// All frames have the following format:
///
/// ``` plaintext
/// HTTP/3 Frame Format {
///   Type (i),
///   Length (i),
///   Frame Payload (..),
/// }
/// ```
pub struct Frame<B> {
    r#type: VarInt,
    length: VarInt,
    payload: B,
}

impl<B> Frame<B> {
    /// Create a new frame.
    ///
    /// Length is calculated from the payload
    pub fn new(r#type: VarInt, payload: B) -> Result<Self, varint::err::Overflow>
    where
        for<'b> &'b B: IntoIterator<Item = &'b Bytes>,
    {
        let length = (&payload).into_iter().map(|b| b.len() as u64).sum::<u64>();
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

    pub fn payload(&self) -> &B {
        &self.payload
    }
}

impl<C> Frame<C>
where
    C: Default + Extend<Bytes>,
{
    pub async fn decode(
        stream: &mut (impl Stream<Item = Result<Bytes, StreamError>> + Unpin),
    ) -> Result<Frame<C>, DecodeStreamError> {
        let mut decoder = FrameDecoder::new(StreamReader::new(stream));
        let r#type = decoder.r#type().await?;
        let length = decoder.length().await?;
        let mut payload = C::default();
        let mut payload_reader = decoder.payload().await?;
        while let Some(bytes) = payload_reader.try_next().await? {
            payload.extend([bytes]);
        }
        Ok(Self {
            r#type,
            length,
            payload,
        })
    }
}

impl<C> Frame<C>
where
    C: IntoIterator<Item = Bytes>,
{
    pub async fn encode(
        self,
        stream: &mut SinkWriter<impl Sink<Bytes, Error = StreamError> + Unpin>,
    ) -> Result<(), EncodeStreamError> {
        encode_varint(stream, self.r#type).await?;
        encode_varint(stream, self.length).await?;

        for bytes in self.payload {
            stream.send(bytes).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use futures::stream::{self, StreamExt};
    use tokio::io::AsyncReadExt;

    use super::*;

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

    async fn fold_try_stream<E>(
        stream: impl Stream<Item = Result<Bytes, E>> + Unpin,
    ) -> Result<BytesMut, E> {
        let fold = |acc: Result<BytesMut, E>, x| async {
            acc.and_then(|mut acc| {
                acc.extend(x?);
                Ok(acc)
            })
        };
        stream.fold(Ok(BytesMut::new()), fold).await
    }

    #[tokio::test]
    async fn test_data_frames() {
        let mut decoder = FrameDecoder::new(StreamReader::new(to_pre_byte_stream(vec![
            0x00, // Type: DATA
            0x05, // Length: 5
            b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
            0x00, // Type: DATA
            0x05, // Length: 5
            b'W', b'o', b'r', b'l', b'd', // Payload: "World"
        ])));

        assert_eq!(decoder.r#type().await.unwrap().into_inner(), 0);
        assert_eq!(decoder.length().await.unwrap().into_inner(), 5);
        let mut payload_reader = decoder.payload().await.unwrap();
        let mut payload = vec![];
        payload_reader.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"Hello");

        assert!(decoder.next_frame().await.unwrap());
        let mut payload_reader = decoder.payload().await.unwrap();
        let mut payload = vec![];
        payload_reader.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"World");
        assert_eq!(decoder.length().await.unwrap().into_inner(), 5);
        assert_eq!(decoder.r#type().await.unwrap().into_inner(), 0);
    }

    fn channel() -> (
        impl Sink<Bytes, Error = StreamError>,
        impl Stream<Item = Result<Bytes, StreamError>>,
    ) {
        let (sink, stream) = futures::channel::mpsc::channel(8);
        (sink.sink_map_err(|_e| unreachable!()), stream.map(Ok))
    }

    #[tokio::test]
    async fn frame_api() {
        let (sink, stream) = channel();
        let mut sink = SinkWriter::new(sink);

        let frame1 = Frame::new(VarInt::from_u32(0), [Bytes::from_static(b"Hello")]).unwrap();
        assert!(frame1.r#type().into_inner() == 0);
        assert!(frame1.length().into_inner() == 5);
        assert!(frame1.payload()[0].as_ref() == b"Hello");
        frame1.encode(&mut sink).await.unwrap();

        let frame2 = Frame::new(VarInt::from_u32(0), vec![Bytes::from_static(b"World")]).unwrap();
        assert!(frame2.r#type().into_inner() == 0);
        assert!(frame2.length().into_inner() == 5);
        assert!(frame2.payload()[0].as_ref() == b"World");
        frame2.encode(&mut sink).await.unwrap();

        let mut decoder = FrameDecoder::new(StreamReader::new(stream));

        assert_eq!(decoder.r#type().await.unwrap().into_inner(), 0);
        assert_eq!(decoder.length().await.unwrap().into_inner(), 5);
        let mut payload_reader = decoder.payload().await.unwrap();
        let mut payload = vec![];
        payload_reader.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"Hello");

        assert!(decoder.next_frame().await.unwrap());
        let mut payload_reader = decoder.payload().await.unwrap();
        let mut payload = vec![];
        payload_reader.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"World");
        assert_eq!(decoder.length().await.unwrap().into_inner(), 5);
        assert_eq!(decoder.r#type().await.unwrap().into_inner(), 0);
    }
}
