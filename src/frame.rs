use std::{
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Stream, ready};
use snafu::Snafu;
use tokio::io;

use crate::{
    codec::{DecodeStreamError, StreamReader},
    error::StreamError,
    varint::{DecodeVarIntError, VarInt, VarintDecoder},
};

pin_project_lite::pin_project! {
    /// Asynchronous HTTP3 frame decoder.
    ///
    /// All frames have the following format:
    ///
    /// ``` plaintext
    /// HTTP/3 Frame Format {
    ///   Type (i),
    ///   Length (i),
    ///   Frame Payload (..),
    /// }
    /// ```
    pub struct FrameDecoder<S> {
        r#type: VarintDecoder,
        length: VarintDecoder,
        #[pin]
        stream: StreamReader<S>,
        read_offset: u64,
    }
}

#[derive(Debug, Snafu)]
pub enum DecodeFrameError {
    #[snafu(transparent)]
    VarInt { source: DecodeVarIntError },
}

impl From<DecodeFrameError> for io::Error {
    fn from(error: DecodeFrameError) -> Self {
        io::Error::other(error)
    }
}

impl<S> FrameDecoder<S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    pub const fn new(stream: StreamReader<S>) -> Self {
        Self {
            stream,
            r#type: VarintDecoder::new(),
            length: VarintDecoder::new(),
            read_offset: 0,
        }
    }

    pub fn poll_type(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, DecodeStreamError<DecodeFrameError>>> {
        let mut project = self.project();
        project
            .r#type
            .poll_decode(&mut project.stream, cx)
            .map_err(|error| error.map_err(DecodeFrameError::from))
    }

    pub async fn r#type(&mut self) -> Result<VarInt, DecodeStreamError<DecodeFrameError>>
    where
        S: Unpin,
    {
        poll_fn(|cx| Pin::new(&mut *self).poll_type(cx)).await
    }

    pub fn poll_length(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, DecodeStreamError<DecodeFrameError>>> {
        ready!(self.as_mut().poll_type(cx)?);
        let mut project = self.project();
        project
            .length
            .poll_decode(&mut project.stream, cx)
            .map_err(|error| error.map_err(DecodeFrameError::from))
    }

    pub async fn length(&mut self) -> Result<VarInt, DecodeStreamError<DecodeFrameError>>
    where
        S: Unpin,
    {
        poll_fn(|cx| Pin::new(&mut *self).poll_length(cx)).await
    }

    fn check_frame_completely_decoded_and_read(&self) {
        debug_assert!(self.r#type.is_decoded(), "Frame type not decoded yet");
        debug_assert!(self.length.is_decoded(), "Frame length not decoded yet");
        debug_assert_eq!(
            self.length.decoded().unwrap().into_inner(),
            self.read_offset,
            "Frame payload not fully read yet"
        );
    }

    /// Create a new decoder for the next frame on the same stream.
    ///
    /// Panic: The current decoder must have completely decoded current frame,
    /// and all payload of the current frame must have been read from the decoder.
    pub fn next_frame(self) -> Self {
        self.check_frame_completely_decoded_and_read();
        Self::new(self.stream)
    }

    pub fn complete(self) -> Result<(), DecodeFrameError> {
        self.check_frame_completely_decoded_and_read();
        Ok(())
    }
}

impl<S> Stream for FrameDecoder<S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    type Item = Result<Bytes, DecodeStreamError<DecodeFrameError>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // When length is ready, type is also ready, its ok to collect data
        let length = match ready!(self.as_mut().poll_length(cx)) {
            Ok(length) => length.into_inner(),
            Err(e) => return Poll::Ready(Some(Err(e))),
        };

        let project = self.project();

        let remaining = (length - *project.read_offset) as usize;
        let chunk = ready!(project.stream.poll_consume_chunk(cx, Some(remaining)))
            .transpose()
            .map_err(|source| DecodeStreamError::Stream { source })?;

        if let Some(ref chunk) = chunk {
            *project.read_offset += chunk.len() as u64;
        }

        Poll::Ready(chunk.map(Ok))
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use futures::stream::{self, StreamExt};

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
        let payload = fold_try_stream(&mut decoder).await.unwrap();

        assert_eq!(&payload[..], b"Hello");
        let mut decoder = decoder.next_frame();
        let payload = fold_try_stream(&mut decoder).await.unwrap();
        assert_eq!(&payload[..], b"World");
        assert_eq!(decoder.length().await.unwrap().into_inner(), 5);
        assert_eq!(decoder.r#type().await.unwrap().into_inner(), 0);
    }
}
