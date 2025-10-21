use bytes::Bytes;
use futures::{Stream, stream};
use http::HeaderMap;

use crate::{
    codec::{StreamReader, error::DecodeStreamError},
    error::StreamError,
    frame::{DataFramesReader, FrameDecoder},
};

pub struct MessageDecoder<S> {
    header: Option<HeaderMap>,
    context: FrameDecoder<S>,
    trailer: Option<HeaderMap>,
}

impl<S> MessageDecoder<S>
where
    S: Stream<Item = Result<Bytes, StreamError>> + Unpin,
{
    pub const fn new(payload: FrameDecoder<S>) -> Self {
        Self {
            header: None,
            context: payload,
            trailer: None,
        }
    }

    pub async fn header(&mut self) -> Result<&HeaderMap, DecodeStreamError> {
        todo!()
    }

    pub async fn context(
        &mut self,
    ) -> Result<StreamReader<impl Stream<Item = Result<Bytes, DecodeStreamError>>>, DecodeStreamError>
    {
        self.header().await?;

        Ok(StreamReader::new(Box::pin(stream::unfold(
            DataFramesReader::new(&mut self.context).await?,
            async move |reader| match reader?.next().await? {
                Ok((chunk, reader)) => Some((Ok(chunk), Some(reader))),
                Err(error) => Some((Err(error), None)),
            },
        ))))
    }
}

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn message() {
        let mut message = MessageDecoder {
            header: None,
            context: FrameDecoder::new(StreamReader::new(to_pre_byte_stream([
                0x00, // Type: DATA
                0x05, // Length: 5
                b'H', b'e', b'l', b'l', b'o', // Payload: "Hello"
                0x00, // Type: DATA
                0x05, // Length: 5
                b'W', b'o', b'r', b'l', b'd', // Payload: "World"
            ]))),
            trailer: None,
        };

        let mut reader = message.context().await.unwrap();
        let mut context = Vec::new();
        reader.read_to_end(&mut context).await.unwrap();
    }
}
