use std::pin::Pin;

use bytes::Bytes;
use futures::{Stream, StreamExt, stream};

use super::super::{MessageStreamError, ReadStream};
use crate::codec::StreamReader;

pub type BoxStreamReader<'s> =
    StreamReader<Pin<Box<dyn Stream<Item = Result<Bytes, MessageStreamError>> + Send + 's>>>;

impl ReadStream {
    pub fn as_bytes_stream(&mut self) -> impl Stream<Item = Result<Bytes, MessageStreamError>> {
        stream::unfold(self, |this| async move {
            match this
                .try_stream_io(async |this| this.read_data_frame_chunk().await.transpose())
                .await
                .transpose()?
            {
                Ok(bytes) => Some((Ok(bytes), this)),
                Err(error) => Some((Err(error), this)),
            }
        })
        .fuse()
    }

    pub fn as_reader(
        &mut self,
    ) -> StreamReader<impl Stream<Item = Result<Bytes, MessageStreamError>>> {
        StreamReader::new(self.as_bytes_stream())
    }

    pub fn as_box_reader(&mut self) -> BoxStreamReader<'_> {
        StreamReader::new(Box::pin(self.as_bytes_stream()))
    }

    pub fn into_bytes_stream(self) -> impl Stream<Item = Result<Bytes, MessageStreamError>> {
        stream::unfold(self, |mut this| async move {
            match this
                .try_stream_io(async |this| this.read_data_frame_chunk().await.transpose())
                .await
                .transpose()?
            {
                Ok(bytes) => Some((Ok(bytes), this)),
                Err(error) => Some((Err(error), this)),
            }
        })
        .fuse()
    }

    pub fn into_reader(
        self,
    ) -> StreamReader<impl Stream<Item = Result<Bytes, MessageStreamError>>> {
        StreamReader::new(self.into_bytes_stream())
    }

    pub fn into_box_reader(self) -> BoxStreamReader<'static> {
        StreamReader::new(Box::pin(self.into_bytes_stream()))
    }
}
