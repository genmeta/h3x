use bytes::Bytes;
use futures::{Stream, StreamExt, stream};

use super::super::{MessageStreamError, ReadStream};
use crate::codec::StreamReader;

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

    pub fn into_bytes_stream(
        self,
    ) -> impl Stream<Item = Result<Bytes, MessageStreamError>> + Send + 'static {
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
    ) -> StreamReader<impl Stream<Item = Result<Bytes, MessageStreamError>> + Send + 'static> {
        StreamReader::new(self.into_bytes_stream())
    }
}
