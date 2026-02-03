use bytes::Bytes;
use futures::{Stream, stream};

use super::super::{ReadStream, StreamError};

impl ReadStream {
    pub fn as_bytes_stream(&mut self) -> impl Stream<Item = Result<Bytes, StreamError>> {
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
    }

    pub fn into_bytes_stream(
        self,
    ) -> impl Stream<Item = Result<Bytes, StreamError>> + Send + 'static {
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
    }
}
