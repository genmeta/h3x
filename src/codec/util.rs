use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, stream};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::codec::error::{DecodeStreamError, EncodeStreamError};

pub(crate) trait DecodeFrom<S>: Sized {
    async fn decode_from(stream: S) -> Result<Self, DecodeStreamError>;
}

pub(crate) trait EncodeInto<S>: Sized {
    async fn encode_into(self, stream: S) -> Result<(), EncodeStreamError>;
}

impl<S: Sink<Bytes>> EncodeInto<S> for Bytes
where
    EncodeStreamError: From<S::Error>,
{
    async fn encode_into(self, stream: S) -> Result<(), EncodeStreamError> {
        tokio::pin!(stream);
        stream.feed(self).await?;
        Ok(())
    }
}

pub(crate) fn decoder<Item, S>(stream: S) -> impl Stream<Item = Result<Item, DecodeStreamError>>
where
    S: AsyncBufRead + Unpin,
    Item: for<'s> DecodeFrom<&'s mut S>,
{
    stream::unfold(stream, move |mut stream| async move {
        match stream.fill_buf().await {
            Ok([]) => None,
            Ok(..) => Some((Item::decode_from(&mut stream).await, stream)),
            Err(error) => Some((Err(error.into()), stream)),
        }
    })
}

pub(crate) fn encoder<T: for<'s> EncodeInto<&'s mut S>, S>(
    stream: S,
) -> impl Sink<T, Error = EncodeStreamError> {
    futures::sink::unfold(stream, |mut stream, item: T| async move {
        item.encode_into(&mut stream).await?;
        Ok(stream)
    })
}
