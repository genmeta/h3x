use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, stream};
use tokio::io::{self, AsyncBufRead, AsyncBufReadExt};

pub(crate) trait DecodeFrom<S>: Sized {
    type Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error>;
}

pub(crate) trait EncodeInto<S>: Sized {
    type Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error>;
}

impl<S: Sink<Bytes>> EncodeInto<S> for Bytes {
    type Error = S::Error;

    async fn encode_into(self, stream: S) -> Result<(), S::Error> {
        tokio::pin!(stream);
        stream.feed(self).await?;
        Ok(())
    }
}

pub(crate) fn decoder<Item, E, S>(stream: S) -> impl Stream<Item = Result<Item, E>>
where
    E: From<io::Error>,
    Item: for<'s> DecodeFrom<&'s mut S, Error = E>,
    S: AsyncBufRead + Unpin,
{
    stream::unfold(stream, move |mut stream| async move {
        match stream.fill_buf().await {
            Ok([]) => None,
            Ok(..) => Some((Item::decode_from(&mut stream).await, stream)),
            Err(error) => Some((Err(error.into()), stream)),
        }
    })
}

pub(crate) fn encoder<Item, E, S>(stream: S) -> impl Sink<Item, Error = E>
where
    Item: for<'s> EncodeInto<&'s mut S, Error = E>,
{
    futures::sink::unfold(stream, |mut stream, item: Item| async move {
        item.encode_into(&mut stream).await?;
        Ok(stream)
    })
}
