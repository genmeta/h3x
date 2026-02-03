#![allow(async_fn_in_trait)]

mod error;

mod reader;
mod writer;

pub use error::{DecodeError, DecodeStreamError, EncodeError, EncodeStreamError};
use futures::{Sink, stream::Stream};
pub use reader::{FixedLengthReader, StreamReader};
use tokio::io::{self, AsyncBufRead, AsyncBufReadExt};
pub use writer::{Feed, SinkWriter};

pub trait Encode<T>: Sized {
    type Output;
    type Error;

    async fn encode(self, item: T) -> Result<Self::Output, Self::Error>;
}

pub trait EncodeExt {
    async fn encode_one<'s, T>(
        &'s mut self,
        item: T,
    ) -> Result<<&'s mut Self as Encode<T>>::Output, <&'s mut Self as Encode<T>>::Error>
    where
        Self: Sized,
        &'s mut Self: Encode<T>,
    {
        Encode::encode(self, item).await
    }

    fn into_encode_sink<T, Error>(self) -> impl Sink<T, Error = Error>
    where
        Self: Sized,
        for<'s> &'s mut Self: Encode<T, Error = Error>,
    {
        futures::sink::unfold(self, |mut encoder, item| async move {
            (&mut encoder).encode(item).await?;
            Ok(encoder)
        })
    }
}

impl<T: ?Sized> EncodeExt for T {}

pub trait Decode<T>: Sized {
    type Error;

    async fn decode(self) -> Result<T, Self::Error>;
}

pub trait DecodeExt {
    async fn decode_one<'s, T>(&'s mut self) -> Result<T, <&'s mut Self as Decode<T>>::Error>
    where
        &'s mut Self: Decode<T>,
    {
        Decode::decode(self).await
    }

    async fn into_decoded<T>(self) -> Result<T, <Self as Decode<T>>::Error>
    where
        Self: Decode<T>,
    {
        Decode::decode(self).await
    }

    fn into_decode_stream<T, Error>(self) -> impl Stream<Item = Result<T, Error>>
    where
        Self: Sized,
        for<'s> &'s mut Self: Decode<T, Error = Error> + AsyncBufRead,
        Error: From<io::Error>,
    {
        futures::stream::unfold(self, |mut decoder| async move {
            match (&mut decoder).fill_buf().await {
                Ok([]) => None,
                Ok(..) => match (&mut decoder).decode().await {
                    Ok(item) => Some((Ok(item), decoder)),
                    Err(e) => Some((Err(e), decoder)),
                },
                Err(error) => Some((Err(error.into()), decoder)),
            }
        })
    }
}

impl<T: ?Sized> DecodeExt for T {}
