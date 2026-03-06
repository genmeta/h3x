use std::{future::Future, pin::Pin};

use crate::quic;

mod error;
mod reader;
mod writer;

pub use error::{DecodeError, DecodeStreamError, EncodeError, EncodeStreamError};
use futures::{Sink, stream::Stream};
pub use reader::{FixedLengthReader, PeekableStreamReader, StreamReader};
use tokio::io::{self, AsyncBufRead, AsyncBufReadExt};
pub use writer::{Feed, SinkWriter};

pub type BoxStreamWriter<C> = SinkWriter<Pin<Box<<C as quic::ManageStream>::StreamWriter>>>;
pub type BoxStreamReader<C> = StreamReader<Pin<Box<<C as quic::ManageStream>::StreamReader>>>;

/// Type alias for a `StreamReader` wrapping a boxed unidirectional read stream.
pub type BoxQuicStreamReader<C> = StreamReader<Pin<Box<<C as quic::ManageStream>::StreamReader>>>;

/// Type alias for a peekable unidirectional stream.
pub type BoxPeekableUniStream<C> =
    PeekableStreamReader<Pin<Box<<C as quic::ManageStream>::StreamReader>>>;

/// Type alias for a peekable bidirectional stream pair.
pub type BoxPeekableBiStream<C> = (
    PeekableStreamReader<Pin<Box<<C as quic::ManageStream>::StreamReader>>>,
    SinkWriter<Pin<Box<<C as quic::ManageStream>::StreamWriter>>>,
);

pub trait Encode<T>: Sized {
    type Output;
    type Error;

    fn encode(self, item: T) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;
}

pub trait EncodeExt {
    fn encode_one<'s, T>(
        &'s mut self,
        item: T,
    ) -> impl Future<
        Output = Result<<&'s mut Self as Encode<T>>::Output, <&'s mut Self as Encode<T>>::Error>,
    >
    where
        Self: Sized,
        &'s mut Self: Encode<T>,
    {
        Encode::encode(self, item)
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

    fn decode(self) -> impl Future<Output = Result<T, Self::Error>> + Send;
}

pub trait DecodeExt {
    fn decode_one<'s, T>(
        &'s mut self,
    ) -> impl Future<Output = Result<T, <&'s mut Self as Decode<T>>::Error>>
    where
        &'s mut Self: Decode<T>,
    {
        Decode::decode(self)
    }

    fn into_decoded<T>(self) -> impl Future<Output = Result<T, <Self as Decode<T>>::Error>>
    where
        Self: Decode<T>,
    {
        Decode::decode(self)
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
