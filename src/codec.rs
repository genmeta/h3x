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

pub type BoxStreamReader<C> = StreamReader<Pin<Box<<C as quic::ManageStream>::StreamReader>>>;

/// Type alias for a peekable unidirectional stream.
pub type BoxPeekableUniStream<C> =
    PeekableStreamReader<Pin<Box<<C as quic::ManageStream>::StreamReader>>>;

/// Type alias for a peekable bidirectional stream pair.
pub type BoxPeekableBiStream<C> = (
    PeekableStreamReader<Pin<Box<<C as quic::ManageStream>::StreamReader>>>,
    SinkWriter<Pin<Box<<C as quic::ManageStream>::StreamWriter>>>,
);

/// Raw erased read stream: a pinned, boxed trait object for `quic::ReadStream`.
pub type BoxReadStream = Pin<Box<dyn quic::ReadStream + Send>>;

/// Raw erased write stream: a pinned, boxed trait object for `quic::WriteStream`.
pub type BoxWriteStream = Pin<Box<dyn quic::WriteStream + Send>>;

/// Erased (non-generic) stream reader wrapping a boxed `ReadStream` trait object.
pub type ErasedStreamReader = StreamReader<BoxReadStream>;

/// Erased (non-generic) sink writer wrapping a boxed `WriteStream` trait object.
pub type ErasedStreamWriter = SinkWriter<BoxWriteStream>;

/// Erased (non-generic) peekable unidirectional stream reader.
pub type ErasedPeekableUniStream = PeekableStreamReader<BoxReadStream>;

/// Erased (non-generic) peekable bidirectional stream pair.
pub type ErasedPeekableBiStream = (
    PeekableStreamReader<BoxReadStream>,
    SinkWriter<BoxWriteStream>,
);

pub trait EncodeInto<S>: Sized {
    type Output;
    type Error;

    fn encode_into(
        self,
        stream: S,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;
}

pub trait EncodeExt {
    fn encode<T>(self, item: T) -> impl Future<Output = Result<T::Output, T::Error>> + Send
    where
        Self: Sized,
        T: EncodeInto<Self>,
    {
        item.encode_into(self)
    }

    fn encode_one<'s, T>(&'s mut self, item: T) -> impl Future<Output = Result<T::Output, T::Error>>
    where
        Self: Sized,
        T: EncodeInto<&'s mut Self>,
    {
        item.encode_into(self)
    }

    fn into_encode_sink<T, Error>(self) -> impl Sink<T, Error = Error>
    where
        Self: Sized,
        for<'s> T: EncodeInto<&'s mut Self, Error = Error>,
    {
        futures::sink::unfold(self, |mut encoder, item: T| async move {
            item.encode_into(&mut encoder).await?;
            Ok(encoder)
        })
    }
}

impl<S: ?Sized> EncodeExt for S {}

pub trait DecodeFrom<S>: Sized {
    type Error;

    fn decode_from(stream: S) -> impl Future<Output = Result<Self, Self::Error>> + Send;
}

pub trait DecodeExt {
    fn decode<T>(self) -> impl Future<Output = Result<T, T::Error>> + Send
    where
        Self: Sized,
        T: DecodeFrom<Self>,
    {
        T::decode_from(self)
    }

    fn decode_one<'s, T>(&'s mut self) -> impl Future<Output = Result<T, T::Error>>
    where
        T: DecodeFrom<&'s mut Self>,
    {
        T::decode_from(self)
    }

    fn into_decode_stream<T, Error>(self) -> impl Stream<Item = Result<T, Error>>
    where
        Self: Sized,
        for<'s> T: DecodeFrom<&'s mut Self, Error = Error>,
        for<'s> &'s mut Self: AsyncBufRead,
        Error: From<io::Error>,
    {
        futures::stream::unfold(self, |mut decoder| async move {
            match (&mut decoder).fill_buf().await {
                Ok([]) => None,
                Ok(..) => match T::decode_from(&mut decoder).await {
                    Ok(item) => Some((Ok(item), decoder)),
                    Err(e) => Some((Err(e), decoder)),
                },
                Err(error) => Some((Err(error.into()), decoder)),
            }
        })
    }
}

impl<S: ?Sized> DecodeExt for S {}
