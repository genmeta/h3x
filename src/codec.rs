use std::{future::Future, pin::Pin};

use crate::quic;

mod error;
mod reader;
mod writer;

pub use error::{
    ConnectionDecodeError, ConnectionEncodeError, DecodeError, EncodeError, StreamDecodeError,
    StreamEncodeError,
};
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

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::StreamExt;
    use tokio::io::{AsyncRead, ReadBuf};

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct FailingItem;

    #[derive(Debug, PartialEq, Eq)]
    enum TestDecodeError {
        Decode,
        Io(io::ErrorKind),
    }

    impl From<io::Error> for TestDecodeError {
        fn from(error: io::Error) -> Self {
            Self::Io(error.kind())
        }
    }

    impl<'s, S> DecodeFrom<&'s mut S> for FailingItem
    where
        S: AsyncBufRead + Send + 's,
    {
        type Error = TestDecodeError;

        async fn decode_from(_stream: &'s mut S) -> Result<Self, Self::Error> {
            Err(TestDecodeError::Decode)
        }
    }

    struct FailingRead;

    impl AsyncRead for FailingRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("read failed")))
        }
    }

    #[tokio::test]
    async fn into_decode_stream_yields_item_decode_errors() {
        let decoder = io::Cursor::new([1]);
        let stream = decoder.into_decode_stream::<FailingItem, TestDecodeError>();
        futures::pin_mut!(stream);

        assert_eq!(stream.next().await, Some(Err(TestDecodeError::Decode)));
    }

    #[tokio::test]
    async fn into_decode_stream_yields_io_errors() {
        let decoder = tokio::io::BufReader::new(FailingRead);
        let stream = decoder.into_decode_stream::<FailingItem, TestDecodeError>();
        futures::pin_mut!(stream);

        assert_eq!(
            stream.next().await,
            Some(Err(TestDecodeError::Io(io::ErrorKind::Other)))
        );
    }
}
