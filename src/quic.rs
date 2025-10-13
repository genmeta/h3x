use bytes::Bytes;
use futures::{Sink, Stream};

use crate::error::{ConnectionError, StreamError};

#[async_trait::async_trait]
pub trait QuicConnection {
    type StreamWriter: WriteStream;
    type StreamReader: ReadStream;

    async fn open_bi(
        &mut self,
    ) -> Result<(Self::StreamWriter, Self::StreamReader), ConnectionError>;

    async fn open_uni(&mut self) -> Result<Self::StreamWriter, ConnectionError>;

    async fn accept_bi(
        &mut self,
    ) -> Result<(Self::StreamWriter, Self::StreamReader), ConnectionError>;

    async fn accept_uni(&mut self) -> Result<Self::StreamReader, ConnectionError>;
}

pub trait WriteStream: Sink<Bytes, Error = StreamError> {
    fn reset(&mut self, code: u64);
}

pub trait ReadStream: Stream<Item = Result<Bytes, StreamError>> {
    fn stop_sending(&mut self, code: u64);
}
