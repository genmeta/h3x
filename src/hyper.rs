pub mod upgrade {
    use std::{future::poll_fn, pin::Pin};

    use bytes::Bytes;
    use futures::{Sink, Stream};

    pub use crate::message::stream::hyper::upgrade::HasRemainingStream;
    use crate::{
        codec,
        message::stream::{ReadStream, StreamError, WriteStream, hyper::upgrade::Sealed},
    };

    pub type StreamReader =
        codec::StreamReader<Pin<Box<dyn Stream<Item = Result<Bytes, StreamError>> + Send>>>;
    pub type StreamWriter =
        codec::SinkWriter<Pin<Box<dyn Sink<Bytes, Error = StreamError> + Send>>>;

    pub async fn on(
        mut message: impl HasRemainingStream<ReadStream> + HasRemainingStream<WriteStream>,
    ) -> Option<(StreamReader, StreamWriter)> {
        let write_stream = poll_fn(|cx| Sealed::<WriteStream>::poll_extract(&mut message, cx))
            .await?
            .await?;
        let read_stream = poll_fn(|cx| Sealed::<ReadStream>::poll_extract(&mut message, cx))
            .await?
            .await?;
        Some((
            StreamReader::new(Box::pin(read_stream.into_bytes_stream())),
            StreamWriter::new(Box::pin(write_stream.into_bytes_sink())),
        ))
    }
}

pub mod ext {
    pub use crate::qpack::field::Protocol;
}

pub use crate::message::stream::hyper::write::SendMesageError;

pub mod client;
pub mod server;
