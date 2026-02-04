pub mod upgrade {
    use std::future::poll_fn;

    pub use crate::message::stream::hyper::upgrade::HasRemainingStream;
    use crate::message::stream::{ReadStream, WriteStream, hyper::upgrade::Sealed};

    pub async fn on(
        mut message: impl HasRemainingStream<ReadStream> + HasRemainingStream<WriteStream>,
    ) -> Option<(ReadStream, WriteStream)> {
        let write_stream = poll_fn(|cx| Sealed::<WriteStream>::poll_extract(&mut message, cx))
            .await?
            .await?;
        let read_stream = poll_fn(|cx| Sealed::<ReadStream>::poll_extract(&mut message, cx))
            .await?
            .await?;
        Some((read_stream, write_stream))
    }
}

pub mod ext {
    pub use crate::qpack::field::Protocol;
}

pub use crate::message::stream::hyper::write::SendMesageError;

pub mod client;
