use super::{ReadStream, StreamError, WriteStream};

mod read;
mod upgrade_impl;
mod write;

pub use upgrade_impl::HasRemainingStream;
pub(crate) use upgrade_impl::RemainStream;
pub use write::SendMesageError;

pub mod upgrade {
    use std::future::poll_fn;

    pub use super::HasRemainingStream;
    use super::{ReadStream, WriteStream, upgrade_impl::Sealed};

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
