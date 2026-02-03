use super::{ReadStream, StreamError, WriteStream};

mod read;
mod tunnel_imp;
mod write;

pub use tunnel_imp::HasRemainingStream;
pub(crate) use tunnel_imp::RemainStream;
pub use write::SendMesageError;

pub mod tunnel {
    use std::future::poll_fn;

    pub use super::HasRemainingStream;
    use super::{ReadStream, WriteStream, tunnel_imp::Sealed};

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
