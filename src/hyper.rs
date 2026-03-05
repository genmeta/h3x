pub mod upgrade {
    use std::future::poll_fn;

    use crate::message::stream::{ReadStream, WriteStream, hyper::upgrade::Sealed};
    pub use crate::message::stream::{
        hyper::upgrade::HasRemainingStream,
        unfold::{read::BoxStreamReader, write::BoxStreamWriter},
    };

    pub async fn on(
        mut message: impl HasRemainingStream<ReadStream> + HasRemainingStream<WriteStream>,
    ) -> Option<(BoxStreamReader<'static>, BoxStreamWriter<'static>)> {
        let write_stream = poll_fn(|cx| Sealed::<WriteStream>::poll_extract(&mut message, cx))
            .await?
            .await?;
        let read_stream = poll_fn(|cx| Sealed::<ReadStream>::poll_extract(&mut message, cx))
            .await?
            .await?;
        Some((
            read_stream.into_box_reader(),
            write_stream.into_box_writer(),
        ))
    }
}

pub mod ext {
    pub use crate::qpack::field::Protocol;
}

pub use crate::message::stream::hyper::write::SendMesageError;

pub mod client;
pub mod server;
