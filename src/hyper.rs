#[doc(alias = "takeover")]
pub mod upgrade {
    use std::future::poll_fn;

    pub use crate::message::stream::{
        BoxMessageStreamReader, BoxMessageStreamWriter, ReadStream, WriteStream,
        hyper::upgrade::{HasTakeover, MissingStream, TakeoverError, TakeoverSlot, UpgradeError},
    };

    pub async fn take<T: Send + 'static>(
        mut message: impl HasTakeover<T>,
    ) -> Result<T, TakeoverError> {
        poll_fn(|cx| HasTakeover::<T>::poll_takeover(&mut message, cx)).await
    }

    #[doc(alias = "take")]
    pub async fn on(
        mut message: impl HasTakeover<ReadStream> + HasTakeover<WriteStream>,
    ) -> Result<
        (
            BoxMessageStreamReader<'static>,
            BoxMessageStreamWriter<'static>,
        ),
        UpgradeError,
    > {
        let read =
            match poll_fn(|cx| HasTakeover::<ReadStream>::poll_takeover(&mut message, cx)).await {
                Ok(read) => Some(read),
                Err(TakeoverError::Unsupported) => None,
                Err(source) => return Err(UpgradeError::Takeover { source }),
            };
        let write =
            match poll_fn(|cx| HasTakeover::<WriteStream>::poll_takeover(&mut message, cx)).await {
                Ok(write) => Some(write),
                Err(TakeoverError::Unsupported) => None,
                Err(source) => return Err(UpgradeError::Takeover { source }),
            };

        match (read, write) {
            (Some(read), Some(write)) => Ok((read.into_box_reader(), write.into_box_writer())),
            (Some(_), None) => Err(UpgradeError::Incomplete {
                missing: MissingStream::Write,
            }),
            (None, Some(_)) => Err(UpgradeError::Incomplete {
                missing: MissingStream::Read,
            }),
            (None, None) => Err(UpgradeError::Incomplete {
                missing: MissingStream::Both,
            }),
        }
    }
}

pub mod ext {
    pub use crate::qpack::field::Protocol;
}

pub use crate::message::stream::hyper::write::SendMessageError;

pub mod client;
pub mod server;

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use http_body::{Body, Frame};

    use super::upgrade;

    #[derive(Debug, Clone)]
    struct ErrorBody;

    impl Body for ErrorBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(Some(Err(std::io::Error::other("body error"))))
        }
    }

    #[tokio::test]
    async fn explicit_takeover_and_upgrade_on_both_surface_body_not_released() {
        let compat = upgrade::on(http::Request::new(ErrorBody)).await;
        assert!(matches!(
            compat,
            Err(
                crate::message::stream::hyper::upgrade::UpgradeError::Takeover {
                    source: crate::message::stream::hyper::upgrade::TakeoverError::BodyNotReleased,
                }
            )
        ));
    }
}
