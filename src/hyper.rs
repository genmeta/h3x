#[doc(alias = "takeover")]
pub mod upgrade {
    use std::future::poll_fn;

    pub use crate::dhttp::message::{
        BoxMessageReader, BoxMessageWriter, MessageReader, MessageWriter,
        hyper::upgrade::{HasTakeover, MissingStream, TakeoverError, TakeoverSlot, UpgradeError},
    };

    pub async fn take<T: Send + 'static>(
        mut message: impl HasTakeover<T>,
    ) -> Result<T, TakeoverError> {
        poll_fn(|cx| HasTakeover::<T>::poll_takeover(&mut message, cx)).await
    }

    #[doc(alias = "take")]
    pub async fn on(
        mut message: impl HasTakeover<MessageReader> + HasTakeover<MessageWriter>,
    ) -> Result<(BoxMessageReader, BoxMessageWriter), UpgradeError> {
        let read = match poll_fn(|cx| HasTakeover::<MessageReader>::poll_takeover(&mut message, cx))
            .await
        {
            Ok(read) => Some(read),
            Err(TakeoverError::Unsupported) => None,
            Err(source) => return Err(UpgradeError::Takeover { source }),
        };
        let write =
            match poll_fn(|cx| HasTakeover::<MessageWriter>::poll_takeover(&mut message, cx)).await
            {
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

pub mod extended_connect {
    pub use crate::extended_connect::hyper::*;
}

pub use crate::dhttp::message::hyper::{RequestError, SendMessageError, client};
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
    use crate::{
        dhttp::message::{
            hyper::upgrade::{
                MissingStream, RemainStream, TakeoverError, TakeoverSlot, UpgradeError,
            },
            test::{read_stream_for_test, write_stream_for_test},
        },
        quic::GetStreamIdExt,
        varint::VarInt,
    };

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
                crate::dhttp::message::hyper::upgrade::UpgradeError::Takeover {
                    source: crate::dhttp::message::hyper::upgrade::TakeoverError::BodyNotReleased,
                }
            )
        ));
    }

    #[tokio::test]
    async fn take_returns_unsupported_when_no_takeover_slot() {
        let request = http::Request::new(http_body_util::Empty::<Bytes>::new());

        let result = upgrade::take::<upgrade::MessageReader>(request).await;
        assert!(matches!(result, Err(TakeoverError::Unsupported)));
    }

    #[tokio::test]
    async fn take_releases_empty_body_and_returns_stream() {
        let request = {
            let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
            let stream = read_stream_for_test(VarInt::from_u32(55));
            request
                .extensions_mut()
                .insert(TakeoverSlot::new(RemainStream::immediately(stream)));
            request
        };
        let mut read_stream = upgrade::take::<upgrade::MessageReader>(request)
            .await
            .unwrap();
        let stream_id = GetStreamIdExt::stream_id(&mut read_stream).await.unwrap();
        assert_eq!(stream_id, VarInt::from_u32(55));
    }

    #[tokio::test]
    async fn upgrade_with_missing_read_or_write_stream_reports_incomplete() {
        let request = {
            let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
            request
                .extensions_mut()
                .insert(TakeoverSlot::new(RemainStream::immediately(
                    read_stream_for_test(VarInt::from_u32(11)),
                )));
            request
        };

        assert!(matches!(
            upgrade::on(request).await,
            Err(UpgradeError::Incomplete {
                missing: MissingStream::Write
            })
        ));

        let request = {
            let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
            request
                .extensions_mut()
                .insert(TakeoverSlot::new(RemainStream::immediately(
                    write_stream_for_test(VarInt::from_u32(22)),
                )));
            request
        };

        assert!(matches!(
            upgrade::on(request).await,
            Err(UpgradeError::Incomplete {
                missing: MissingStream::Read
            })
        ));

        let request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        assert!(matches!(
            upgrade::on(request).await,
            Err(UpgradeError::Incomplete {
                missing: MissingStream::Both
            })
        ));
    }

    #[tokio::test]
    async fn upgrade_requires_both_read_and_write_stream() {
        let request = {
            let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
            request
                .extensions_mut()
                .insert(TakeoverSlot::new(RemainStream::immediately(
                    read_stream_for_test(VarInt::from_u32(33)),
                )));
            request
                .extensions_mut()
                .insert(TakeoverSlot::new(RemainStream::immediately(
                    write_stream_for_test(VarInt::from_u32(44)),
                )));
            request
        };
        let (mut read_stream, mut write_stream) = upgrade::on(request).await.unwrap();

        let read_id = GetStreamIdExt::stream_id(&mut read_stream).await.unwrap();
        let write_id = GetStreamIdExt::stream_id(&mut write_stream).await.unwrap();
        assert_eq!(read_id, VarInt::from_u32(33));
        assert_eq!(write_id, VarInt::from_u32(44));
    }

    #[tokio::test]
    async fn upgrade_fails_when_stream_already_taken() {
        let mut request = {
            let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
            request
                .extensions_mut()
                .insert(TakeoverSlot::new(RemainStream::immediately(
                    read_stream_for_test(VarInt::from_u32(66)),
                )));
            request
                .extensions_mut()
                .insert(TakeoverSlot::new(RemainStream::immediately(
                    write_stream_for_test(VarInt::from_u32(77)),
                )));
            request
        };

        let _ = upgrade::take::<upgrade::MessageReader>(&mut request)
            .await
            .unwrap();

        assert!(matches!(
            upgrade::on(&mut request).await,
            Err(UpgradeError::Takeover {
                source: TakeoverError::AlreadyTaken
            })
        ));
    }
}
