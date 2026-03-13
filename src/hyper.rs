pub mod upgrade {
    use crate::hyper::takeover;
    pub use crate::message::stream::{
        hyper::upgrade::{HasTakeover, TakeoverError},
        unfold::{read::BoxStreamReader, write::BoxStreamWriter},
    };

    pub async fn on(
        message: impl HasTakeover,
    ) -> Result<(BoxStreamReader<'static>, BoxStreamWriter<'static>), TakeoverError> {
        let pending = takeover::take(message).await?;
        pending.wait().await
    }
}

pub mod takeover {
    use std::future::poll_fn;

    use crate::message::stream::hyper::upgrade::TakeoverSealed;
    pub use crate::message::stream::hyper::upgrade::{HasTakeover, PendingTakeover, TakeoverError};

    pub async fn take(mut message: impl HasTakeover) -> Result<PendingTakeover, TakeoverError> {
        poll_fn(|cx| TakeoverSealed::poll_takeover(&mut message, cx)).await
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

    use super::{takeover, upgrade};

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
        let explicit = takeover::take(http::Request::new(ErrorBody)).await;
        assert!(matches!(
            explicit,
            Err(crate::message::stream::hyper::upgrade::TakeoverError::BodyNotReleased)
        ));

        let compat = upgrade::on(http::Request::new(ErrorBody)).await;
        assert!(matches!(
            compat,
            Err(crate::message::stream::hyper::upgrade::TakeoverError::BodyNotReleased)
        ));
    }
}
