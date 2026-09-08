use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};

use crate::Error;

type BoxBody = Pin<Box<dyn HttpBody<Data = Bytes, Error = Error> + Send + 'static>>;

/// Streaming body of a received HTTP/3 request or response.
///
/// The underlying request stream is polled only when the consumer polls this
/// body, so transport backpressure is preserved.
pub struct Body {
    inner: BoxBody,
}

impl Body {
    pub(crate) fn new(body: impl HttpBody<Data = Bytes, Error = Error> + Send + 'static) -> Self {
        Self {
            inner: Box::pin(body),
        }
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Body").finish_non_exhaustive()
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.inner.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::{BodyExt, Full};

    use super::*;

    #[tokio::test]
    async fn delegates_frames_and_size_hints_without_buffering() {
        let inner = Full::new(Bytes::from_static(b"payload")).map_err(|never| match never {});
        let mut body = Body::new(inner);

        assert_eq!(body.size_hint().exact(), Some(7));
        let data = body
            .frame()
            .await
            .expect("one frame")
            .expect("valid frame")
            .into_data()
            .expect("data frame");
        assert_eq!(data, Bytes::from_static(b"payload"));
        assert!(body.frame().await.is_none());
    }
}
