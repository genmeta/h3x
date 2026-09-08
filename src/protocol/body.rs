use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};

use crate::Error;

pub(crate) mod writer;
pub use writer::BodyWriter;

/// Complete in-memory request content.
#[derive(Debug, Default)]
pub struct Fixed {
    body: http_body_util::Full<Bytes>,
}

impl From<Bytes> for Fixed {
    fn from(data: Bytes) -> Self {
        Self {
            body: http_body_util::Full::new(data),
        }
    }
}

impl HttpBody for Fixed {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// Construction marker for a streaming request. No pipe exists until execution.
#[derive(Debug)]
pub struct Chunk;

/// An HTTP body that reads the receive stream only when polled.
pub struct ChunkBody {
    inner: Option<UnsyncBoxBody<Bytes, Error>>,
}

impl fmt::Debug for ChunkBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkBody")
            .field("ended", &self.inner.is_none())
            .finish_non_exhaustive()
    }
}

impl ChunkBody {
    pub(crate) fn new(body: impl HttpBody<Data = Bytes, Error = Error> + Send + 'static) -> Self {
        Self {
            inner: Some(body.boxed_unsync()),
        }
    }
}

impl HttpBody for ChunkBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let Some(body) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };
        let frame = std::task::ready!(Pin::new(body).poll_frame(cx));
        if !matches!(frame, Some(Ok(_))) {
            // Release the reader and request quota immediately on EOF or error.
            self.inner.take();
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        if self.inner.is_none() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::default()
        }
    }
}
