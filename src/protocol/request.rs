use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::future::AbortHandle;
use tokio::sync::oneshot;

use crate::{ChunkBody, Error};

/// Waiting for final response headers owns only the receive direction.
pub struct ResponseFuture {
    pub(crate) reply: oneshot::Receiver<Result<http::Response<ChunkBody>, Error>>,
    pub(crate) stop: Option<AbortHandle>,
}

impl Future for ResponseFuture {
    type Output = Result<http::Response<ChunkBody>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = std::task::ready!(Pin::new(&mut self.reply).poll(cx));
        self.stop.take();
        Poll::Ready(result.unwrap_or(Err(Error::OwnerStopped)))
    }
}

impl Drop for ResponseFuture {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.abort();
        }
    }
}
