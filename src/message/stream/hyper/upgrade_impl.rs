use std::{
    future::poll_fn,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use http_body::Body;
use tokio::sync::oneshot;

use super::{ReadStream, WriteStream};

pub struct RemainStream<S> {
    rx: Arc<Mutex<oneshot::Receiver<S>>>,
}

impl<S> Clone for RemainStream<S> {
    fn clone(&self) -> Self {
        Self {
            rx: self.rx.clone(),
        }
    }
}

impl<S> RemainStream<S> {
    pub fn pending() -> (oneshot::Sender<S>, Self) {
        let (tx, rx) = oneshot::channel();
        (
            tx,
            Self {
                rx: Arc::new(Mutex::new(rx)),
            },
        )
    }

    pub fn immediately(stream: S) -> Self {
        let (tx, this) = Self::pending();
        _ = tx.send(stream);
        this
    }
}

impl<S> Future for RemainStream<S> {
    type Output = Option<S>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut rx = self.get_mut().rx.lock().expect("poisoned mutex");
        Pin::new(rx.deref_mut()).poll(cx).map(Result::ok)
    }
}

pub trait Sealed<S> {
    fn poll_extract(&mut self, cx: &mut Context<'_>) -> Poll<Option<RemainStream<S>>>;
}

impl<S: Send + 'static, B: Body + Unpin> Sealed<S> for http::Request<B> {
    fn poll_extract(&mut self, cx: &mut Context<'_>) -> Poll<Option<RemainStream<S>>> {
        while ready!(Pin::new(self.body_mut()).poll_frame(cx)).is_some() {}
        Poll::Ready(self.extensions_mut().remove::<RemainStream<S>>())
    }
}

impl<S: Send + 'static, B: Body + Unpin> Sealed<S> for http::Response<B> {
    fn poll_extract(&mut self, cx: &mut Context<'_>) -> Poll<Option<RemainStream<S>>> {
        while ready!(Pin::new(self.body_mut()).poll_frame(cx)).is_some() {}
        Poll::Ready(self.extensions_mut().remove::<RemainStream<S>>())
    }
}

impl<S: Send + 'static, B: Body + Unpin> Sealed<S> for &mut http::Request<B> {
    fn poll_extract(&mut self, cx: &mut Context<'_>) -> Poll<Option<RemainStream<S>>> {
        while ready!(Pin::new(self.body_mut()).poll_frame(cx)).is_some() {}
        Poll::Ready(self.extensions_mut().remove::<RemainStream<S>>())
    }
}

impl<S: Send + 'static, B: Body + Unpin> Sealed<S> for &mut http::Response<B> {
    fn poll_extract(&mut self, cx: &mut Context<'_>) -> Poll<Option<RemainStream<S>>> {
        while ready!(Pin::new(self.body_mut()).poll_frame(cx)).is_some() {}
        Poll::Ready(self.extensions_mut().remove::<RemainStream<S>>())
    }
}

pub trait HasRemainingStream<S>: Sealed<S> {}

impl<S, R: Sealed<S>> HasRemainingStream<S> for R {}

impl ReadStream {
    /// Extract the remaining ReadStream from hyper Request/Response.
    ///
    /// This method will consume all remaining body frames, then return the
    /// RemainReadStream if exists.
    pub async fn extract_from(mut message: impl HasRemainingStream<Self>) -> Option<Self> {
        poll_fn(|cx| message.poll_extract(cx)).await?.await
    }
}

impl WriteStream {
    pub async fn extract_from(mut message: impl HasRemainingStream<Self>) -> Option<Self> {
        poll_fn(|cx| message.poll_extract(cx)).await?.await
    }
}
