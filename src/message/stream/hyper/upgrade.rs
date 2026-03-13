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
use crate::message::stream::unfold::{read::BoxStreamReader, write::BoxStreamWriter};

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

#[derive(Clone)]
pub struct TakeoverSlot {
    state: Arc<Mutex<TakeoverState>>,
}

enum TakeoverState {
    Available {
        read: RemainStream<ReadStream>,
        write: RemainStream<WriteStream>,
    },
    Taken,
}

impl TakeoverSlot {
    pub fn new(read: RemainStream<ReadStream>, write: RemainStream<WriteStream>) -> Self {
        Self {
            state: Arc::new(Mutex::new(TakeoverState::Available { read, write })),
        }
    }

    pub fn take(&self) -> Result<PendingTakeover, TakeoverError> {
        let mut guard = self.state.lock().expect("poisoned mutex");
        match &*guard {
            TakeoverState::Available { .. } => (),
            TakeoverState::Taken => return Err(TakeoverError::AlreadyTaken),
        }

        let state = std::mem::replace(&mut *guard, TakeoverState::Taken);
        match state {
            TakeoverState::Available { read, write } => Ok(PendingTakeover { read, write }),
            TakeoverState::Taken => Err(TakeoverError::AlreadyTaken),
        }
    }
}

pub struct PendingTakeover {
    read: RemainStream<ReadStream>,
    write: RemainStream<WriteStream>,
}

impl PendingTakeover {
    pub async fn wait(
        self,
    ) -> Result<(BoxStreamReader<'static>, BoxStreamWriter<'static>), TakeoverError> {
        let write = self.write.await.ok_or(TakeoverError::Aborted)?;
        let read = self.read.await.ok_or(TakeoverError::Aborted)?;
        Ok((read.into_box_reader(), write.into_box_writer()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeoverError {
    AlreadyTaken,
    Aborted,
    BodyNotReleased,
}

pub trait TakeoverSealed {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<PendingTakeover>, TakeoverError>>;
}

fn poll_release_body<B: Body + Unpin>(
    body: &mut B,
    cx: &mut Context<'_>,
) -> Poll<Result<(), TakeoverError>> {
    loop {
        match ready!(Pin::new(&mut *body).poll_frame(cx)) {
            Some(Ok(_)) => continue,
            Some(Err(_)) => return Poll::Ready(Err(TakeoverError::BodyNotReleased)),
            None => return Poll::Ready(Ok(())),
        }
    }
}

fn take_legacy_pair(
    extensions: &mut http::Extensions,
) -> Result<Option<PendingTakeover>, TakeoverError> {
    let write = extensions.remove::<RemainStream<WriteStream>>();
    let read = extensions.remove::<RemainStream<ReadStream>>();
    match (read, write) {
        (Some(read), Some(write)) => Ok(Some(PendingTakeover { read, write })),
        (None, None) => Ok(None),
        (read, write) => {
            if let Some(read) = read {
                extensions.insert(read);
            }
            if let Some(write) = write {
                extensions.insert(write);
            }
            Ok(None)
        }
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

impl<R: Sealed<ReadStream>> HasRemainingStream<ReadStream> for R {}
impl<R: Sealed<WriteStream>> HasRemainingStream<WriteStream> for R {}

pub trait HasTakeover: TakeoverSealed {}

impl<R: TakeoverSealed> HasTakeover for R {}

impl<B: Body + Unpin> TakeoverSealed for http::Request<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<PendingTakeover>, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        if let Some(slot) = self.extensions().get::<TakeoverSlot>() {
            return Poll::Ready(slot.take().map(Some));
        }
        Poll::Ready(take_legacy_pair(self.extensions_mut()))
    }
}

impl<B: Body + Unpin> TakeoverSealed for http::Response<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<PendingTakeover>, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        if let Some(slot) = self.extensions().get::<TakeoverSlot>() {
            return Poll::Ready(slot.take().map(Some));
        }
        Poll::Ready(take_legacy_pair(self.extensions_mut()))
    }
}

impl<B: Body + Unpin> TakeoverSealed for &mut http::Request<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<PendingTakeover>, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        if let Some(slot) = self.extensions().get::<TakeoverSlot>() {
            return Poll::Ready(slot.take().map(Some));
        }
        Poll::Ready(take_legacy_pair(self.extensions_mut()))
    }
}

impl<B: Body + Unpin> TakeoverSealed for &mut http::Response<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<PendingTakeover>, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        if let Some(slot) = self.extensions().get::<TakeoverSlot>() {
            return Poll::Ready(slot.take().map(Some));
        }
        Poll::Ready(take_legacy_pair(self.extensions_mut()))
    }
}

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

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use http_body::{Body, Frame};

    use super::*;

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
    async fn takeover_returns_none_for_unsupported_message() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let result = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn takeover_returns_already_taken_when_taken_twice() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (_read_tx, read) = RemainStream::<ReadStream>::pending();
        let (_write_tx, write) = RemainStream::<WriteStream>::pending();
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(read, write));

        let first = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(matches!(first, Ok(Some(_))));

        let second = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(matches!(second, Err(TakeoverError::AlreadyTaken)));
    }

    #[tokio::test]
    async fn pending_takeover_wait_returns_aborted_when_write_not_ready() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (read_tx, read) = RemainStream::<ReadStream>::pending();
        let (write_tx, write) = RemainStream::<WriteStream>::pending();
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(read, write));

        let pending = poll_fn(|cx| request.poll_takeover(cx))
            .await
            .expect("takeover should succeed")
            .expect("takeover should be supported");

        drop(read_tx);
        drop(write_tx);

        let result = pending.wait().await;
        assert!(matches!(result, Err(TakeoverError::Aborted)));
    }

    #[tokio::test]
    async fn takeover_returns_body_not_released_on_body_error() {
        let mut request = http::Request::new(ErrorBody);
        let result = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(matches!(result, Err(TakeoverError::BodyNotReleased)));
    }
}
