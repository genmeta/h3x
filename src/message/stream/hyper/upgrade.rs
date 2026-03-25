use std::{
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use http_body::Body;
use tokio::sync::oneshot;

use super::{ReadStream, WriteStream};
use crate::message::stream::{BoxMessageStreamReader, BoxMessageStreamWriter};

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
    ) -> Result<
        (
            BoxMessageStreamReader<'static>,
            BoxMessageStreamWriter<'static>,
        ),
        TakeoverError,
    > {
        let write = self.write.await.ok_or(TakeoverError::Aborted)?;
        let read = self.read.await.ok_or(TakeoverError::Aborted)?;
        Ok((read.into_box_reader(), write.into_box_writer()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeoverError {
    Unsupported,
    AlreadyTaken,
    Aborted,
    BodyNotReleased,
}

pub trait TakeoverSealed {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PendingTakeover, TakeoverError>>;
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

pub trait HasTakeover: TakeoverSealed {}

impl<R: TakeoverSealed> HasTakeover for R {}

impl<B: Body + Unpin> TakeoverSealed for http::Request<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PendingTakeover, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        if let Some(slot) = self.extensions().get::<TakeoverSlot>() {
            return Poll::Ready(slot.take());
        }
        Poll::Ready(Err(TakeoverError::Unsupported))
    }
}

impl<B: Body + Unpin> TakeoverSealed for http::Response<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PendingTakeover, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        if let Some(slot) = self.extensions().get::<TakeoverSlot>() {
            return Poll::Ready(slot.take());
        }
        Poll::Ready(Err(TakeoverError::Unsupported))
    }
}

impl<B: Body + Unpin> TakeoverSealed for &mut http::Request<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PendingTakeover, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        if let Some(slot) = self.extensions().get::<TakeoverSlot>() {
            return Poll::Ready(slot.take());
        }
        Poll::Ready(Err(TakeoverError::Unsupported))
    }
}

impl<B: Body + Unpin> TakeoverSealed for &mut http::Response<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PendingTakeover, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        if let Some(slot) = self.extensions().get::<TakeoverSlot>() {
            return Poll::Ready(slot.take());
        }
        Poll::Ready(Err(TakeoverError::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
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
    async fn takeover_returns_unsupported_for_unsupported_message() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let result = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(matches!(result, Err(TakeoverError::Unsupported)));
    }

    #[tokio::test]
    async fn takeover_returns_pending_when_slot_available() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (_read_tx, read) = RemainStream::<ReadStream>::pending();
        let (_write_tx, write) = RemainStream::<WriteStream>::pending();
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(read, write));

        let result = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(result.is_ok());
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
        assert!(first.is_ok());

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
            .expect("takeover should succeed");

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
