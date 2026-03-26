use std::{
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use http_body::Body;
use snafu::Snafu;
use tokio::sync::oneshot;

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

pub struct TakeoverSlot<T> {
    state: Arc<Mutex<TakeoverState<T>>>,
}

impl<T> Clone for TakeoverSlot<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

enum TakeoverState<T> {
    Available { stream: RemainStream<T> },
    Taken,
}

impl<T> TakeoverSlot<T> {
    pub fn new(stream: RemainStream<T>) -> Self {
        Self {
            state: Arc::new(Mutex::new(TakeoverState::Available { stream })),
        }
    }

    pub fn poll_take(&self, cx: &mut Context<'_>) -> Poll<Result<T, TakeoverError>> {
        let mut guard = self.state.lock().expect("poisoned mutex");
        match &mut *guard {
            TakeoverState::Available { stream } => match ready!(Pin::new(stream).poll(cx)) {
                Some(value) => {
                    *guard = TakeoverState::Taken;
                    Poll::Ready(Ok(value))
                }
                None => {
                    *guard = TakeoverState::Taken;
                    Poll::Ready(Err(TakeoverError::Aborted))
                }
            },
            TakeoverState::Taken => Poll::Ready(Err(TakeoverError::AlreadyTaken)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
pub enum TakeoverError {
    #[snafu(display("takeover stream is unsupported on this message"))]
    Unsupported,
    #[snafu(display("stream already taken"))]
    AlreadyTaken,
    #[snafu(display("stream provider was dropped before delivery"))]
    Aborted,
    #[snafu(display("message body could not be released"))]
    BodyNotReleased,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(module, visibility(pub))]
pub enum UpgradeError {
    #[snafu(display("failed to take over stream"))]
    Takeover { source: TakeoverError },
    #[snafu(display("upgrade incomplete, missing {missing} stream"))]
    Incomplete { missing: MissingStream },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingStream {
    Read,
    Write,
    Both,
}

impl std::fmt::Display for MissingStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MissingStream::Read => f.write_str("read"),
            MissingStream::Write => f.write_str("write"),
            MissingStream::Both => f.write_str("read and write"),
        }
    }
}

impl From<TakeoverError> for UpgradeError {
    fn from(source: TakeoverError) -> Self {
        UpgradeError::Takeover { source }
    }
}

mod sealed {
    use super::*;

    pub trait SealedTakeover<T> {
        fn poll_takeover(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, TakeoverError>>;
    }
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

fn poll_take_slot<T: Send + 'static>(
    extensions: &http::Extensions,
    cx: &mut Context<'_>,
) -> Poll<Result<T, TakeoverError>> {
    let slot = extensions
        .get::<TakeoverSlot<T>>()
        .ok_or(TakeoverError::Unsupported)?;
    slot.poll_take(cx)
}

pub trait HasTakeover<T> {
    fn poll_takeover(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, TakeoverError>>;
}

impl<M, T> HasTakeover<T> for M
where
    M: sealed::SealedTakeover<T>,
{
    fn poll_takeover(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, TakeoverError>> {
        sealed::SealedTakeover::poll_takeover(self, cx)
    }
}

impl<B: Body + Unpin, T: Send + 'static> sealed::SealedTakeover<T> for http::Request<B> {
    fn poll_takeover(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        poll_take_slot(self.extensions(), cx)
    }
}

impl<B: Body + Unpin, T: Send + 'static> sealed::SealedTakeover<T> for http::Response<B> {
    fn poll_takeover(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        poll_take_slot(self.extensions(), cx)
    }
}

impl<B: Body + Unpin, T: Send + 'static> sealed::SealedTakeover<T> for &mut http::Request<B> {
    fn poll_takeover(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        poll_take_slot(self.extensions(), cx)
    }
}

impl<B: Body + Unpin, T: Send + 'static> sealed::SealedTakeover<T> for &mut http::Response<B> {
    fn poll_takeover(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, TakeoverError>> {
        ready!(poll_release_body(self.body_mut(), cx))?;
        poll_take_slot(self.extensions(), cx)
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
    use crate::message::stream::ReadStream;

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
    async fn takeover_returns_unsupported_when_slot_missing() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let result = poll_fn(|cx| HasTakeover::<ReadStream>::poll_takeover(&mut request, cx)).await;
        assert!(matches!(result, Err(TakeoverError::Unsupported)));
    }

    #[tokio::test]
    async fn takeover_returns_ready_when_slot_available() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (read_tx, read) = RemainStream::<ReadStream>::pending();
        request.extensions_mut().insert(TakeoverSlot::new(read));

        drop(read_tx);

        let result = poll_fn(|cx| HasTakeover::<ReadStream>::poll_takeover(&mut request, cx)).await;
        assert!(matches!(result, Err(TakeoverError::Aborted)));
    }

    #[tokio::test]
    async fn takeover_returns_already_taken_when_taken_twice() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (_read_tx, read) = RemainStream::<ReadStream>::pending();
        request.extensions_mut().insert(TakeoverSlot::new(read));

        let first = poll_fn(|cx| HasTakeover::<ReadStream>::poll_takeover(&mut request, cx)).await;
        assert!(first.is_ok());

        let second = poll_fn(|cx| HasTakeover::<ReadStream>::poll_takeover(&mut request, cx)).await;
        assert!(matches!(second, Err(TakeoverError::AlreadyTaken)));
    }

    #[tokio::test]
    async fn takeover_returns_aborted_when_sender_dropped() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (read_tx, read) = RemainStream::<ReadStream>::pending();
        request.extensions_mut().insert(TakeoverSlot::new(read));

        drop(read_tx);

        let result = poll_fn(|cx| HasTakeover::<ReadStream>::poll_takeover(&mut request, cx)).await;
        assert!(matches!(result, Err(TakeoverError::Aborted)));
    }

    #[tokio::test]
    async fn takeover_returns_body_not_released_on_body_error() {
        let mut request = http::Request::new(ErrorBody);
        let result = poll_fn(|cx| HasTakeover::<ReadStream>::poll_takeover(&mut request, cx)).await;
        assert!(matches!(result, Err(TakeoverError::BodyNotReleased)));
    }
}
