use std::{
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use http_body::Body;
use snafu::Snafu;
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

    pub fn take(&self) -> Result<PendingTakeover<T>, TakeoverError> {
        let mut guard = self.state.lock().expect("poisoned mutex");
        match &*guard {
            TakeoverState::Available { .. } => (),
            TakeoverState::Taken => return Err(TakeoverError::AlreadyTaken),
        }

        let state = std::mem::replace(&mut *guard, TakeoverState::Taken);
        match state {
            TakeoverState::Available { stream } => Ok(PendingTakeover { stream }),
            TakeoverState::Taken => Err(TakeoverError::AlreadyTaken),
        }
    }
}

pub struct PendingTakeover<T> {
    stream: RemainStream<T>,
}

impl<T> PendingTakeover<T> {
    pub async fn wait(self) -> Result<T, TakeoverError> {
        self.stream.await.ok_or(TakeoverError::Aborted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
pub enum TakeoverError {
    #[snafu(display("stream already taken"))]
    AlreadyTaken,
    #[snafu(display("stream provider was dropped before delivery"))]
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(module, visibility(pub))]
pub enum UpgradeError {
    #[snafu(display("failed to take over stream"))]
    Takeover { source: TakeoverError },
    #[snafu(display("upgrade incomplete, missing {missing} stream"))]
    Incomplete { missing: MissingStream },
    #[snafu(display("message body could not be released"))]
    BodyNotReleased,
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

pub(crate) trait TakeoverSealed {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        Result<(PendingTakeover<ReadStream>, PendingTakeover<WriteStream>), UpgradeError>,
    >;
}

fn poll_release_body<B: Body + Unpin>(
    body: &mut B,
    cx: &mut Context<'_>,
) -> Poll<Result<(), UpgradeError>> {
    loop {
        match ready!(Pin::new(&mut *body).poll_frame(cx)) {
            Some(Ok(_)) => continue,
            Some(Err(_)) => return Poll::Ready(Err(UpgradeError::BodyNotReleased)),
            None => return Poll::Ready(Ok(())),
        }
    }
}

fn take_both_slots(
    extensions: &http::Extensions,
) -> Result<(PendingTakeover<ReadStream>, PendingTakeover<WriteStream>), UpgradeError> {
    let read_slot = extensions.get::<TakeoverSlot<ReadStream>>();
    let write_slot = extensions.get::<TakeoverSlot<WriteStream>>();
    match (read_slot, write_slot) {
        (Some(r), Some(w)) => {
            let rp = r.take()?;
            let wp = w.take()?;
            Ok((rp, wp))
        }
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

pub trait HasTakeover: TakeoverSealed {}

impl<R: TakeoverSealed> HasTakeover for R {}

impl<B: Body + Unpin> TakeoverSealed for http::Request<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        Result<(PendingTakeover<ReadStream>, PendingTakeover<WriteStream>), UpgradeError>,
    > {
        ready!(poll_release_body(self.body_mut(), cx))?;
        Poll::Ready(take_both_slots(self.extensions()))
    }
}

impl<B: Body + Unpin> TakeoverSealed for http::Response<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        Result<(PendingTakeover<ReadStream>, PendingTakeover<WriteStream>), UpgradeError>,
    > {
        ready!(poll_release_body(self.body_mut(), cx))?;
        Poll::Ready(take_both_slots(self.extensions()))
    }
}

impl<B: Body + Unpin> TakeoverSealed for &mut http::Request<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        Result<(PendingTakeover<ReadStream>, PendingTakeover<WriteStream>), UpgradeError>,
    > {
        ready!(poll_release_body(self.body_mut(), cx))?;
        Poll::Ready(take_both_slots(self.extensions()))
    }
}

impl<B: Body + Unpin> TakeoverSealed for &mut http::Response<B> {
    fn poll_takeover(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        Result<(PendingTakeover<ReadStream>, PendingTakeover<WriteStream>), UpgradeError>,
    > {
        ready!(poll_release_body(self.body_mut(), cx))?;
        Poll::Ready(take_both_slots(self.extensions()))
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
    async fn upgrade_returns_incomplete_when_no_slots() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let result = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(matches!(
            result,
            Err(UpgradeError::Incomplete {
                missing: MissingStream::Both
            })
        ));
    }

    #[tokio::test]
    async fn upgrade_returns_incomplete_when_only_read_slot() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (_read_tx, read) = RemainStream::<ReadStream>::pending();
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(read));

        let result = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(matches!(
            result,
            Err(UpgradeError::Incomplete {
                missing: MissingStream::Write
            })
        ));
    }

    #[tokio::test]
    async fn upgrade_returns_pending_when_both_slots_available() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (_read_tx, read) = RemainStream::<ReadStream>::pending();
        let (_write_tx, write) = RemainStream::<WriteStream>::pending();
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(read));
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(write));

        let result = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn upgrade_returns_already_taken_when_taken_twice() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (_read_tx, read) = RemainStream::<ReadStream>::pending();
        let (_write_tx, write) = RemainStream::<WriteStream>::pending();
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(read));
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(write));

        let first = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(first.is_ok());

        let second = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(matches!(
            second,
            Err(UpgradeError::Takeover {
                source: TakeoverError::AlreadyTaken
            })
        ));
    }

    #[tokio::test]
    async fn pending_takeover_wait_returns_aborted_when_sender_dropped() {
        let mut request = http::Request::new(http_body_util::Empty::<Bytes>::new());
        let (read_tx, read) = RemainStream::<ReadStream>::pending();
        let (write_tx, write) = RemainStream::<WriteStream>::pending();
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(read));
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(write));

        let (read_pending, write_pending) = poll_fn(|cx| request.poll_takeover(cx))
            .await
            .expect("takeover should succeed");

        drop(read_tx);
        drop(write_tx);

        let result = read_pending.wait().await;
        assert!(matches!(result, Err(TakeoverError::Aborted)));
        let result = write_pending.wait().await;
        assert!(matches!(result, Err(TakeoverError::Aborted)));
    }

    #[tokio::test]
    async fn upgrade_returns_body_not_released_on_body_error() {
        let mut request = http::Request::new(ErrorBody);
        let result = poll_fn(|cx| request.poll_takeover(cx)).await;
        assert!(matches!(result, Err(UpgradeError::BodyNotReleased)));
    }
}
