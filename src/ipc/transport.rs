//! Unix-domain IPC transport for remoc bytes plus file-descriptor transfer.
//!
//! The public FD API is intentionally receiver-chosen:
//!
//! - the receiving side calls [`FdTransfer::receive`] to reserve an id;
//! - the id travels in the RPC request;
//! - the sending side calls [`FdTransfer::delivery`] and consumes the returned
//!   [`FdDelivery`] with [`FdDelivery::deliver`];
//! - [`FdDelivery::deliver`] returns after the FD frame is queued to the local
//!   mux writer FIFO.
//!
//! `MuxChannel` runs independent reader and writer tasks. FD delivery is not
//! receiver-acknowledged; remoc cancellation is the sender-visible cancellation
//! mechanism for RPC operations that carry receiver-chosen FD ids.

use std::{
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream as StdUnixStream,
    },
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, ready};
use smallvec::SmallVec;
use snafu::ResultExt;
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

use crate::varint::VarInt;

mod driver;
mod fd_plane;
mod frame;

pub use driver::FdSender;
pub use fd_plane::{FdDelivered, FdDelivery, FdReceiver, FdTransfer, ReceivedFds};

/// Alias for a small-vec optimised FD collection.
///
/// Inline capacity 4 covers the common cases (uni = 1 FD, bidi = 2 FDs)
/// without heap allocation.
pub type FdVec = SmallVec<[OwnedFd; 4]>;

/// Maximum number of FDs allowed in a single FD frame.
pub(crate) const MAX_FDS_PER_FRAME: usize = 4;

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum QueueFdsError {
    #[snafu(display("fd sender is closed"))]
    Closed,
    #[snafu(display("fd list is empty"))]
    EmptyFds,
    #[snafu(display("too many fds ({count}), max is {MAX_FDS_PER_FRAME}"))]
    TooManyFds { count: usize },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum WaitFdsError {
    #[snafu(display("fd registry is closed"))]
    Closed,
    #[snafu(display("waiter already exists for fd id {id}"))]
    AlreadyWaiting { id: VarInt },
    #[snafu(display("fd waiter channel is closed unexpectedly"))]
    ChannelClosed,
    #[snafu(display("fd id space is exhausted"))]
    IdExhausted,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum TakeFdsError {
    #[snafu(display("expected {expected} fds, got {actual}"))]
    Count { expected: usize, actual: usize },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum DeliverFdsError {
    #[snafu(display("failed to queue fd delivery"))]
    Queue { source: QueueFdsError },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum MuxSinkError {
    #[snafu(display("write side is closed"))]
    Closed,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum MuxStreamError {
    #[snafu(display("failed to poll readable readiness"))]
    PollReady { source: io::Error },
    #[snafu(display("failed to receive mux frame"))]
    Recv { source: io::Error },
    #[snafu(display("ancillary data was truncated"))]
    AncillaryTruncated,
    #[snafu(display("unknown frame type: 0x{frame_type:02x}"))]
    UnknownFrameType { frame_type: u8 },
    #[snafu(display("invalid frame length"))]
    InvalidFrameLength,
    #[snafu(display("invalid fds payload"))]
    InvalidFdsPayload,
    #[snafu(display("fds frame received without ancillary fds"))]
    MissingAncillaryFds,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum SplitError {
    #[snafu(display("failed to clone fd"))]
    CloneFd { source: io::Error },
    #[snafu(display("failed to create async fd"))]
    AsyncFd { source: io::Error },
}

#[derive(Debug)]
pub struct MuxChannel {
    fd: OwnedFd,
}

impl MuxChannel {
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let std_stream = StdUnixStream::from(fd);
        std_stream.set_nonblocking(true)?;
        Ok(Self {
            fd: std_stream.into(),
        })
    }

    pub fn split(self) -> Result<(MuxSink, MuxStream), SplitError> {
        let read_fd = self.fd;
        let write_fd = read_fd
            .as_fd()
            .try_clone_to_owned()
            .context(split_error::CloneFdSnafu)?;

        let plane = Arc::new(fd_plane::FdPlaneCore::new());
        let (writer_core, fd_sender, writer_task) =
            driver::start_writer(write_fd).context(split_error::AsyncFdSnafu)?;
        let (bytes_rx, reader_task) =
            driver::start_reader(read_fd, plane.clone()).context(split_error::AsyncFdSnafu)?;

        let sink = MuxSink {
            core: Some(writer_core),
            fd_sender,
            writer_task: Some(writer_task),
        };
        let stream = MuxStream {
            plane,
            bytes_rx,
            reader_task: Some(reader_task),
        };

        Ok((sink, stream))
    }

    #[cfg(test)]
    pub fn pair_for_test() -> io::Result<(Self, Self)> {
        let (a, b) = StdUnixStream::pair()?;
        let a = Self::from_fd(a.into())?;
        let b = Self::from_fd(b.into())?;
        Ok((a, b))
    }

    /// Create a socketpair and return `(local_channel, remote_fd)`.
    ///
    /// The local side is a ready-to-use [`MuxChannel`]; the remote `OwnedFd`
    /// is intended to be transferred to another process via
    /// [`FdDelivery::deliver`] and reconstructed with [`MuxChannel::from_fd`]
    /// on the receiving end.
    pub fn create_pair() -> io::Result<(Self, OwnedFd)> {
        let (a, b) = StdUnixStream::pair()?;
        let local = Self::from_fd(a.into())?;
        Ok((local, b.into()))
    }
}

#[derive(Debug)]
pub struct MuxSink {
    core: Option<Arc<driver::WriterCore>>,
    fd_sender: FdSender,
    writer_task: Option<AbortOnDropHandle<()>>,
}

impl MuxSink {
    pub fn fd_sender(&self) -> FdSender {
        self.fd_sender.clone()
    }

    fn core_ref(&self) -> Result<&Arc<driver::WriterCore>, MuxSinkError> {
        self.core.as_ref().ok_or(MuxSinkError::Closed)
    }

    fn signal_close(&self) {
        if let Some(core) = &self.core {
            core.close();
        }
    }

    fn close_core(&mut self) {
        self.signal_close();
        if let Some(core) = &self.core {
            core.shutdown_write();
        }
        self.core = None;
        self.writer_task = None;
    }

    fn poll_flush_internal(&self, cx: &mut Context<'_>) -> Poll<Result<(), MuxSinkError>> {
        let core = self.core_ref()?;
        core.register_flush_waker(cx.waker());
        if core.is_closed() {
            return Poll::Ready(Err(MuxSinkError::Closed));
        }
        if core.is_flushed() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for MuxSink {
    fn drop(&mut self) {
        self.close_core();
    }
}

impl Sink<Bytes> for MuxSink {
    type Error = MuxSinkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.core_ref() {
            Ok(core) if !core.is_closed() => Poll::Ready(Ok(())),
            _ => Poll::Ready(Err(MuxSinkError::Closed)),
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        match self.core_ref()?.queue(frame::OutboundFrame::Bytes(item)) {
            Ok(()) => Ok(()),
            Err(_) => Err(MuxSinkError::Closed),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_internal(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let result = ready!(self.poll_flush_internal(cx));
        if result.is_ok() {
            self.signal_close();
        }
        Poll::Ready(result)
    }
}

#[derive(Debug)]
pub struct MuxStream {
    plane: Arc<fd_plane::FdPlaneCore>,
    bytes_rx: mpsc::UnboundedReceiver<Result<Bytes, MuxStreamError>>,
    reader_task: Option<AbortOnDropHandle<()>>,
}

impl MuxStream {
    pub fn fd_transfer(&self, sender: FdSender) -> FdTransfer {
        FdTransfer::new(sender, self.plane.clone())
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.reader_task = None;
        self.plane.close();
    }
}

impl Stream for MuxStream {
    type Item = Result<Bytes, MuxStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.bytes_rx.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use smallvec::smallvec;
    use tokio::time::{Duration, timeout};

    use super::*;

    fn make_pair() -> ((MuxSink, MuxStream), (MuxSink, MuxStream)) {
        let (left, right) = MuxChannel::pair_for_test().expect("create pair");
        let left = left.split().expect("split left");
        let right = right.split().expect("split right");
        (left, right)
    }

    #[tokio::test]
    async fn bytes_roundtrip() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();

        sink_a
            .send(Bytes::from_static(b"hello-mux"))
            .await
            .expect("send");

        let received = stream_b
            .next()
            .await
            .expect("stream item")
            .expect("bytes frame");
        assert_eq!(received, Bytes::from_static(b"hello-mux"));
    }

    #[tokio::test]
    async fn fd_delivery_deliver_completes_after_local_queue() {
        let ((sink_a, stream_a), (sink_b, stream_b)) = make_pair();
        let transfer_a = stream_a.fd_transfer(sink_a.fd_sender());
        let transfer_b = stream_b.fd_transfer(sink_b.fd_sender());

        let receiver = transfer_b.receive();
        let id = receiver.id();
        let delivery = transfer_a.delivery(id);
        let (fd, _peer) = StdUnixStream::pair().expect("fd pair");
        let delivered = timeout(
            Duration::from_secs(1),
            delivery.deliver(smallvec![fd.into()]),
        )
        .await
        .expect("deliver queue timeout")
        .expect("deliver should complete once queued");
        assert_eq!(delivered.id(), id);

        let received = timeout(Duration::from_secs(1), receiver)
            .await
            .expect("receiver timeout")
            .expect("receive fds");
        assert_eq!(received.len(), 1);
    }

    #[tokio::test]
    async fn receiver_drop_only_removes_local_waiting_slot() {
        let ((sink_a, stream_a), (sink_b, stream_b)) = make_pair();
        let transfer_a = stream_a.fd_transfer(sink_a.fd_sender());
        let transfer_b = stream_b.fd_transfer(sink_b.fd_sender());

        let receiver = transfer_b.receive();
        let id = receiver.id();
        drop(receiver);

        let (fd, _peer) = StdUnixStream::pair().expect("fd pair");
        let delivered = timeout(
            Duration::from_secs(1),
            transfer_a.delivery(id).deliver(smallvec![fd.into()]),
        )
        .await
        .expect("delivery should not wait for dropped receiver")
        .expect("dropped receiver should not be sender-visible");
        assert_eq!(delivered.id(), id);
    }

    #[tokio::test]
    async fn fd_arrival_without_receiver_is_dropped() {
        let ((mut sink_a, stream_a), (_sink_b, mut stream_b)) = make_pair();
        let transfer_a = stream_a.fd_transfer(sink_a.fd_sender());
        let id = VarInt::from_u32(7);
        let delivery = transfer_a.delivery(id);
        let (fd, _peer) = StdUnixStream::pair().expect("fd pair");
        let delivered = timeout(
            Duration::from_secs(1),
            delivery.deliver(smallvec![fd.into()]),
        )
        .await
        .expect("unknown fd delivery should queue")
        .expect("unknown fd id should not cancel delivery");
        assert_eq!(delivered.id(), id);

        sink_a
            .send(Bytes::from_static(b"after-unknown-fd"))
            .await
            .expect("send after unknown fd");
        let received = timeout(Duration::from_secs(1), stream_b.next())
            .await
            .expect("stream should not be closed by unknown fd")
            .expect("stream item")
            .expect("unknown fd should not be a protocol error");
        assert_eq!(received, Bytes::from_static(b"after-unknown-fd"));
    }
}
