use std::{
    collections::{HashMap, VecDeque},
    io,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream as StdUnixStream,
    },
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures::{Sink, Stream, ready};
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, Shutdown, recvmsg, sendmsg, shutdown,
};
use smallvec::SmallVec;
use snafu::ResultExt;
use tokio::{io::unix::AsyncFd, sync::oneshot};

use crate::varint::{VARINT_MAX, VarInt};

/// Alias for a small-vec optimised FD collection.
///
/// Inline capacity 4 covers the common cases (uni = 1 FD, bidi = 2 FDs)
/// without heap allocation.
pub type FdVec = SmallVec<[OwnedFd; 4]>;

const FRAME_TYPE_BYTES: u8 = 0x00;
const FRAME_TYPE_FDS: u8 = 0x01;

const MAX_FRAME_HEADER_LEN: usize = 1 + VarInt::MAX_SIZE;
const MAX_FDS_FRAME_LEN: usize = 1 + VarInt::MAX_SIZE + VarInt::MAX_SIZE + VarInt::MAX_SIZE;
const READ_CHUNK_LEN: usize = 8 * 1024;

/// Maximum number of FDs allowed in a single FD frame.
///
/// Enforced on both the send side ([`FdSender::queue_fds`]) and the receive
/// side ([`try_decode_frame`]) to bound the cmsg buffer required by
/// [`recv_frame_data`].
const MAX_FDS_PER_FRAME: usize = 4;

/// Minimum wire bytes for an FD frame: type(1) + payload_len(1) + id(1) + fd_count(1).
const MIN_FDS_FRAME_LEN: usize = 4;

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum QueueFdsError {
    #[snafu(display("fd sender is closed"))]
    Closed,
    #[snafu(display("fd list is empty"))]
    EmptyFds,
    #[snafu(display("too many fds ({count}), max is {MAX_FDS_PER_FRAME}"))]
    TooManyFds { count: usize },
    #[snafu(display("fd id space is exhausted"))]
    IdExhausted,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum WaitFdsError {
    #[snafu(display("fd registry is closed"))]
    Closed,
    #[snafu(display("waiter already exists for stream id {id}"))]
    AlreadyWaiting { id: VarInt },
    #[snafu(display("fd waiter channel is closed unexpectedly"))]
    ChannelClosed,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum RegisterFdsError {
    #[snafu(display("fd registry is closed"))]
    Closed,
    #[snafu(display("duplicate stream id {id} received"))]
    DuplicateId { id: VarInt },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum MuxSinkError {
    #[snafu(display("failed to poll writable readiness"))]
    PollReady { source: io::Error },
    #[snafu(display("failed to send mux frame"))]
    Send { source: io::Error },
    #[snafu(display("sink is not ready for start_send"))]
    NotReady,
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
    #[snafu(display("unknown frame type: 0x{frame_type:02x}"))]
    UnknownFrameType { frame_type: u8 },
    #[snafu(display("invalid frame length"))]
    InvalidFrameLength,
    #[snafu(display("invalid fds payload"))]
    InvalidFdsPayload,
    #[snafu(display("fds frame received without ancillary fds"))]
    MissingAncillaryFds,
    #[snafu(display("failed to register incoming fds"))]
    RegisterFds { source: RegisterFdsError },
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

        let writer_core = Arc::new(WriterCore {
            next_id: AtomicU64::new(0),
            fd_queue: Mutex::new(VecDeque::new()),
        });
        let registry_core = Arc::new(RegistryCore::new());
        let registry = FdRegistry::from_core(&registry_core);

        let sink = MuxSink {
            fd: AsyncFd::new(write_fd).context(split_error::AsyncFdSnafu)?,
            core: Some(writer_core.clone()),
            fd_sender: FdSender::from_core(&writer_core),
            pending_bytes: None,
            current: None,
        };
        let stream = MuxStream {
            fd: AsyncFd::new(read_fd).context(split_error::AsyncFdSnafu)?,
            registry_core,
            registry: registry.clone(),
            read_buf: BytesMut::new(),
            cmsg_buf: {
                let per_msg = nix::sys::socket::cmsg_space::<[RawFd; MAX_FDS_PER_FRAME]>();
                let max_msgs = READ_CHUNK_LEN / MIN_FDS_FRAME_LEN;
                vec![0u8; max_msgs * per_msg]
            },
            pending_fds: VecDeque::new(),
            pending_fd_frame: None,
            closed: false,
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
    /// is intended to be sent to another process via [`FdSender::queue_fds`]
    /// and reconstructed with [`MuxChannel::from_fd`] on the receiving end.
    pub fn create_pair() -> io::Result<(Self, OwnedFd)> {
        let (a, b) = StdUnixStream::pair()?;
        let local = Self::from_fd(a.into())?;
        Ok((local, b.into()))
    }
}

#[derive(Debug)]
struct QueuedFds {
    id: VarInt,
    fds: FdVec,
}

#[derive(Debug)]
struct WriterCore {
    next_id: AtomicU64,
    fd_queue: Mutex<VecDeque<QueuedFds>>,
}

#[derive(Clone, Debug)]
pub struct FdSender {
    core: Weak<WriterCore>,
}

impl FdSender {
    fn from_core(core: &Arc<WriterCore>) -> Self {
        Self {
            core: Arc::downgrade(core),
        }
    }

    pub fn queue_fds(&self, fds: FdVec) -> Result<VarInt, QueueFdsError> {
        if fds.is_empty() {
            return Err(QueueFdsError::EmptyFds);
        }
        if fds.len() > MAX_FDS_PER_FRAME {
            return Err(QueueFdsError::TooManyFds { count: fds.len() });
        }

        let core = self.core.upgrade().ok_or(QueueFdsError::Closed)?;

        let id_raw = core
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let next = current.checked_add(1)?;
                if next >= VARINT_MAX { None } else { Some(next) }
            })
            .map_err(|_| QueueFdsError::IdExhausted)?;

        let id = VarInt::from_u64(id_raw).map_err(|_| QueueFdsError::IdExhausted)?;

        let mut queue = core.fd_queue.lock().expect("fd queue poisoned");
        queue.push_back(QueuedFds { id, fds });

        Ok(id)
    }
}

#[derive(Debug)]
pub struct MuxSink {
    fd: AsyncFd<OwnedFd>,
    core: Option<Arc<WriterCore>>,
    fd_sender: FdSender,
    pending_bytes: Option<Bytes>,
    current: Option<PendingWriteFrame>,
}

impl MuxSink {
    pub fn fd_sender(&self) -> FdSender {
        self.fd_sender.clone()
    }

    fn close_core(&mut self) {
        self.core = None;
        self.pending_bytes = None;
        self.current = None;
    }

    fn core_ref(&self) -> Result<&Arc<WriterCore>, MuxSinkError> {
        self.core.as_ref().ok_or(MuxSinkError::Closed)
    }

    fn pop_next_frame(&mut self) -> Option<PendingWriteFrame> {
        let core = self.core.as_ref()?;

        if let Some(queued_fds) = core.fd_queue.lock().expect("fd queue poisoned").pop_front() {
            return Some(PendingWriteFrame::new_fds(queued_fds.id, queued_fds.fds));
        }

        self.pending_bytes.take().map(PendingWriteFrame::new_bytes)
    }

    fn poll_flush_internal(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), MuxSinkError>> {
        if self.core.is_none() {
            return Poll::Ready(Err(MuxSinkError::Closed));
        }

        loop {
            if self.current.is_none() {
                self.current = self.pop_next_frame();
                if self.current.is_none() {
                    return Poll::Ready(Ok(()));
                }
            }

            let mut guard = match ready!(self.fd.poll_write_ready(cx)) {
                Ok(guard) => guard,
                Err(source) => return Poll::Ready(Err(MuxSinkError::PollReady { source })),
            };
            let frame = self.current.as_mut().expect("current frame must exist");

            let io_result = guard.try_io(|inner| send_frame(inner.get_ref().as_raw_fd(), frame));
            let sent = match io_result {
                Ok(Ok(sent)) => sent,
                Ok(Err(source)) => {
                    self.close_core();
                    return Poll::Ready(Err(MuxSinkError::Send { source }));
                }
                Err(_would_block) => return Poll::Pending,
            };

            if sent == 0 {
                self.close_core();
                return Poll::Ready(Err(MuxSinkError::Send {
                    source: io::Error::new(io::ErrorKind::WriteZero, "sendmsg returned 0 bytes"),
                }));
            }

            frame.advance(sent);
            if frame.is_complete() {
                self.current = None;
            }
        }
    }
}

impl Drop for MuxSink {
    fn drop(&mut self) {
        self.close_core();
        let _ = shutdown(self.fd.get_ref().as_raw_fd(), Shutdown::Write);
    }
}

impl Sink<Bytes> for MuxSink {
    type Error = MuxSinkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_internal(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.core_ref()?;
        if self.pending_bytes.is_some() || self.current.is_some() {
            return Err(MuxSinkError::NotReady);
        }
        self.pending_bytes = Some(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_internal(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let result = ready!(self.poll_flush_internal(cx));
        if result.is_ok() {
            self.close_core();
            let _ = shutdown(self.fd.get_ref().as_raw_fd(), Shutdown::Write);
        }
        Poll::Ready(result)
    }
}

#[derive(Debug)]
enum PendingWriteFrame {
    Bytes {
        header: [u8; MAX_FRAME_HEADER_LEN],
        header_len: usize,
        header_written: usize,
        payload: Bytes,
        payload_written: usize,
    },
    Fds {
        header: [u8; MAX_FDS_FRAME_LEN],
        header_len: usize,
        header_written: usize,
        payload: FdVec,
        include_ancillary: bool,
    },
}

impl PendingWriteFrame {
    fn new_bytes(payload: Bytes) -> Self {
        let payload_len =
            VarInt::try_from(payload.len()).expect("payload length must fit into varint");

        let mut header = [0u8; MAX_FRAME_HEADER_LEN];
        header[0] = FRAME_TYPE_BYTES;
        let varint_len = encode_varint_to_slice(&mut header[1..], payload_len);

        Self::Bytes {
            header,
            header_len: 1 + varint_len,
            header_written: 0,
            payload,
            payload_written: 0,
        }
    }

    fn new_fds(id: VarInt, fds: FdVec) -> Self {
        let fd_count = VarInt::try_from(fds.len()).expect("fd count must fit into varint");

        let mut id_buf = [0u8; VarInt::MAX_SIZE];
        let id_len = encode_varint_to_slice(&mut id_buf, id);

        let mut fc_buf = [0u8; VarInt::MAX_SIZE];
        let fc_len = encode_varint_to_slice(&mut fc_buf, fd_count);

        let mut header = [0u8; MAX_FDS_FRAME_LEN];
        header[0] = FRAME_TYPE_FDS;
        let body_len = VarInt::try_from(id_len + fc_len)
            .expect("fd frame payload length must fit into varint");
        let len_len = encode_varint_to_slice(&mut header[1..], body_len);
        let hdr_prefix = 1 + len_len;
        header[hdr_prefix..hdr_prefix + id_len].copy_from_slice(&id_buf[..id_len]);
        header[hdr_prefix + id_len..hdr_prefix + id_len + fc_len]
            .copy_from_slice(&fc_buf[..fc_len]);

        Self::Fds {
            header,
            header_len: hdr_prefix + id_len + fc_len,
            header_written: 0,
            payload: fds,
            include_ancillary: true,
        }
    }

    fn advance(&mut self, mut n: usize) {
        match self {
            Self::Bytes {
                header_len,
                header_written,
                payload,
                payload_written,
                ..
            } => {
                let header_remaining = *header_len - *header_written;
                let header_advance = n.min(header_remaining);
                *header_written += header_advance;
                n -= header_advance;

                if n > 0 {
                    let payload_remaining = payload.len().saturating_sub(*payload_written);
                    let payload_advance = n.min(payload_remaining);
                    *payload_written += payload_advance;
                }
            }
            Self::Fds {
                header_written,
                include_ancillary,
                ..
            } => {
                *header_written += n;
                if n > 0 {
                    *include_ancillary = false;
                }
            }
        }
    }

    fn is_complete(&self) -> bool {
        match self {
            Self::Bytes {
                header_len,
                header_written,
                payload,
                payload_written,
                ..
            } => *header_written >= *header_len && *payload_written >= payload.len(),
            Self::Fds {
                header_len,
                header_written,
                ..
            } => *header_written >= *header_len,
        }
    }
}

fn send_frame(fd: RawFd, frame: &mut PendingWriteFrame) -> io::Result<usize> {
    match frame {
        PendingWriteFrame::Bytes {
            header,
            header_len,
            header_written,
            payload,
            payload_written,
        } => {
            let mut iovecs = [io::IoSlice::new(&[]), io::IoSlice::new(&[])];
            let mut iov_count = 0usize;

            if *header_written < *header_len {
                iovecs[iov_count] = io::IoSlice::new(&header[*header_written..*header_len]);
                iov_count += 1;
            }
            if *payload_written < payload.len() {
                iovecs[iov_count] = io::IoSlice::new(&payload[*payload_written..]);
                iov_count += 1;
            }

            if iov_count == 0 {
                return Ok(0);
            }

            let sent = sendmsg::<()>(fd, &iovecs[..iov_count], &[], MsgFlags::empty(), None)
                .map_err(io::Error::from)?;
            Ok(sent)
        }
        PendingWriteFrame::Fds {
            header,
            header_len,
            header_written,
            payload,
            include_ancillary,
        } => {
            if *header_written >= *header_len {
                return Ok(0);
            }

            let iov = [io::IoSlice::new(&header[*header_written..*header_len])];
            let sent = if *include_ancillary {
                let raw_fds: SmallVec<[RawFd; 4]> =
                    payload.iter().map(AsRawFd::as_raw_fd).collect();
                let cmsgs = [ControlMessage::ScmRights(&raw_fds)];
                sendmsg::<()>(fd, &iov, &cmsgs, MsgFlags::empty(), None)
            } else {
                sendmsg::<()>(fd, &iov, &[], MsgFlags::empty(), None)
            }
            .map_err(io::Error::from)?;

            Ok(sent)
        }
    }
}

#[derive(Debug)]
struct RegistryCore {
    state: Mutex<RegistryState>,
}

#[derive(Debug)]
struct RegistryState {
    slots: HashMap<VarInt, RegistrySlot>,
    closed: bool,
}

#[derive(Debug)]
enum RegistrySlot {
    Ready(FdVec),
    Waiting(oneshot::Sender<Result<FdVec, WaitFdsError>>),
}

impl RegistryCore {
    fn new() -> Self {
        Self {
            state: Mutex::new(RegistryState {
                slots: HashMap::new(),
                closed: false,
            }),
        }
    }

    async fn wait_fds(&self, id: VarInt) -> Result<FdVec, WaitFdsError> {
        let rx = {
            let mut state = self.state.lock().expect("registry mutex poisoned");
            if state.closed {
                return Err(WaitFdsError::Closed);
            }

            if let Some(existing) = state.slots.remove(&id) {
                match existing {
                    RegistrySlot::Ready(fds) => return Ok(fds),
                    RegistrySlot::Waiting(waiter) => {
                        state.slots.insert(id, RegistrySlot::Waiting(waiter));
                        return Err(WaitFdsError::AlreadyWaiting { id });
                    }
                }
            }

            let (tx, rx) = oneshot::channel();
            state.slots.insert(id, RegistrySlot::Waiting(tx));
            rx
        };

        match rx.await {
            Ok(result) => result,
            Err(_) => Err(WaitFdsError::ChannelClosed),
        }
    }

    fn register_arrival(&self, id: VarInt, fds: FdVec) -> Result<(), RegisterFdsError> {
        let mut state = self.state.lock().expect("registry mutex poisoned");
        if state.closed {
            return Err(RegisterFdsError::Closed);
        }

        let existing = state.slots.remove(&id);
        match existing {
            None => {
                state.slots.insert(id, RegistrySlot::Ready(fds));
                Ok(())
            }
            Some(RegistrySlot::Waiting(waiter)) => {
                if let Err(payload) = waiter.send(Ok(fds)) {
                    let recovered_fds = payload.unwrap_or_else(|_| FdVec::new());
                    state.slots.insert(id, RegistrySlot::Ready(recovered_fds));
                }
                Ok(())
            }
            Some(RegistrySlot::Ready(existing_fds)) => {
                state.slots.insert(id, RegistrySlot::Ready(existing_fds));
                Err(RegisterFdsError::DuplicateId { id })
            }
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("registry mutex poisoned");
        if state.closed {
            return;
        }
        state.closed = true;

        for (_, slot) in state.slots.drain() {
            if let RegistrySlot::Waiting(waiter) = slot {
                let _ = waiter.send(Err(WaitFdsError::Closed));
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct FdRegistry {
    core: Weak<RegistryCore>,
}

impl FdRegistry {
    fn from_core(core: &Arc<RegistryCore>) -> Self {
        Self {
            core: Arc::downgrade(core),
        }
    }

    #[cfg(test)]
    fn new_for_test() -> (Arc<RegistryCore>, Self) {
        let core = Arc::new(RegistryCore::new());
        let registry = Self::from_core(&core);
        (core, registry)
    }

    pub async fn wait_fds(&self, id: VarInt) -> Result<FdVec, WaitFdsError> {
        let core = self.core.upgrade().ok_or(WaitFdsError::Closed)?;
        core.wait_fds(id).await
    }
}

#[derive(Debug)]
pub struct MuxStream {
    fd: AsyncFd<OwnedFd>,
    registry_core: Arc<RegistryCore>,
    registry: FdRegistry,
    read_buf: BytesMut,
    /// Heap-allocated cmsg buffer for `recvmsg()`, reused across calls.
    ///
    /// Sized for the worst case where every `MIN_FDS_FRAME_LEN` bytes in a
    /// read chunk originates from a separate `sendmsg()` carrying
    /// `MAX_FDS_PER_FRAME` FDs — on `SOCK_STREAM` the kernel may coalesce
    /// all of them into a single `recvmsg()`.
    cmsg_buf: Vec<u8>,
    /// Flat queue of pending FDs received via SCM_RIGHTS.
    ///
    /// On SOCK_STREAM, the kernel may coalesce SCM_RIGHTS from multiple
    /// sendmsg calls into a single control message.  Each FD frame includes
    /// an `fd_count` field so the receiver can take the correct number of
    /// FDs from this flat queue.
    pending_fds: VecDeque<OwnedFd>,
    /// An FD frame that has been decoded from the byte stream but whose
    /// ancillary FDs have not yet arrived.
    pending_fd_frame: Option<(VarInt, usize)>,
    closed: bool,
}

impl MuxStream {
    pub fn fd_registry(&self) -> FdRegistry {
        self.registry.clone()
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.registry_core.close();
    }
}

impl Stream for MuxStream {
    type Item = Result<Bytes, MuxStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }

        loop {
            // 1. Complete any pending FD frame whose ancillary FDs have now arrived.
            if let Some((id, fd_count)) = self.pending_fd_frame {
                if self.pending_fds.len() >= fd_count {
                    self.pending_fd_frame = None;
                    let fds: FdVec = self.pending_fds.drain(..fd_count).collect();
                    if let Err(source) = self.registry_core.register_arrival(id, fds) {
                        self.closed = true;
                        self.registry_core.close();
                        return Poll::Ready(Some(Err(MuxStreamError::RegisterFds { source })));
                    }
                    continue;
                }
                // Still waiting for FDs — fall through to read more data.
            } else {
                // 2. Decode next frame from the byte buffer.
                match try_decode_frame(&mut self.read_buf) {
                    Ok(Some(DecodedFrame::Bytes(payload))) => {
                        return Poll::Ready(Some(Ok(payload)));
                    }
                    Ok(Some(DecodedFrame::Fds { id, fd_count })) => {
                        if self.pending_fds.len() >= fd_count {
                            let fds: FdVec = self.pending_fds.drain(..fd_count).collect();
                            if let Err(source) = self.registry_core.register_arrival(id, fds) {
                                self.closed = true;
                                self.registry_core.close();
                                return Poll::Ready(Some(Err(MuxStreamError::RegisterFds {
                                    source,
                                })));
                            }
                            continue;
                        }
                        // FD frame decoded but ancillary not yet received.
                        // Stash it and fall through to read more data.
                        self.pending_fd_frame = Some((id, fd_count));
                    }
                    Ok(None) => {
                        // Incomplete frame — fall through to read more data.
                    }
                    Err(err) => {
                        self.closed = true;
                        self.registry_core.close();
                        return Poll::Ready(Some(Err(err)));
                    }
                }
            }

            // 3. Read more data (and ancillary FDs) from the socket.
            // Reborrow to enable split field borrows (guard borrows fd, recv
            // borrows cmsg_buf).
            let this = &mut *self;
            let mut guard = match ready!(this.fd.poll_read_ready(cx)) {
                Ok(guard) => guard,
                Err(source) => return Poll::Ready(Some(Err(MuxStreamError::PollReady { source }))),
            };

            let mut read_buf = [0u8; READ_CHUNK_LEN];
            let io_result = guard.try_io(|inner| {
                recv_frame_data(
                    inner.get_ref().as_raw_fd(),
                    &mut read_buf,
                    &mut this.cmsg_buf,
                )
            });

            let (read, ancillary) = match io_result {
                Ok(Ok(result)) => result,
                Ok(Err(source)) => {
                    this.closed = true;
                    this.registry_core.close();
                    return Poll::Ready(Some(Err(MuxStreamError::Recv { source })));
                }
                Err(_would_block) => return Poll::Pending,
            };

            if read == 0 {
                this.closed = true;
                this.registry_core.close();
                if this.pending_fd_frame.is_some() {
                    return Poll::Ready(Some(Err(MuxStreamError::MissingAncillaryFds)));
                }
                return Poll::Ready(None);
            }

            if !ancillary.is_empty() {
                this.pending_fds.extend(ancillary);
            }
            this.read_buf.extend_from_slice(&read_buf[..read]);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{F_GETFD, F_SETFD, FdFlag, fcntl};
    let raw = fd.as_raw_fd();
    let bits = fcntl(raw, F_GETFD).map_err(io::Error::from)?;
    let new_flags = FdFlag::from_bits_truncate(bits) | FdFlag::FD_CLOEXEC;
    fcntl(raw, F_SETFD(new_flags)).map_err(io::Error::from)?;
    Ok(())
}

fn recv_frame_data(
    fd: RawFd,
    data_buf: &mut [u8],
    cmsg_buf: &mut Vec<u8>,
) -> io::Result<(usize, FdVec)> {
    let mut iov = [io::IoSliceMut::new(data_buf)];

    // `MSG_CMSG_CLOEXEC` is Linux-only; on other Unix platforms we fall back to
    // setting `FD_CLOEXEC` manually on each received fd below.
    #[cfg(target_os = "linux")]
    let recv_flags = MsgFlags::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let recv_flags = MsgFlags::empty();

    let msg = recvmsg::<()>(fd, &mut iov, Some(cmsg_buf), recv_flags).map_err(io::Error::from)?;

    if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cmsg buffer overflow: ancillary data truncated (MSG_CTRUNC)",
        ));
    }

    let mut fds = FdVec::new();
    let cmsgs = msg.cmsgs().map_err(io::Error::from)?;
    for cmsg in cmsgs {
        if let ControlMessageOwned::ScmRights(raw_fds) = cmsg {
            for raw_fd in raw_fds {
                // SAFETY: SCM_RIGHTS transfers ownership of a new fd to receiver.
                let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
                #[cfg(not(target_os = "linux"))]
                set_cloexec(&fd)?;
                fds.push(fd);
            }
        }
    }

    Ok((msg.bytes, fds))
}

#[derive(Debug)]
enum DecodedFrame {
    Bytes(Bytes),
    Fds { id: VarInt, fd_count: usize },
}

fn try_decode_frame(src: &mut BytesMut) -> Result<Option<DecodedFrame>, MuxStreamError> {
    if src.is_empty() {
        return Ok(None);
    }

    let frame_type = src[0];
    if frame_type != FRAME_TYPE_BYTES && frame_type != FRAME_TYPE_FDS {
        return Err(MuxStreamError::UnknownFrameType { frame_type });
    }

    let Some((payload_len, varint_len)) = try_decode_varint_len(&src[1..])? else {
        return Ok(None);
    };

    let frame_header_len = 1 + varint_len;
    if src.len() < frame_header_len + payload_len {
        return Ok(None);
    }

    src.advance(frame_header_len);
    let payload = src.split_to(payload_len).freeze();

    match frame_type {
        FRAME_TYPE_BYTES => Ok(Some(DecodedFrame::Bytes(payload))),
        FRAME_TYPE_FDS => {
            let (id, id_consumed) = decode_varint_from_slice(&payload)?;
            let remaining = &payload[id_consumed..];
            let (fd_count_vi, fc_consumed) = decode_varint_from_slice(remaining)?;
            if id_consumed + fc_consumed != payload.len() {
                return Err(MuxStreamError::InvalidFdsPayload);
            }
            let fd_count = usize::try_from(u64::from(fd_count_vi))
                .map_err(|_| MuxStreamError::InvalidFdsPayload)?;
            if fd_count == 0 || fd_count > MAX_FDS_PER_FRAME {
                return Err(MuxStreamError::InvalidFdsPayload);
            }
            Ok(Some(DecodedFrame::Fds { id, fd_count }))
        }
        _ => Err(MuxStreamError::UnknownFrameType { frame_type }),
    }
}

fn try_decode_varint_len(src: &[u8]) -> Result<Option<(usize, usize)>, MuxStreamError> {
    let Some((value, consumed)) = try_decode_varint(src)? else {
        return Ok(None);
    };
    let payload_len = usize::try_from(value).map_err(|_| MuxStreamError::InvalidFrameLength)?;
    Ok(Some((payload_len, consumed)))
}

fn decode_varint_from_slice(src: &[u8]) -> Result<(VarInt, usize), MuxStreamError> {
    let Some((value, consumed)) = try_decode_varint(src)? else {
        return Err(MuxStreamError::InvalidFdsPayload);
    };
    let id = VarInt::from_u64(value).map_err(|_| MuxStreamError::InvalidFdsPayload)?;
    Ok((id, consumed))
}

fn try_decode_varint(src: &[u8]) -> Result<Option<(u64, usize)>, MuxStreamError> {
    if src.is_empty() {
        return Ok(None);
    }

    let first = src[0];
    let len = 1usize << (first >> 6);
    if src.len() < len {
        return Ok(None);
    }

    let mut raw = [0u8; 8];
    raw[..len].copy_from_slice(&src[..len]);
    raw[0] &= 0x3f;
    let value = u64::from_be_bytes(raw) >> (8 * (8 - len));
    if value >= VARINT_MAX {
        return Err(MuxStreamError::InvalidFrameLength);
    }

    Ok(Some((value, len)))
}

fn encode_varint_to_slice(dst: &mut [u8], v: VarInt) -> usize {
    let x = v.into_inner();
    if x < (1 << 6) {
        dst[0] = x as u8;
        1
    } else if x < (1 << 14) {
        let bytes = ((0b01 << 14) | x as u16).to_be_bytes();
        dst[..2].copy_from_slice(&bytes);
        2
    } else if x < (1 << 30) {
        let bytes = ((0b10 << 30) | x as u32).to_be_bytes();
        dst[..4].copy_from_slice(&bytes);
        4
    } else {
        let bytes = ((0b11 << 62) | x).to_be_bytes();
        dst[..8].copy_from_slice(&bytes);
        8
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
    async fn queue_fds_auto_id_and_wait() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();

        let registry = stream_b.fd_registry();
        let (fd_a, _fd_b) = StdUnixStream::pair().expect("fd pair");
        let id = sink_a
            .fd_sender()
            .queue_fds(smallvec![fd_a.into()])
            .expect("queue fds");

        sink_a.send(Bytes::new()).await.expect("drive flush");

        let _ = stream_b
            .next()
            .await
            .expect("stream item")
            .expect("empty bytes frame");
        let fds = registry.wait_fds(id).await.expect("wait fds");
        assert_eq!(fds.len(), 1);
    }

    #[tokio::test]
    async fn wait_before_arrival() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();

        let registry = stream_b.fd_registry();
        let waiter = tokio::spawn(async move { registry.wait_fds(VarInt::from_u32(0)).await });

        let (fd_a, _fd_b) = StdUnixStream::pair().expect("fd pair");
        let id = sink_a
            .fd_sender()
            .queue_fds(smallvec![fd_a.into()])
            .expect("queue fds");
        assert_eq!(id, VarInt::from_u32(0));

        sink_a.send(Bytes::new()).await.expect("drive flush");
        let _ = stream_b
            .next()
            .await
            .expect("stream item")
            .expect("empty bytes frame");

        let received = waiter.await.expect("join").expect("wait result");
        assert_eq!(received.len(), 1);
    }

    #[tokio::test]
    async fn duplicate_id_rejected_in_registry() {
        let (registry_core, registry) = FdRegistry::new_for_test();

        let (fd1, _peer1) = StdUnixStream::pair().expect("pair1");
        let (fd2, _peer2) = StdUnixStream::pair().expect("pair2");
        let id = VarInt::from_u32(7);

        registry_core
            .register_arrival(id, smallvec![fd1.into()])
            .expect("first arrival");
        let duplicate = registry_core.register_arrival(id, smallvec![fd2.into()]);
        assert!(matches!(
            duplicate,
            Err(RegisterFdsError::DuplicateId { .. })
        ));

        let first = registry.wait_fds(id).await.expect("first still valid");
        assert_eq!(first.len(), 1);
    }

    #[tokio::test]
    async fn wait_after_consumed_waits_for_next_arrival() {
        let (registry_core, registry) = FdRegistry::new_for_test();
        let id = VarInt::from_u32(9);

        let (fd1, _peer1) = StdUnixStream::pair().expect("pair1");
        registry_core
            .register_arrival(id, smallvec![fd1.into()])
            .expect("first arrival");
        let first = registry.wait_fds(id).await.expect("first consume");
        assert_eq!(first.len(), 1);

        let reg2 = registry.clone();
        let waiter = tokio::spawn(async move { reg2.wait_fds(id).await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        let (fd2, _peer2) = StdUnixStream::pair().expect("pair2");
        registry_core
            .register_arrival(id, smallvec![fd2.into()])
            .expect("second arrival");

        let second = waiter.await.expect("join").expect("second consume");
        assert_eq!(second.len(), 1);
    }

    #[tokio::test]
    async fn interleaved_fd_and_bytes_do_not_leak_fd_frames() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();

        let registry = stream_b.fd_registry();
        let (fd_a, _fd_b) = StdUnixStream::pair().expect("fd pair");
        let id = sink_a
            .fd_sender()
            .queue_fds(smallvec![fd_a.into()])
            .expect("queue fds");

        sink_a
            .send(Bytes::from_static(b"payload"))
            .await
            .expect("send payload");

        let payload = stream_b
            .next()
            .await
            .expect("stream item")
            .expect("bytes frame");
        assert_eq!(payload, Bytes::from_static(b"payload"));

        let fds = registry.wait_fds(id).await.expect("wait fds");
        assert_eq!(fds.len(), 1);
    }

    #[tokio::test]
    async fn sink_drop_propagates_eof() {
        let ((sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();

        drop(sink_a);
        let eof = timeout(Duration::from_millis(200), stream_b.next())
            .await
            .expect("expected eof signal");
        assert!(eof.is_none());
    }

    #[tokio::test]
    async fn fd_sender_closed_after_sink_drop() {
        let ((sink_a, _stream_a), (_sink_b, _stream_b)) = make_pair();
        let sender = sink_a.fd_sender();
        drop(sink_a);

        let (fd, _peer) = StdUnixStream::pair().expect("fd pair");
        let result = sender.queue_fds(smallvec![fd.into()]);
        assert!(matches!(result, Err(QueueFdsError::Closed)));
    }

    // -----------------------------------------------------------------------
    // FdSender boundary tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn queue_fds_empty_vec_rejected() {
        let ((sink_a, _stream_a), (_sink_b, _stream_b)) = make_pair();
        let sender = sink_a.fd_sender();
        let result = sender.queue_fds(smallvec![]);
        assert!(matches!(result, Err(QueueFdsError::EmptyFds)));
    }

    #[tokio::test]
    async fn queue_fds_multiple_fds_per_message() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();
        let registry = stream_b.fd_registry();

        let (fd1, _p1) = StdUnixStream::pair().expect("pair1");
        let (fd2, _p2) = StdUnixStream::pair().expect("pair2");
        let (fd3, _p3) = StdUnixStream::pair().expect("pair3");
        let id = sink_a
            .fd_sender()
            .queue_fds(smallvec![fd1.into(), fd2.into(), fd3.into()])
            .expect("queue 3 fds");

        sink_a.send(Bytes::new()).await.expect("drive flush");
        let _ = stream_b
            .next()
            .await
            .expect("stream item")
            .expect("empty bytes");

        let fds = registry.wait_fds(id).await.expect("wait fds");
        assert_eq!(fds.len(), 3);
    }

    // -----------------------------------------------------------------------
    // FdRegistry boundary tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn wait_fds_already_waiting() {
        let (registry_core, registry) = FdRegistry::new_for_test();
        let id = VarInt::from_u32(1);

        let reg2 = registry.clone();
        let waiter = tokio::spawn(async move { reg2.wait_fds(id).await });
        tokio::task::yield_now().await;

        // Second wait on same ID should fail
        let result = registry_core.wait_fds(id).await;
        assert!(matches!(result, Err(WaitFdsError::AlreadyWaiting { .. })));

        // Satisfy the first waiter to clean up
        let (fd, _peer) = StdUnixStream::pair().expect("pair");
        registry_core
            .register_arrival(id, smallvec![fd.into()])
            .expect("arrival");
        waiter.await.expect("join").expect("wait result");
    }

    #[tokio::test]
    async fn wait_fds_closed_registry() {
        let (registry_core, registry) = FdRegistry::new_for_test();
        registry_core.close();

        let result = registry.wait_fds(VarInt::from_u32(0)).await;
        assert!(matches!(result, Err(WaitFdsError::Closed)));
    }

    #[tokio::test]
    async fn wait_fds_close_while_waiting() {
        let (registry_core, registry) = FdRegistry::new_for_test();
        let id = VarInt::from_u32(42);

        let reg = registry.clone();
        let waiter = tokio::spawn(async move { reg.wait_fds(id).await });
        tokio::task::yield_now().await;

        registry_core.close();

        let result = waiter.await.expect("join");
        assert!(matches!(result, Err(WaitFdsError::Closed)));
    }

    #[tokio::test]
    async fn register_arrival_after_close() {
        let (registry_core, _registry) = FdRegistry::new_for_test();
        registry_core.close();

        let (fd, _peer) = StdUnixStream::pair().expect("pair");
        let result = registry_core.register_arrival(VarInt::from_u32(0), smallvec![fd.into()]);
        assert!(matches!(result, Err(RegisterFdsError::Closed)));
    }

    // -----------------------------------------------------------------------
    // MuxStream demux boundary tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn multiple_fd_ids_interleaved() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();
        let registry = stream_b.fd_registry();
        let sender = sink_a.fd_sender();

        let (fd1, _p1) = StdUnixStream::pair().expect("pair1");
        let id1 = sender.queue_fds(smallvec![fd1.into()]).expect("queue 1");

        sink_a
            .send(Bytes::from_static(b"msg1"))
            .await
            .expect("send msg1");

        let (fd2, _p2) = StdUnixStream::pair().expect("pair2");
        let id2 = sender.queue_fds(smallvec![fd2.into()]).expect("queue 2");

        sink_a
            .send(Bytes::from_static(b"msg2"))
            .await
            .expect("send msg2");

        let (fd3, _p3) = StdUnixStream::pair().expect("pair3");
        let id3 = sender.queue_fds(smallvec![fd3.into()]).expect("queue 3");

        sink_a
            .send(Bytes::from_static(b"msg3"))
            .await
            .expect("send msg3");

        // FD frames are demuxed internally; only bytes frames are yielded
        let p1 = stream_b.next().await.expect("item1").expect("bytes1");
        let p2 = stream_b.next().await.expect("item2").expect("bytes2");
        let p3 = stream_b.next().await.expect("item3").expect("bytes3");
        assert_eq!(p1, Bytes::from_static(b"msg1"));
        assert_eq!(p2, Bytes::from_static(b"msg2"));
        assert_eq!(p3, Bytes::from_static(b"msg3"));

        let fds1 = registry.wait_fds(id1).await.expect("wait 1");
        let fds2 = registry.wait_fds(id2).await.expect("wait 2");
        let fds3 = registry.wait_fds(id3).await.expect("wait 3");
        assert_eq!(fds1.len(), 1);
        assert_eq!(fds2.len(), 1);
        assert_eq!(fds3.len(), 1);
    }

    #[tokio::test]
    async fn large_payload_roundtrip() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();

        let large = Bytes::from(vec![0xAB; 128 * 1024]);
        sink_a.send(large.clone()).await.expect("send large");

        let received = stream_b.next().await.expect("item").expect("bytes");
        assert_eq!(received, large);
    }

    #[tokio::test]
    async fn consecutive_fd_frames() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();
        let registry = stream_b.fd_registry();
        let sender = sink_a.fd_sender();

        // Queue two FD frames back to back without bytes between
        let (fd1, _p1) = StdUnixStream::pair().expect("pair1");
        let (fd2, _p2) = StdUnixStream::pair().expect("pair2");
        let id1 = sender.queue_fds(smallvec![fd1.into()]).expect("queue 1");
        let id2 = sender.queue_fds(smallvec![fd2.into()]).expect("queue 2");

        // A bytes frame drives the flush of both FD frames
        sink_a
            .send(Bytes::from_static(b"after"))
            .await
            .expect("send");

        let payload = stream_b.next().await.expect("item").expect("bytes");
        assert_eq!(payload, Bytes::from_static(b"after"));

        let fds1 = registry.wait_fds(id1).await.expect("wait 1");
        let fds2 = registry.wait_fds(id2).await.expect("wait 2");
        assert_eq!(fds1.len(), 1);
        assert_eq!(fds2.len(), 1);
    }

    #[tokio::test]
    async fn fd_frame_without_ancillary_errors() {
        // Craft a raw FD frame without SCM_RIGHTS ancillary data
        let (raw_writer, reader) = StdUnixStream::pair().expect("pair");
        let reader_ch = MuxChannel::from_fd(reader.into()).expect("from_fd");
        let (_sink, mut stream) = reader_ch.split().expect("split");

        // FD frame: type=0x01, length=2, id=0x00, fd_count=0x01
        use std::io::Write;
        (&raw_writer)
            .write_all(&[FRAME_TYPE_FDS, 0x02, 0x00, 0x01])
            .expect("write");
        drop(raw_writer);

        let result = stream.next().await;
        assert!(
            matches!(result, Some(Err(MuxStreamError::MissingAncillaryFds))),
            "expected MissingAncillaryFds, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn unknown_frame_type_rejected() {
        let (raw_writer, reader) = StdUnixStream::pair().expect("pair");
        let reader_ch = MuxChannel::from_fd(reader.into()).expect("from_fd");
        let (_sink, mut stream) = reader_ch.split().expect("split");

        // Unknown frame type 0xFF
        use std::io::Write;
        (&raw_writer).write_all(&[0xFF, 0x01, 0x00]).expect("write");
        drop(raw_writer);

        let result = stream.next().await;
        assert!(
            matches!(
                result,
                Some(Err(MuxStreamError::UnknownFrameType { frame_type: 0xFF }))
            ),
            "expected UnknownFrameType(0xFF), got: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // MuxSink boundary tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_after_close_errors() {
        let ((mut sink_a, _stream_a), (_sink_b, _stream_b)) = make_pair();
        sink_a.close().await.expect("close");

        let result = sink_a.send(Bytes::from_static(b"after-close")).await;
        assert!(matches!(result, Err(MuxSinkError::Closed)));
    }

    #[tokio::test]
    async fn fd_priority_over_bytes() {
        use futures::future::poll_fn;

        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();
        let registry = stream_b.fd_registry();

        // Step 1: poll_ready + start_send to park pending bytes
        poll_fn(|cx| Pin::new(&mut sink_a).poll_ready(cx))
            .await
            .expect("ready");
        Pin::new(&mut sink_a)
            .start_send(Bytes::from_static(b"after-fds"))
            .expect("start_send");

        // Step 2: queue FD — it should be flushed before the pending bytes
        let (fd, _peer) = StdUnixStream::pair().expect("pair");
        let fd_id = sink_a
            .fd_sender()
            .queue_fds(smallvec![fd.into()])
            .expect("queue fds");

        // Step 3: flush sends FD frame first, then bytes frame
        sink_a.flush().await.expect("flush");

        // Stream yields only bytes (FD is demuxed internally)
        let payload = stream_b.next().await.expect("item").expect("bytes");
        assert_eq!(payload, Bytes::from_static(b"after-fds"));

        // FD should be available
        let fds = registry.wait_fds(fd_id).await.expect("wait fds");
        assert_eq!(fds.len(), 1);
    }

    #[tokio::test]
    async fn empty_bytes_frame() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();
        sink_a.send(Bytes::new()).await.expect("send empty");

        let payload = stream_b.next().await.expect("item").expect("bytes");
        assert!(payload.is_empty());
    }

    // -----------------------------------------------------------------------
    // Close propagation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn stream_drop_propagates_registry_close() {
        let ((_sink_a, _stream_a), (_sink_b, stream_b)) = make_pair();
        let registry = stream_b.fd_registry();
        drop(stream_b);

        let result = registry.wait_fds(VarInt::from_u32(0)).await;
        assert!(matches!(result, Err(WaitFdsError::Closed)));
    }

    // -----------------------------------------------------------------------
    // Phase 1: Validation path tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn queue_fds_too_many_rejected() {
        let ((sink_a, _stream_a), (_sink_b, _stream_b)) = make_pair();
        let sender = sink_a.fd_sender();

        let (fd1, _p1) = StdUnixStream::pair().expect("pair1");
        let (fd2, _p2) = StdUnixStream::pair().expect("pair2");
        let (fd3, _p3) = StdUnixStream::pair().expect("pair3");
        let (fd4, _p4) = StdUnixStream::pair().expect("pair4");
        let (fd5, _p5) = StdUnixStream::pair().expect("pair5");

        let result = sender.queue_fds(smallvec![
            fd1.into(),
            fd2.into(),
            fd3.into(),
            fd4.into(),
            fd5.into(),
        ]);
        assert!(
            matches!(result, Err(QueueFdsError::TooManyFds { count: 5 })),
            "expected TooManyFds {{ count: 5 }}, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn max_fds_per_frame_roundtrip() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();
        let registry = stream_b.fd_registry();

        let (fd1, _p1) = StdUnixStream::pair().expect("pair1");
        let (fd2, _p2) = StdUnixStream::pair().expect("pair2");
        let (fd3, _p3) = StdUnixStream::pair().expect("pair3");
        let (fd4, _p4) = StdUnixStream::pair().expect("pair4");

        let id = sink_a
            .fd_sender()
            .queue_fds(smallvec![fd1.into(), fd2.into(), fd3.into(), fd4.into()])
            .expect("queue 4 fds");

        sink_a.send(Bytes::new()).await.expect("drive flush");
        let _ = stream_b
            .next()
            .await
            .expect("stream item")
            .expect("empty bytes");

        let fds = registry.wait_fds(id).await.expect("wait fds");
        assert_eq!(fds.len(), 4);
    }

    #[tokio::test]
    async fn fd_frame_fd_count_zero_rejected() {
        let (raw_writer, reader) = StdUnixStream::pair().expect("pair");
        let reader_ch = MuxChannel::from_fd(reader.into()).expect("from_fd");
        let (_sink, mut stream) = reader_ch.split().expect("split");

        // FD frame: type=0x01, payload_len=2, id=0x00, fd_count=0x00
        use std::io::Write;
        (&raw_writer)
            .write_all(&[FRAME_TYPE_FDS, 0x02, 0x00, 0x00])
            .expect("write");
        drop(raw_writer);

        let result = stream.next().await;
        assert!(
            matches!(result, Some(Err(MuxStreamError::InvalidFdsPayload))),
            "expected InvalidFdsPayload, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn fd_frame_fd_count_exceeds_max_rejected() {
        let (raw_writer, reader) = StdUnixStream::pair().expect("pair");
        let reader_ch = MuxChannel::from_fd(reader.into()).expect("from_fd");
        let (_sink, mut stream) = reader_ch.split().expect("split");

        // FD frame: type=0x01, payload_len=2, id=0x00, fd_count=0x05
        use std::io::Write;
        (&raw_writer)
            .write_all(&[FRAME_TYPE_FDS, 0x02, 0x00, 0x05])
            .expect("write");
        drop(raw_writer);

        let result = stream.next().await;
        assert!(
            matches!(result, Some(Err(MuxStreamError::InvalidFdsPayload))),
            "expected InvalidFdsPayload, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn fd_frame_trailing_bytes_rejected() {
        let (raw_writer, reader) = StdUnixStream::pair().expect("pair");
        let reader_ch = MuxChannel::from_fd(reader.into()).expect("from_fd");
        let (_sink, mut stream) = reader_ch.split().expect("split");

        // FD frame: type=0x01, payload_len=3, id=0x00, fd_count=0x01, extra=0xFF
        // id(1 byte) + fd_count(1 byte) = 2 bytes, but payload_len says 3
        use std::io::Write;
        (&raw_writer)
            .write_all(&[FRAME_TYPE_FDS, 0x03, 0x00, 0x01, 0xFF])
            .expect("write");
        drop(raw_writer);

        let result = stream.next().await;
        assert!(
            matches!(result, Some(Err(MuxStreamError::InvalidFdsPayload))),
            "expected InvalidFdsPayload, got: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 2: Frame decoding boundary tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn incomplete_bytes_header_waits_for_more_data() {
        let (raw_writer, reader) = StdUnixStream::pair().expect("pair");
        let reader_ch = MuxChannel::from_fd(reader.into()).expect("from_fd");
        let (_sink, mut stream) = reader_ch.split().expect("split");

        // Write only the frame type byte; payload_len + payload missing.
        use std::io::Write;
        (&raw_writer)
            .write_all(&[FRAME_TYPE_BYTES])
            .expect("write type");

        // Stream should not yield yet (incomplete header).
        let poll = timeout(Duration::from_millis(50), stream.next()).await;
        assert!(poll.is_err(), "expected timeout (incomplete header)");

        // Now write the rest: payload_len=5, payload="hello"
        (&raw_writer)
            .write_all(&[0x05, b'h', b'e', b'l', b'l', b'o'])
            .expect("write rest");
        drop(raw_writer);

        let payload = stream.next().await.expect("item").expect("bytes");
        assert_eq!(payload, Bytes::from_static(b"hello"));

        // EOF
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn varint_2byte_length_roundtrip() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();

        // 100 bytes → varint length needs 2 bytes (64..16383)
        let data = Bytes::from(vec![0xAB; 100]);
        sink_a.send(data.clone()).await.expect("send");

        let received = stream_b.next().await.expect("item").expect("bytes");
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn fd_over_bytes_ordering_guarantee() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();
        let registry = stream_b.fd_registry();
        let sender = sink_a.fd_sender();

        // Interleave: FD, bytes, FD, bytes, FD, bytes
        let mut fd_ids = Vec::new();
        for i in 0..3 {
            let (fd, _peer) = StdUnixStream::pair().expect("fd pair");
            let id = sender.queue_fds(smallvec![fd.into()]).expect("queue fds");
            fd_ids.push(id);

            let msg = Bytes::from(format!("msg-{i}"));
            sink_a.send(msg).await.expect("send");
        }

        // All 3 bytes frames arrive in order
        for i in 0..3 {
            let payload = stream_b.next().await.expect("item").expect("bytes");
            assert_eq!(payload, Bytes::from(format!("msg-{i}")));
        }

        // All 3 FDs arrive
        for &id in &fd_ids {
            let fds = registry.wait_fds(id).await.expect("wait fds");
            assert_eq!(fds.len(), 1);
        }
    }

    #[tokio::test]
    async fn concurrent_fds_and_bytes_stress() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();
        let registry = stream_b.fd_registry();
        let sender = sink_a.fd_sender();

        let rounds = 20;
        let mut fd_ids = Vec::with_capacity(rounds);

        for i in 0..rounds {
            let (fd, _peer) = StdUnixStream::pair().expect("fd pair");
            let id = sender.queue_fds(smallvec![fd.into()]).expect("queue fds");
            fd_ids.push(id);
            sink_a
                .send(Bytes::from(format!("stress-{i}")))
                .await
                .expect("send");
        }

        // Drain all bytes frames
        for i in 0..rounds {
            let payload = stream_b.next().await.expect("item").expect("bytes");
            assert_eq!(payload, Bytes::from(format!("stress-{i}")));
        }

        // All FDs accessible
        for &id in &fd_ids {
            let fds = registry.wait_fds(id).await.expect("wait fds");
            assert_eq!(fds.len(), 1);
        }
    }

    // -----------------------------------------------------------------------
    // Phase 3: Close / lifecycle tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn graceful_close_flushes_pending_fds() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();
        let registry = stream_b.fd_registry();

        let (fd, _peer) = StdUnixStream::pair().expect("fd pair");
        let id = sink_a
            .fd_sender()
            .queue_fds(smallvec![fd.into()])
            .expect("queue fds");

        // Also send a bytes frame so the stream yields something before EOF
        sink_a
            .send(Bytes::from_static(b"before-close"))
            .await
            .expect("send");

        // close() should flush both pending FD frame and bytes, then shutdown
        sink_a.close().await.expect("close");

        // Drive the stream: the FD frame is consumed internally, bytes yielded
        let payload = stream_b.next().await.expect("item").expect("bytes");
        assert_eq!(payload, Bytes::from_static(b"before-close"));

        // FD was registered during poll_next — wait_fds should succeed
        let fds = registry.wait_fds(id).await.expect("wait fds");
        assert_eq!(fds.len(), 1);

        // Now EOF
        let eof = stream_b.next().await;
        assert!(eof.is_none(), "expected EOF after close");
    }

    #[tokio::test]
    async fn stream_eof_after_sink_close() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();

        // Send some data, then close explicitly
        sink_a
            .send(Bytes::from_static(b"before-close"))
            .await
            .expect("send");
        sink_a.close().await.expect("close");

        let payload = stream_b.next().await.expect("item").expect("bytes");
        assert_eq!(payload, Bytes::from_static(b"before-close"));

        let eof = stream_b.next().await;
        assert!(eof.is_none(), "expected EOF");
    }

    #[tokio::test]
    async fn double_close_is_idempotent() {
        let ((mut sink_a, _stream_a), (_sink_b, _stream_b)) = make_pair();

        sink_a.close().await.expect("first close");
        let result = sink_a.close().await;
        assert!(
            matches!(result, Err(MuxSinkError::Closed)),
            "expected Closed on double close, got: {result:?}"
        );
    }
}
