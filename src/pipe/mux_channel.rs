use std::{
    collections::{HashMap, VecDeque},
    io,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream as StdUnixStream,
    },
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures::{Sink, Stream, ready};
use nix::{
    cmsg_space,
    sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, Shutdown, recvmsg, sendmsg, shutdown,
    },
};
use snafu::ResultExt;
use tokio::{io::unix::AsyncFd, sync::oneshot};

use crate::varint::{VARINT_MAX, VarInt};

const FRAME_TYPE_BYTES: u8 = 0x00;
const FRAME_TYPE_FDS: u8 = 0x01;

const MAX_FRAME_HEADER_LEN: usize = 1 + VarInt::MAX_SIZE;
const READ_CHUNK_LEN: usize = 8 * 1024;
const MAX_FDS_PER_MESSAGE: usize = 8;

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum QueueFdsError {
    #[snafu(display("fd sender is closed"))]
    Closed,
    #[snafu(display("fd list is empty"))]
    EmptyFds,
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
    #[snafu(display("stream id {id} has already been consumed"))]
    AlreadyConsumed { id: VarInt },
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

        let writer_shared = Arc::new(WriterShared {
            next_id: AtomicU64::new(0),
            queue: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
        });
        let registry = FdRegistry::new();

        let sink = MuxSink {
            fd: AsyncFd::new(write_fd).context(split_error::AsyncFdSnafu)?,
            shared: writer_shared.clone(),
            fd_sender: FdSender {
                shared: writer_shared,
            },
            bytes_queue: VecDeque::new(),
            current: None,
        };
        let stream = MuxStream {
            fd: AsyncFd::new(read_fd).context(split_error::AsyncFdSnafu)?,
            registry: registry.clone(),
            read_buf: BytesMut::new(),
            ancillary_queue: VecDeque::new(),
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
}

#[derive(Debug)]
struct QueuedFds {
    id: VarInt,
    fds: Vec<OwnedFd>,
}

#[derive(Debug)]
struct WriterShared {
    next_id: AtomicU64,
    queue: Mutex<VecDeque<QueuedFds>>,
    closed: AtomicBool,
}

#[derive(Clone, Debug)]
pub struct FdSender {
    shared: Arc<WriterShared>,
}

impl FdSender {
    pub fn queue_fds(&self, fds: Vec<OwnedFd>) -> Result<VarInt, QueueFdsError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(QueueFdsError::Closed);
        }
        if fds.is_empty() {
            return Err(QueueFdsError::EmptyFds);
        }

        let id_raw = self
            .shared
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let next = current.checked_add(1)?;
                if next >= VARINT_MAX { None } else { Some(next) }
            })
            .map_err(|_| QueueFdsError::IdExhausted)?;

        let id = VarInt::from_u64(id_raw).map_err(|_| QueueFdsError::IdExhausted)?;

        let mut queue = self.shared.queue.lock().expect("fd queue poisoned");
        queue.push_back(QueuedFds { id, fds });

        Ok(id)
    }
}

#[derive(Debug)]
pub struct MuxSink {
    fd: AsyncFd<OwnedFd>,
    shared: Arc<WriterShared>,
    fd_sender: FdSender,
    bytes_queue: VecDeque<Bytes>,
    current: Option<PendingWriteFrame>,
}

impl MuxSink {
    pub fn fd_sender(&self) -> FdSender {
        self.fd_sender.clone()
    }

    fn pop_next_frame(&mut self) -> Option<PendingWriteFrame> {
        if let Some(queued_fds) = self
            .shared
            .queue
            .lock()
            .expect("fd queue poisoned")
            .pop_front()
        {
            return Some(PendingWriteFrame::new_fds(queued_fds.id, queued_fds.fds));
        }

        self.bytes_queue
            .pop_front()
            .map(PendingWriteFrame::new_bytes)
    }

    fn poll_flush_internal(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), MuxSinkError>> {
        if self.shared.closed.load(Ordering::Acquire) {
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
                    self.shared.closed.store(true, Ordering::Release);
                    return Poll::Ready(Err(MuxSinkError::Send { source }));
                }
                Err(_would_block) => return Poll::Pending,
            };

            if sent == 0 {
                self.shared.closed.store(true, Ordering::Release);
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
        self.shared.closed.store(true, Ordering::Release);
        let _ = shutdown(self.fd.get_ref().as_raw_fd(), Shutdown::Write);
    }
}

impl Sink<Bytes> for MuxSink {
    type Error = MuxSinkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_internal(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(MuxSinkError::Closed);
        }
        self.bytes_queue.push_back(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_internal(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let result = ready!(self.poll_flush_internal(cx));
        self.shared.closed.store(true, Ordering::Release);
        if result.is_ok() {
            let _ = shutdown(self.fd.get_ref().as_raw_fd(), Shutdown::Write);
        }
        Poll::Ready(result)
    }
}

#[derive(Debug)]
enum PendingWriteFrame {
    Bytes {
        data: Vec<u8>,
        written: usize,
    },
    Fds {
        data: Vec<u8>,
        written: usize,
        fds: Vec<OwnedFd>,
        include_ancillary: bool,
    },
}

impl PendingWriteFrame {
    fn new_bytes(payload: Bytes) -> Self {
        let data = encode_frame(FRAME_TYPE_BYTES, &payload);
        Self::Bytes { data, written: 0 }
    }

    fn new_fds(id: VarInt, fds: Vec<OwnedFd>) -> Self {
        let mut payload = [0u8; VarInt::MAX_SIZE];
        let payload_len = encode_varint_to_slice(&mut payload, id);
        let data = encode_frame(FRAME_TYPE_FDS, &payload[..payload_len]);

        Self::Fds {
            data,
            written: 0,
            fds,
            include_ancillary: true,
        }
    }

    fn advance(&mut self, n: usize) {
        match self {
            Self::Bytes { written, .. } => *written += n,
            Self::Fds {
                written,
                include_ancillary,
                ..
            } => {
                *written += n;
                if n > 0 {
                    *include_ancillary = false;
                }
            }
        }
    }

    fn is_complete(&self) -> bool {
        match self {
            Self::Bytes { data, written } => *written >= data.len(),
            Self::Fds { data, written, .. } => *written >= data.len(),
        }
    }
}

fn send_frame(fd: RawFd, frame: &mut PendingWriteFrame) -> io::Result<usize> {
    let (data, written, ancillary_fds) = match frame {
        PendingWriteFrame::Bytes { data, written } => (&data[..], *written, None),
        PendingWriteFrame::Fds {
            data,
            written,
            fds,
            include_ancillary,
        } => {
            let ancillary = if *include_ancillary {
                Some(fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>())
            } else {
                None
            };
            (&data[..], *written, ancillary)
        }
    };

    if written >= data.len() {
        return Ok(0);
    }

    let iov = [io::IoSlice::new(&data[written..])];

    let sent = match ancillary_fds {
        Some(raw_fds) => {
            let cmsgs = [ControlMessage::ScmRights(&raw_fds)];
            sendmsg::<()>(fd, &iov, &cmsgs, MsgFlags::empty(), None)
        }
        None => sendmsg::<()>(fd, &iov, &[], MsgFlags::empty(), None),
    }
    .map_err(io::Error::from)?;

    Ok(sent)
}

#[derive(Clone, Debug)]
pub struct FdRegistry {
    inner: Arc<Mutex<RegistryState>>,
}

#[derive(Debug)]
struct RegistryState {
    slots: HashMap<VarInt, RegistrySlot>,
    closed: bool,
}

#[derive(Debug)]
enum RegistrySlot {
    Ready(Vec<OwnedFd>),
    Waiting(oneshot::Sender<Result<Vec<OwnedFd>, WaitFdsError>>),
    Consumed,
}

impl FdRegistry {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RegistryState {
                slots: HashMap::new(),
                closed: false,
            })),
        }
    }

    pub async fn wait_fds(&self, id: VarInt) -> Result<Vec<OwnedFd>, WaitFdsError> {
        let rx = {
            let mut state = self.inner.lock().expect("registry mutex poisoned");
            if state.closed {
                return Err(WaitFdsError::Closed);
            }

            if let Some(existing) = state.slots.remove(&id) {
                match existing {
                    RegistrySlot::Ready(fds) => {
                        state.slots.insert(id, RegistrySlot::Consumed);
                        return Ok(fds);
                    }
                    RegistrySlot::Waiting(waiter) => {
                        state.slots.insert(id, RegistrySlot::Waiting(waiter));
                        return Err(WaitFdsError::AlreadyWaiting { id });
                    }
                    RegistrySlot::Consumed => {
                        state.slots.insert(id, RegistrySlot::Consumed);
                        return Err(WaitFdsError::AlreadyConsumed { id });
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

    fn register_arrival(&self, id: VarInt, fds: Vec<OwnedFd>) -> Result<(), RegisterFdsError> {
        let mut state = self.inner.lock().expect("registry mutex poisoned");
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
                    let recovered_fds = payload.unwrap_or_default();
                    state.slots.insert(id, RegistrySlot::Ready(recovered_fds));
                } else {
                    state.slots.insert(id, RegistrySlot::Consumed);
                }
                Ok(())
            }
            Some(RegistrySlot::Ready(existing_fds)) => {
                state.slots.insert(id, RegistrySlot::Ready(existing_fds));
                Err(RegisterFdsError::DuplicateId { id })
            }
            Some(RegistrySlot::Consumed) => {
                state.slots.insert(id, RegistrySlot::Consumed);
                Err(RegisterFdsError::DuplicateId { id })
            }
        }
    }

    fn close(&self) {
        let mut state = self.inner.lock().expect("registry mutex poisoned");
        if state.closed {
            return;
        }
        state.closed = true;

        for slot in state.slots.values_mut() {
            if let RegistrySlot::Waiting(waiter) = std::mem::replace(slot, RegistrySlot::Consumed) {
                let _ = waiter.send(Err(WaitFdsError::Closed));
            }
        }
    }
}

#[derive(Debug)]
pub struct MuxStream {
    fd: AsyncFd<OwnedFd>,
    registry: FdRegistry,
    read_buf: BytesMut,
    ancillary_queue: VecDeque<Vec<OwnedFd>>,
    closed: bool,
}

impl MuxStream {
    pub fn fd_registry(&self) -> FdRegistry {
        self.registry.clone()
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.registry.close();
    }
}

impl Stream for MuxStream {
    type Item = Result<Bytes, MuxStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }

        loop {
            if let Some(frame) = match try_decode_frame(&mut self.read_buf) {
                Ok(frame) => frame,
                Err(err) => {
                    self.closed = true;
                    self.registry.close();
                    return Poll::Ready(Some(Err(err)));
                }
            } {
                match frame {
                    DecodedFrame::Bytes(payload) => return Poll::Ready(Some(Ok(payload))),
                    DecodedFrame::Fds { id } => {
                        let Some(fds) = self.ancillary_queue.pop_front() else {
                            self.closed = true;
                            self.registry.close();
                            return Poll::Ready(Some(Err(MuxStreamError::MissingAncillaryFds)));
                        };
                        if let Err(source) = self.registry.register_arrival(id, fds) {
                            self.closed = true;
                            self.registry.close();
                            return Poll::Ready(Some(Err(MuxStreamError::RegisterFds { source })));
                        }
                        continue;
                    }
                }
            }

            let mut guard = match ready!(self.fd.poll_read_ready(cx)) {
                Ok(guard) => guard,
                Err(source) => return Poll::Ready(Some(Err(MuxStreamError::PollReady { source }))),
            };

            let mut read_buf = [0u8; READ_CHUNK_LEN];
            let io_result =
                guard.try_io(|inner| recv_frame_data(inner.get_ref().as_raw_fd(), &mut read_buf));

            let (read, ancillary) = match io_result {
                Ok(Ok(result)) => result,
                Ok(Err(source)) => {
                    self.closed = true;
                    self.registry.close();
                    return Poll::Ready(Some(Err(MuxStreamError::Recv { source })));
                }
                Err(_would_block) => return Poll::Pending,
            };

            if read == 0 {
                self.closed = true;
                self.registry.close();
                return Poll::Ready(None);
            }

            if !ancillary.is_empty() {
                self.ancillary_queue.push_back(ancillary);
            }
            self.read_buf.extend_from_slice(&read_buf[..read]);
        }
    }
}

fn recv_frame_data(fd: RawFd, data_buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut iov = [io::IoSliceMut::new(data_buf)];
    let mut cmsg_buf = cmsg_space!([RawFd; MAX_FDS_PER_MESSAGE]);

    let msg = recvmsg::<()>(
        fd,
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(io::Error::from)?;

    let mut fds = Vec::new();
    let cmsgs = msg.cmsgs().map_err(io::Error::from)?;
    for cmsg in cmsgs {
        if let ControlMessageOwned::ScmRights(raw_fds) = cmsg {
            for raw_fd in raw_fds {
                // SAFETY: SCM_RIGHTS transfers ownership of a new fd to receiver.
                let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
                fds.push(fd);
            }
        }
    }

    Ok((msg.bytes, fds))
}

#[derive(Debug)]
enum DecodedFrame {
    Bytes(Bytes),
    Fds { id: VarInt },
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
            let (id, consumed) = decode_varint_from_slice(&payload)?;
            if consumed != payload.len() {
                return Err(MuxStreamError::InvalidFdsPayload);
            }
            Ok(Some(DecodedFrame::Fds { id }))
        }
        _ => Err(MuxStreamError::UnknownFrameType { frame_type }),
    }
}

fn encode_frame(frame_type: u8, payload: &[u8]) -> Vec<u8> {
    let payload_len = VarInt::try_from(payload.len()).expect("payload length must fit varint");
    let mut out = Vec::with_capacity(MAX_FRAME_HEADER_LEN + payload.len());
    out.push(frame_type);

    let mut len_buf = [0u8; VarInt::MAX_SIZE];
    let len_size = encode_varint_to_slice(&mut len_buf, payload_len);
    out.extend_from_slice(&len_buf[..len_size]);
    out.extend_from_slice(payload);
    out
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
            .queue_fds(vec![fd_a.into()])
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
            .queue_fds(vec![fd_a.into()])
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
        let registry = FdRegistry::new();

        let (fd1, _peer1) = StdUnixStream::pair().expect("pair1");
        let (fd2, _peer2) = StdUnixStream::pair().expect("pair2");
        let id = VarInt::from_u32(7);

        registry
            .register_arrival(id, vec![fd1.into()])
            .expect("first arrival");
        let duplicate = registry.register_arrival(id, vec![fd2.into()]);
        assert!(matches!(
            duplicate,
            Err(RegisterFdsError::DuplicateId { .. })
        ));

        let first = registry.wait_fds(id).await.expect("first still valid");
        assert_eq!(first.len(), 1);
    }

    #[tokio::test]
    async fn interleaved_fd_and_bytes_do_not_leak_fd_frames() {
        let ((mut sink_a, _stream_a), (_sink_b, mut stream_b)) = make_pair();

        let registry = stream_b.fd_registry();
        let (fd_a, _fd_b) = StdUnixStream::pair().expect("fd pair");
        let id = sink_a
            .fd_sender()
            .queue_fds(vec![fd_a.into()])
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
}
