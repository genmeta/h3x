use std::{
    collections::VecDeque,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{Arc, Mutex, Weak},
};

use bytes::{Bytes, BytesMut};
use futures::task::AtomicWaker;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, Shutdown, recvmsg, shutdown};
use tokio::{
    io::unix::AsyncFd,
    sync::{Notify, mpsc},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument as _;

use super::{FdVec, MAX_FDS_PER_FRAME, MuxStreamError, QueueFdsError, fd_plane::FdPlaneCore};
use crate::{ipc::transport::frame, varint::VarInt};

const READ_CHUNK_LEN: usize = 8 * 1024;
const MIN_FDS_FRAME_LEN: usize = 4;

pub(crate) type ReaderStart = (
    mpsc::UnboundedReceiver<Result<Bytes, MuxStreamError>>,
    AbortOnDropHandle<()>,
);

#[derive(Debug)]
pub(crate) struct WriterCore {
    fd: AsyncFd<OwnedFd>,
    state: Mutex<WriterState>,
    notify: Notify,
    flush_waker: AtomicWaker,
}

#[derive(Debug)]
struct WriterState {
    queue: VecDeque<frame::OutboundFrame>,
    closed: bool,
    in_flight: bool,
}

impl WriterCore {
    pub(crate) fn queue(&self, frame: frame::OutboundFrame) -> Result<(), QueueFdsError> {
        let mut state = self.state.lock().expect("writer state poisoned");
        if state.closed {
            return Err(QueueFdsError::Closed);
        }
        state.queue.push_back(frame);
        drop(state);
        self.notify.notify_one();
        self.flush_waker.wake();
        Ok(())
    }

    pub(crate) fn close(&self) {
        let mut state = self.state.lock().expect("writer state poisoned");
        state.closed = true;
        drop(state);
        self.notify.notify_one();
        self.flush_waker.wake();
    }

    pub(crate) fn shutdown_write(&self) {
        let _ = shutdown(self.fd.get_ref().as_raw_fd(), Shutdown::Write);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().expect("writer state poisoned").closed
    }

    pub(crate) fn is_flushed(&self) -> bool {
        let state = self.state.lock().expect("writer state poisoned");
        state.queue.is_empty() && !state.in_flight
    }

    pub(crate) fn register_flush_waker(&self, waker: &std::task::Waker) {
        self.flush_waker.register(waker);
    }
}

#[derive(Clone, Debug)]
pub struct FdSender {
    core: Weak<WriterCore>,
}

impl FdSender {
    fn new(core: &Arc<WriterCore>) -> Self {
        Self {
            core: Arc::downgrade(core),
        }
    }

    pub(crate) fn send_fds(&self, id: VarInt, fds: FdVec) -> Result<(), QueueFdsError> {
        if fds.is_empty() {
            return Err(QueueFdsError::EmptyFds);
        }
        if fds.len() > MAX_FDS_PER_FRAME {
            return Err(QueueFdsError::TooManyFds { count: fds.len() });
        }
        self.queue(frame::OutboundFrame::Fds { id, fds })
    }

    fn queue(&self, frame: frame::OutboundFrame) -> Result<(), QueueFdsError> {
        let Some(core) = self.core.upgrade() else {
            return Err(QueueFdsError::Closed);
        };
        core.queue(frame)
    }
}

pub(crate) fn start_writer(
    fd: OwnedFd,
) -> io::Result<(Arc<WriterCore>, FdSender, AbortOnDropHandle<()>)> {
    let core = Arc::new(WriterCore {
        fd: AsyncFd::new(fd)?,
        state: Mutex::new(WriterState {
            queue: VecDeque::new(),
            closed: false,
            in_flight: false,
        }),
        notify: Notify::new(),
        flush_waker: AtomicWaker::new(),
    });
    let sender = FdSender::new(&core);
    let task = AbortOnDropHandle::new(tokio::spawn(writer_loop(core.clone()).in_current_span()));
    Ok((core, sender, task))
}

pub(crate) fn start_reader(fd: OwnedFd, plane: Arc<FdPlaneCore>) -> io::Result<ReaderStart> {
    let fd = AsyncFd::new(fd)?;
    let (bytes_tx, bytes_rx) = mpsc::unbounded_channel();
    let task = AbortOnDropHandle::new(tokio::spawn(
        reader_loop(fd, plane, bytes_tx).in_current_span(),
    ));
    Ok((bytes_rx, task))
}

async fn writer_loop(core: Arc<WriterCore>) {
    let mut current = None;

    loop {
        if current.is_none() {
            let next = {
                let mut state = core.state.lock().expect("writer state poisoned");
                if let Some(frame) = state.queue.pop_front() {
                    state.in_flight = true;
                    Some(frame)
                } else {
                    state.in_flight = false;
                    core.flush_waker.wake();
                    if state.closed {
                        break;
                    }
                    None
                }
            };

            let Some(frame) = next else {
                core.notify.notified().await;
                continue;
            };
            current = Some(frame::pending_frame(frame));
        }

        let pending = current.as_mut().expect("pending frame must exist");
        if !write_pending_frame(&core.fd, pending).await {
            break;
        }

        if pending.is_complete() {
            current = None;
            let mut state = core.state.lock().expect("writer state poisoned");
            state.in_flight = false;
            if state.queue.is_empty() {
                core.flush_waker.wake();
            }
        }
    }

    let _ = shutdown(core.fd.get_ref().as_raw_fd(), Shutdown::Write);
    let mut state = core.state.lock().expect("writer state poisoned");
    state.closed = true;
    state.in_flight = false;
    state.queue.clear();
    drop(state);
    core.flush_waker.wake();
}

async fn write_pending_frame(fd: &AsyncFd<OwnedFd>, frame: &mut frame::PendingFrame) -> bool {
    while !frame.is_complete() {
        let mut guard = match fd.writable().await {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        let result =
            guard.try_io(|inner| frame::send_pending_frame(inner.get_ref().as_raw_fd(), frame));
        let sent = match result {
            Ok(Ok(sent)) => sent,
            Ok(Err(_error)) => return false,
            Err(_would_block) => continue,
        };
        if sent == 0 {
            return false;
        }
    }
    true
}

async fn reader_loop(
    fd: AsyncFd<OwnedFd>,
    plane: Arc<FdPlaneCore>,
    bytes_tx: mpsc::UnboundedSender<Result<Bytes, MuxStreamError>>,
) {
    let mut read_buf = BytesMut::new();
    let mut cmsg_buf = {
        let per_msg = nix::sys::socket::cmsg_space::<[RawFd; MAX_FDS_PER_FRAME]>();
        let max_msgs = READ_CHUNK_LEN / MIN_FDS_FRAME_LEN;
        vec![0u8; max_msgs * per_msg]
    };
    let mut pending_fds = VecDeque::new();
    let mut pending_fd_frame = None;

    loop {
        if let Some((id, fd_count)) = pending_fd_frame {
            if pending_fds.len() >= fd_count {
                pending_fd_frame = None;
                let fds: FdVec = pending_fds.drain(..fd_count).collect();
                plane.arrive_fds(id, fds);
                continue;
            }
        } else {
            match frame::try_decode_frame(&mut read_buf) {
                Ok(Some(frame::InboundFrame::Bytes(payload))) => {
                    if bytes_tx.send(Ok(payload)).is_err() {
                        plane.close();
                        return;
                    }
                    continue;
                }
                Ok(Some(frame::InboundFrame::Fds { id, fd_count })) => {
                    if pending_fds.len() >= fd_count {
                        let fds: FdVec = pending_fds.drain(..fd_count).collect();
                        plane.arrive_fds(id, fds);
                        continue;
                    }
                    pending_fd_frame = Some((id, fd_count));
                }
                Ok(None) => {}
                Err(error) => {
                    plane.close();
                    let _ = bytes_tx.send(Err(error));
                    return;
                }
            }
        }

        let mut chunk = [0u8; READ_CHUNK_LEN];
        let mut guard = match fd.readable().await {
            Ok(guard) => guard,
            Err(source) => {
                plane.close();
                let _ = bytes_tx.send(Err(MuxStreamError::PollReady { source }));
                return;
            }
        };
        let result = guard.try_io(|inner| {
            recv_frame_data(inner.get_ref().as_raw_fd(), &mut chunk, &mut cmsg_buf)
        });

        let (read, ancillary) = match result {
            Ok(Ok(RecvOutcome::Data { read, ancillary })) => (read, ancillary),
            Ok(Ok(RecvOutcome::AncillaryTruncated)) => {
                plane.close();
                let _ = bytes_tx.send(Err(MuxStreamError::AncillaryTruncated));
                return;
            }
            Ok(Err(source)) => {
                plane.close();
                let _ = bytes_tx.send(Err(MuxStreamError::Recv { source }));
                return;
            }
            Err(_would_block) => continue,
        };

        if read == 0 {
            plane.close();
            if pending_fd_frame.is_some() {
                let _ = bytes_tx.send(Err(MuxStreamError::MissingAncillaryFds));
            }
            return;
        }

        if !ancillary.is_empty() {
            pending_fds.extend(ancillary);
        }
        read_buf.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(not(target_os = "linux"))]
fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{F_GETFD, F_SETFD, FdFlag, fcntl};
    let raw = fd.as_raw_fd();
    let bits = match fcntl(raw, F_GETFD) {
        Ok(bits) => bits,
        Err(error) => return Err(io::Error::from(error)),
    };
    let new_flags = FdFlag::from_bits_truncate(bits) | FdFlag::FD_CLOEXEC;
    if let Err(error) = fcntl(raw, F_SETFD(new_flags)) {
        return Err(io::Error::from(error));
    }
    Ok(())
}

enum RecvOutcome {
    Data { read: usize, ancillary: FdVec },
    AncillaryTruncated,
}

fn recv_frame_data(fd: RawFd, data_buf: &mut [u8], cmsg_buf: &mut [u8]) -> io::Result<RecvOutcome> {
    let mut iov = [io::IoSliceMut::new(data_buf)];

    #[cfg(target_os = "linux")]
    let recv_flags = MsgFlags::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let recv_flags = MsgFlags::empty();

    let msg = match recvmsg::<()>(fd, &mut iov, Some(cmsg_buf), recv_flags) {
        Ok(msg) => msg,
        Err(error) => return Err(io::Error::from(error)),
    };
    if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
        return Ok(RecvOutcome::AncillaryTruncated);
    }

    let mut fds = FdVec::new();
    let cmsgs = match msg.cmsgs() {
        Ok(cmsgs) => cmsgs,
        Err(error) => return Err(io::Error::from(error)),
    };
    for cmsg in cmsgs {
        if let ControlMessageOwned::ScmRights(raw_fds) = cmsg {
            for raw_fd in raw_fds {
                // SAFETY: SCM_RIGHTS transfers ownership of a new fd to the receiver.
                let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
                #[cfg(not(target_os = "linux"))]
                if let Err(source) = set_cloexec(&fd) {
                    return Err(source);
                }
                fds.push(fd);
            }
        }
    }

    Ok(RecvOutcome::Data {
        read: msg.bytes,
        ancillary: fds,
    })
}
