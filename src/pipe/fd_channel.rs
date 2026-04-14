//! [`FdChannel`] — high-performance FD passing over `SOCK_SEQPACKET`.
//!
//! Transfers file descriptors (pipe/socketpair endpoints) between processes via
//! `SCM_RIGHTS` ancillary messages.  Each SEQPACKET message carries:
//!
//! - A VarInt-encoded stream ID as ordinary data
//! - One or more file descriptors as ancillary `SCM_RIGHTS` payload
//!
//! The SEQPACKET message boundary naturally frames each (stream_id, fds) pair,
//! so no additional length-delimited framing is needed.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use snafu::ResultExt;

use crate::varint::VarInt;

/// Maximum number of FDs per message (bidi stream = 2 socketpairs = 4 FDs).
const MAX_FDS_PER_MSG: usize = 4;

/// Maximum data payload per message (VarInt is at most 8 bytes).
const MAX_DATA_LEN: usize = 8;

/// Error from [`FdChannel::send`].
#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum SendFdsError {
    #[snafu(display("failed to send message via seqpacket"))]
    Send { source: nix::Error },
}

/// Error from [`FdChannel::recv`].
#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum RecvFdsError {
    #[snafu(display("failed to receive message via seqpacket"))]
    Recv { source: nix::Error },
    #[snafu(display("failed to parse control messages"))]
    ParseCmsg { source: nix::Error },
    #[snafu(display("no file descriptors in received message"))]
    NoFds,
    #[snafu(display("incomplete varint in message data"))]
    IncompleteVarInt,
    #[snafu(display("channel closed by remote end"))]
    Closed,
}

/// Encode a QUIC VarInt into a small stack buffer, returning the number of
/// bytes written.
fn encode_varint(buf: &mut [u8; MAX_DATA_LEN], v: VarInt) -> usize {
    let x = v.into_inner();
    if x < (1 << 6) {
        buf[0] = x as u8;
        1
    } else if x < (1 << 14) {
        let val = (0b01u16 << 14) | x as u16;
        buf[..2].copy_from_slice(&val.to_be_bytes());
        2
    } else if x < (1 << 30) {
        let val = (0b10u32 << 30) | x as u32;
        buf[..4].copy_from_slice(&val.to_be_bytes());
        4
    } else {
        let val = (0b11u64 << 62) | x;
        buf[..8].copy_from_slice(&val.to_be_bytes());
        8
    }
}

/// Decode a QUIC VarInt from a byte slice.
fn decode_varint(buf: &[u8]) -> Result<VarInt, RecvFdsError> {
    if buf.is_empty() {
        return Err(RecvFdsError::IncompleteVarInt);
    }
    let first = buf[0];
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return Err(RecvFdsError::IncompleteVarInt);
    }
    let mut raw = [0u8; 8];
    raw[..len].copy_from_slice(&buf[..len]);
    raw[0] &= 0x3f;
    let value = u64::from_be_bytes(raw) >> (8 * (8 - len));
    // SAFETY: value < 2^62 because we masked the two high bits.
    Ok(unsafe { VarInt::from_u64_unchecked(value) })
}

/// A channel for passing file descriptors between processes using
/// `SOCK_SEQPACKET` and `SCM_RIGHTS`.
///
/// This type wraps a raw `OwnedFd` of a `SOCK_SEQPACKET` Unix socket.
/// It does **not** create any FDs itself — it only transfers them.
pub struct FdChannel {
    fd: OwnedFd,
}

impl FdChannel {
    /// Wrap an existing `SOCK_SEQPACKET` socket.
    pub fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Send a stream ID and associated file descriptors.
    ///
    /// This is a **blocking** call. Wrap in `tokio::task::spawn_blocking` for
    /// async usage, or use a dedicated blocking thread.
    pub fn send(&self, stream_id: VarInt, fds: &[OwnedFd]) -> Result<(), SendFdsError> {
        use std::io::IoSlice;

        use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

        let mut data_buf = [0u8; MAX_DATA_LEN];
        let data_len = encode_varint(&mut data_buf, stream_id);
        let iov = [IoSlice::new(&data_buf[..data_len])];

        let raw_fds: Vec<RawFd> = fds.iter().map(|fd| fd.as_raw_fd()).collect();
        let cmsg = [ControlMessage::ScmRights(&raw_fds)];

        sendmsg::<()>(self.fd.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
            .context(send_fds_error::SendSnafu)?;

        Ok(())
    }

    /// Receive a stream ID and associated file descriptors.
    ///
    /// This is a **blocking** call. Wrap in `tokio::task::spawn_blocking` for
    /// async usage.
    pub fn recv(&self) -> Result<(VarInt, Vec<OwnedFd>), RecvFdsError> {
        use std::io::IoSliceMut;

        use nix::{
            cmsg_space,
            sys::socket::{ControlMessageOwned, MsgFlags, recvmsg},
        };

        let mut data_buf = [0u8; MAX_DATA_LEN];
        let mut cmsg_buf = cmsg_space!([RawFd; MAX_FDS_PER_MSG]);

        // Extract bytes count and FDs from the message, then release borrows
        // on data_buf so we can read it for varint decoding.
        let (nbytes, fds) = {
            let mut iov = [IoSliceMut::new(&mut data_buf)];
            let msg = recvmsg::<()>(
                self.fd.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_buf),
                MsgFlags::empty(),
            )
            .context(recv_fds_error::RecvSnafu)?;

            let nbytes = msg.bytes;

            let mut fds = Vec::new();
            for cmsg in msg.cmsgs().context(recv_fds_error::ParseCmsgSnafu)? {
                if let ControlMessageOwned::ScmRights(received_fds) = cmsg {
                    for raw_fd in received_fds {
                        // SAFETY: the kernel just gave us this fd via SCM_RIGHTS.
                        fds.push(unsafe { OwnedFd::from_raw_fd(raw_fd) });
                    }
                }
            }

            (nbytes, fds)
        };

        if nbytes == 0 {
            return Err(RecvFdsError::Closed);
        }

        let stream_id = decode_varint(&data_buf[..nbytes])?;

        snafu::ensure!(!fds.is_empty(), recv_fds_error::NoFdsSnafu);

        Ok((stream_id, fds))
    }
}
