//! [`FdChannel`] — high-performance async FD passing over `SOCK_SEQPACKET`.
//!
//! Transfers file descriptors (pipe/socketpair endpoints) between processes via
//! `SCM_RIGHTS` ancillary messages.  Each SEQPACKET message carries:
//!
//! - A VarInt-encoded stream ID as ordinary data
//! - One or more file descriptors as ancillary `SCM_RIGHTS` payload
//!
//! The SEQPACKET message boundary naturally frames each (stream_id, fds) pair,
//! so no additional length-delimited framing is needed.

use std::{
    io::{self, IoSlice, IoSliceMut},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use snafu::ResultExt;
use tokio_seqpacket::{
    UnixSeqpacket,
    ancillary::{AddControlMessageError, AncillaryMessageWriter, OwnedAncillaryMessage},
};

use crate::{
    codec::{DecodeFrom, EncodeInto},
    varint::VarInt,
};

/// Maximum number of FDs per message (bidi stream = 2 socketpairs = 4 FDs).
const MAX_FDS_PER_MSG: usize = 4;

/// Maximum data payload per message (VarInt is at most 8 bytes).
const MAX_DATA_LEN: usize = VarInt::MAX_SIZE * 2;

/// Ancillary buffer size: `CMSG_SPACE(MAX_FDS_PER_MSG * sizeof(RawFd))`.
/// 64 bytes is more than enough for 4 file descriptors.
const ANCILLARY_BUF_LEN: usize =
    MAX_FDS_PER_MSG * std::mem::size_of::<std::os::unix::prelude::RawFd>();

/// Error from [`FdChannel::send`].
#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum SendFdsError {
    #[snafu(display("failed to encode stream id"))]
    EncodeStreamId { source: io::Error },
    #[snafu(display("failed to add file descriptors to ancillary message"))]
    AddFds { source: AddControlMessageError },
    #[snafu(display("failed to send message via seqpacket"))]
    Send { source: io::Error },
}

/// Error from [`FdChannel::recv`].
#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum RecvFdsError {
    #[snafu(display("failed to receive message via seqpacket"))]
    Recv { source: io::Error },
    #[snafu(display("no file descriptors in received message"))]
    NoFds,
    #[snafu(display("failed to decode stream id"))]
    DecodeStreamId { source: io::Error },
    #[snafu(display("channel closed by remote end"))]
    Closed,
}

/// A channel for passing file descriptors between processes using
/// `SOCK_SEQPACKET` and `SCM_RIGHTS`.
///
/// This type wraps a [`UnixSeqpacket`] socket from `tokio-seqpacket`.
/// It does **not** create any FDs itself — it only transfers them.
pub struct FdChannel {
    socket: UnixSeqpacket,
}

impl FdChannel {
    /// Wrap an existing [`UnixSeqpacket`] socket.
    pub fn new(socket: UnixSeqpacket) -> Self {
        Self { socket }
    }

    /// Create a connected pair of `FdChannel`s.
    pub fn pair() -> io::Result<(Self, Self)> {
        let (a, b) = UnixSeqpacket::pair()?;
        Ok((Self::new(a), Self::new(b)))
    }

    /// Send a stream ID and associated file descriptors.
    pub async fn send(&self, stream_id: VarInt, fds: &[impl AsFd]) -> Result<(), SendFdsError> {
        let mut data_buf = Vec::with_capacity(MAX_DATA_LEN);
        stream_id
            .encode_into(&mut data_buf)
            .await
            .context(send_fds_error::EncodeStreamIdSnafu)?;

        let mut ancillary_buf = [0u8; ANCILLARY_BUF_LEN];
        let mut ancillary = AncillaryMessageWriter::new(&mut ancillary_buf);
        let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(|f| f.as_fd()).collect();
        ancillary
            .add_fds(&borrowed)
            .context(send_fds_error::AddFdsSnafu)?;

        let bufs = [IoSlice::new(&data_buf)];
        self.socket
            .send_vectored_with_ancillary(&bufs, &mut ancillary)
            .await
            .context(send_fds_error::SendSnafu)?;

        Ok(())
    }

    /// Receive a stream ID and associated file descriptors.
    pub async fn recv(&self) -> Result<(VarInt, Vec<OwnedFd>), RecvFdsError> {
        let mut data_buf = [0u8; MAX_DATA_LEN];
        let mut ancillary_buf = [0u8; ANCILLARY_BUF_LEN];

        let mut bufs = [IoSliceMut::new(&mut data_buf)];
        let (nbytes, ancillary) = self
            .socket
            .recv_vectored_with_ancillary(&mut bufs, &mut ancillary_buf)
            .await
            .context(recv_fds_error::RecvSnafu)?;

        if nbytes == 0 {
            return Err(RecvFdsError::Closed);
        }

        let mut fds = Vec::new();
        for msg in ancillary.into_messages() {
            if let OwnedAncillaryMessage::FileDescriptors(owned_fds) = msg {
                fds.extend(owned_fds);
            }
        }

        snafu::ensure!(!fds.is_empty(), recv_fds_error::NoFdsSnafu);

        let stream_id = VarInt::decode_from(&data_buf[..nbytes])
            .await
            .context(recv_fds_error::DecodeStreamIdSnafu)?;

        Ok((stream_id, fds))
    }
}
