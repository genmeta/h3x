use std::{
    io,
    os::fd::{AsRawFd, RawFd},
};

use bytes::{Buf, Bytes, BytesMut};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use smallvec::SmallVec;

use super::{FdVec, MAX_FDS_PER_FRAME, MuxStreamError};
use crate::varint::{VARINT_MAX, VarInt};

const FRAME_TYPE_BYTES: u8 = 0x00;
const FRAME_TYPE_FDS: u8 = 0x01;
const FRAME_TYPE_CANCEL_FDS: u8 = 0x02;
const FRAME_TYPE_ACK_FDS: u8 = 0x03;

const MAX_FRAME_HEADER_LEN: usize = 1 + VarInt::MAX_SIZE;
const MAX_FDS_FRAME_LEN: usize = 1 + VarInt::MAX_SIZE + VarInt::MAX_SIZE + VarInt::MAX_SIZE;
const MAX_ID_FRAME_LEN: usize = 1 + VarInt::MAX_SIZE + VarInt::MAX_SIZE;

#[derive(Debug)]
pub(crate) enum OutboundFrame {
    Bytes(Bytes),
    Fds { id: VarInt, fds: FdVec },
    CancelFds { id: VarInt },
    AckFds { id: VarInt },
}

#[derive(Debug)]
pub(crate) enum InboundFrame {
    Bytes(Bytes),
    Fds { id: VarInt, fd_count: usize },
    CancelFds { id: VarInt },
    AckFds { id: VarInt },
}

#[derive(Debug)]
pub(crate) enum PendingFrame {
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
    Id {
        header: [u8; MAX_ID_FRAME_LEN],
        header_len: usize,
        header_written: usize,
    },
}

impl PendingFrame {
    fn new_bytes(payload: Bytes) -> Self {
        let payload_len = VarInt::try_from(payload.len()).expect("payload length fits varint");
        let mut header = [0u8; MAX_FRAME_HEADER_LEN];
        header[0] = FRAME_TYPE_BYTES;
        let len_len = encode_varint_to_slice(&mut header[1..], payload_len);
        Self::Bytes {
            header,
            header_len: 1 + len_len,
            header_written: 0,
            payload,
            payload_written: 0,
        }
    }

    fn new_fds(id: VarInt, fds: FdVec) -> Self {
        let fd_count = VarInt::try_from(fds.len()).expect("fd count fits varint");

        let mut id_buf = [0u8; VarInt::MAX_SIZE];
        let id_len = encode_varint_to_slice(&mut id_buf, id);
        let mut count_buf = [0u8; VarInt::MAX_SIZE];
        let count_len = encode_varint_to_slice(&mut count_buf, fd_count);

        let mut header = [0u8; MAX_FDS_FRAME_LEN];
        header[0] = FRAME_TYPE_FDS;
        let body_len = VarInt::try_from(id_len + count_len).expect("fd body length fits varint");
        let len_len = encode_varint_to_slice(&mut header[1..], body_len);
        let body_start = 1 + len_len;
        header[body_start..body_start + id_len].copy_from_slice(&id_buf[..id_len]);
        header[body_start + id_len..body_start + id_len + count_len]
            .copy_from_slice(&count_buf[..count_len]);

        Self::Fds {
            header,
            header_len: body_start + id_len + count_len,
            header_written: 0,
            payload: fds,
            include_ancillary: true,
        }
    }

    fn new_id(frame_type: u8, id: VarInt) -> Self {
        let mut id_buf = [0u8; VarInt::MAX_SIZE];
        let id_len = encode_varint_to_slice(&mut id_buf, id);

        let mut header = [0u8; MAX_ID_FRAME_LEN];
        header[0] = frame_type;
        let body_len = VarInt::try_from(id_len).expect("id body length fits varint");
        let len_len = encode_varint_to_slice(&mut header[1..], body_len);
        let body_start = 1 + len_len;
        header[body_start..body_start + id_len].copy_from_slice(&id_buf[..id_len]);

        Self::Id {
            header,
            header_len: body_start + id_len,
            header_written: 0,
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
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
            }
            | Self::Id {
                header_len,
                header_written,
                ..
            } => *header_written >= *header_len,
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
            Self::Id { header_written, .. } => {
                *header_written += n;
            }
        }
    }
}

pub(crate) fn pending_frame(frame: OutboundFrame) -> PendingFrame {
    match frame {
        OutboundFrame::Bytes(payload) => PendingFrame::new_bytes(payload),
        OutboundFrame::Fds { id, fds } => PendingFrame::new_fds(id, fds),
        OutboundFrame::CancelFds { id } => PendingFrame::new_id(FRAME_TYPE_CANCEL_FDS, id),
        OutboundFrame::AckFds { id } => PendingFrame::new_id(FRAME_TYPE_ACK_FDS, id),
    }
}

pub(crate) fn send_pending_frame(fd: RawFd, frame: &mut PendingFrame) -> io::Result<usize> {
    let sent = match frame {
        PendingFrame::Bytes {
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
            sendmsg::<()>(fd, &iovecs[..iov_count], &[], MsgFlags::empty(), None)
        }
        PendingFrame::Fds {
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
            if *include_ancillary {
                let raw_fds: SmallVec<[RawFd; 4]> =
                    payload.iter().map(AsRawFd::as_raw_fd).collect();
                let cmsgs = [ControlMessage::ScmRights(&raw_fds)];
                sendmsg::<()>(fd, &iov, &cmsgs, MsgFlags::empty(), None)
            } else {
                sendmsg::<()>(fd, &iov, &[], MsgFlags::empty(), None)
            }
        }
        PendingFrame::Id {
            header,
            header_len,
            header_written,
        } => {
            if *header_written >= *header_len {
                return Ok(0);
            }
            let iov = [io::IoSlice::new(&header[*header_written..*header_len])];
            sendmsg::<()>(fd, &iov, &[], MsgFlags::empty(), None)
        }
    };

    let sent = match sent {
        Ok(sent) => sent,
        Err(error) => return Err(io::Error::from(error)),
    };
    frame.advance(sent);
    Ok(sent)
}

pub(crate) fn try_decode_frame(src: &mut BytesMut) -> Result<Option<InboundFrame>, MuxStreamError> {
    if src.is_empty() {
        return Ok(None);
    }

    let frame_type = src[0];
    if frame_type != FRAME_TYPE_BYTES
        && frame_type != FRAME_TYPE_FDS
        && frame_type != FRAME_TYPE_CANCEL_FDS
        && frame_type != FRAME_TYPE_ACK_FDS
    {
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
        FRAME_TYPE_BYTES => Ok(Some(InboundFrame::Bytes(payload))),
        FRAME_TYPE_FDS => {
            let (id, id_consumed) = decode_varint_from_slice(&payload)?;
            let remaining = &payload[id_consumed..];
            let (fd_count_vi, count_consumed) = decode_varint_from_slice(remaining)?;
            if id_consumed + count_consumed != payload.len() {
                return Err(MuxStreamError::InvalidFdsPayload);
            }
            let Ok(fd_count) = usize::try_from(u64::from(fd_count_vi)) else {
                return Err(MuxStreamError::InvalidFdsPayload);
            };
            if fd_count == 0 || fd_count > MAX_FDS_PER_FRAME {
                return Err(MuxStreamError::InvalidFdsPayload);
            }
            Ok(Some(InboundFrame::Fds { id, fd_count }))
        }
        FRAME_TYPE_CANCEL_FDS => Ok(Some(InboundFrame::CancelFds {
            id: decode_id_payload(&payload)?,
        })),
        FRAME_TYPE_ACK_FDS => Ok(Some(InboundFrame::AckFds {
            id: decode_id_payload(&payload)?,
        })),
        _ => Err(MuxStreamError::UnknownFrameType { frame_type }),
    }
}

fn decode_id_payload(payload: &[u8]) -> Result<VarInt, MuxStreamError> {
    let (id, consumed) = decode_varint_from_slice(payload)?;
    if consumed != payload.len() {
        return Err(MuxStreamError::InvalidFdsPayload);
    }
    Ok(id)
}

fn try_decode_varint_len(src: &[u8]) -> Result<Option<(usize, usize)>, MuxStreamError> {
    let Some((value, consumed)) = try_decode_varint(src)? else {
        return Ok(None);
    };
    let Ok(payload_len) = usize::try_from(value) else {
        return Err(MuxStreamError::InvalidFrameLength);
    };
    Ok(Some((payload_len, consumed)))
}

fn decode_varint_from_slice(src: &[u8]) -> Result<(VarInt, usize), MuxStreamError> {
    let Some((value, consumed)) = try_decode_varint(src)? else {
        return Err(MuxStreamError::InvalidFdsPayload);
    };
    let Ok(id) = VarInt::from_u64(value) else {
        return Err(MuxStreamError::InvalidFdsPayload);
    };
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
    use super::*;

    #[test]
    fn decodes_cancel_frame() {
        let mut bytes = BytesMut::from(&[FRAME_TYPE_CANCEL_FDS, 0x01, 0x05][..]);
        let frame = try_decode_frame(&mut bytes)
            .expect("decode")
            .expect("frame");
        assert!(matches!(frame, InboundFrame::CancelFds { id } if id == VarInt::from_u32(5)));
    }

    #[test]
    fn decodes_ack_frame() {
        let mut bytes = BytesMut::from(&[FRAME_TYPE_ACK_FDS, 0x01, 0x07][..]);
        let frame = try_decode_frame(&mut bytes)
            .expect("decode")
            .expect("frame");
        assert!(matches!(frame, InboundFrame::AckFds { id } if id == VarInt::from_u32(7)));
    }
}
