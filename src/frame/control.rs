//! Control frame variants and wire codec.
use bytes::BufMut;
use qbase::varint::{VarInt, WriteVarInt};
use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    Error, ErrorCode, Result,
    frame::{self, Frame, FrameType, H3Frame, Write as _},
};

/// Frames permitted on the HTTP/3 control stream (RFC 9114 section 7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Control {
    Settings(Frame<frame::Settings>),
    Goaway(Frame<frame::Goaway>),
    CancelPush(Frame<frame::CancelPush>),
    MaxPushId(Frame<frame::MaxPushId>),
    /// Only the envelope is decoded; the caller consumes the payload.
    Unknown {
        ty: VarInt,
        length: VarInt,
    },
}

/// Type prefix of a peer unidirectional stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum StreamType {
    Control = 0x00,
    Push = 0x01,
    QpackEncoder = 0x02,
    QpackDecoder = 0x03,
}

impl TryFrom<VarInt> for StreamType {
    type Error = VarInt;

    fn try_from(ty: VarInt) -> std::result::Result<Self, Self::Error> {
        match ty.into_u64() {
            0 => Ok(Self::Control),
            1 => Ok(Self::Push),
            2 => Ok(Self::QpackEncoder),
            3 => Ok(Self::QpackDecoder),
            _ => Err(ty),
        }
    }
}

/// Read a unidirectional stream type; FIN/RESET before admission is stream-local.
/// None ends only this stream: EOF/RESET before the header, or an unsupported type.
/// Unknown types use STOP_SENDING, never a connection error (RFC 9114 section 6.2).
pub(crate) async fn be_stream_type<R: AsyncRead + StopSending + Unpin + ?Sized>(
    recv: &mut R,
) -> Result<Option<StreamType>> {
    match frame::be_varint(recv).await {
        Ok(Some(ty)) => match StreamType::try_from(ty) {
            Ok(ty) => Ok(Some(ty)),
            Err(_) => {
                recv.stop(ErrorCode::H3_STREAM_CREATION_ERROR.as_u64());
                Ok(None)
            }
        },
        Ok(None) => Ok(None),
        Err(error)
            if error
                .get_ref()
                .is_some_and(|source| source.is::<qbase::frame::ResetStreamError>()) =>
        {
            Ok(None)
        }
        Err(error) => Err(Error::from(error)),
    }
}

/// Encode one control frame using the shared frame codec.
pub(crate) trait WriteControl {
    fn put_control(&mut self, control: &Control);
}

impl<B: BufMut> WriteControl for B {
    fn put_control(&mut self, control: &Control) {
        match control {
            Control::Settings(frame) => self.put_frame(frame),
            Control::Goaway(frame) => self.put_frame(frame),
            Control::CancelPush(frame) => self.put_frame(frame),
            Control::MaxPushId(frame) => self.put_frame(frame),
            Control::Unknown { ty, length } => {
                self.put_varint(ty);
                self.put_varint(length);
            }
        }
    }
}

/// Read one control frame. Unknown payloads remain for the caller to discard.
/// SETTINGS ordering is checked by the receiving connection.
pub(crate) async fn be_control<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Control> {
    let ty = frame::be_varint(recv)
        .await
        .map_err(|error| crate::Error::from_io(error, ErrorCode::H3_CLOSED_CRITICAL_STREAM))?
        .ok_or_else(|| {
            ErrorCode::H3_CLOSED_CRITICAL_STREAM.reason("critical HTTP/3 stream closed")
        })?;
    let known = match ty.into_u64() {
        4 => Some(FrameType::Settings),
        3 => Some(FrameType::CancelPush),
        7 => Some(FrameType::Goaway),
        13 => Some(FrameType::MaxPushId),
        0..=9 => {
            return Err(
                ErrorCode::H3_FRAME_UNEXPECTED.reason("frame is not allowed in this context")
            );
        }
        _ => None,
    };
    let length = frame::be_varint(recv)
        .await
        .map_err(|error| crate::Error::from_io(error, ErrorCode::H3_CLOSED_CRITICAL_STREAM))?
        .ok_or_else(|| {
            ErrorCode::H3_CLOSED_CRITICAL_STREAM.reason("critical HTTP/3 stream closed")
        })?;
    let Some(known) = known else {
        return Ok(Control::Unknown { ty, length });
    };
    if length.into_u64() > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64 {
        return Err(ErrorCode::H3_EXCESSIVE_LOAD.reason("configured resource limit exceeded"));
    }
    let mut payload = vec![0; length.into_u64() as usize];
    recv.read_exact(&mut payload)
        .await
        .map_err(|error| crate::Error::from_io(error, ErrorCode::H3_CLOSED_CRITICAL_STREAM))?;
    Ok(
        match frame::be_frame_payload(&mut payload.as_slice(), known, length).await? {
            H3Frame::Settings(frame) => Control::Settings(frame),
            H3Frame::Goaway(frame) => Control::Goaway(frame),
            H3Frame::CancelPush(frame) => Control::CancelPush(frame),
            H3Frame::MaxPushId(frame) => Control::MaxPushId(frame),
            _ => unreachable!("validated control frame type"),
        },
    )
}
