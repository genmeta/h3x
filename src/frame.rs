//! HTTP/3 frames (RFC 9114 section 7.2). Stream placement is checked by the caller.
use std::io;

use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{Error, ErrorCode, Result};

mod cancel_push;
mod control;
mod data;
mod goaway;
mod headers;
mod max_push_id;
mod push_promise;
mod settings;
mod varint;

#[cfg(test)]
mod tests;

pub(crate) use varint::be_varint;

/// Local per-buffer budget for HTTP/3 frame payloads and QPACK literals/field sections.
/// DATA and unknown frame payloads are streamed without this size limit.
pub(crate) const MAX_BUFFERED_FRAME_PAYLOAD: usize = 64 * 1024;
// BufferReader DEFAULT_BUF_SIZE
pub(crate) const MAX_DATA_CHUNK: usize = 8 * 1024;

pub(crate) use cancel_push::CancelPush;
pub(crate) use control::{Control, StreamType, WriteControl, be_control, be_stream_type};
pub(crate) use data::Data;
pub use goaway::Goaway;
pub(crate) use headers::Headers;
pub(crate) use max_push_id::MaxPushId;
pub(crate) use push_promise::PushPromise;
pub(crate) use settings::{
    SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_MAX_FIELD_SECTION_SIZE,
    SETTINGS_QPACK_BLOCKED_STREAMS, SETTINGS_QPACK_MAX_TABLE_CAPACITY, Settings,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameType {
    Data,
    Headers,
    Settings,
    Goaway,
    CancelPush,
    PushPromise,
    MaxPushId,
    Unknown(VarInt),
}

impl TryFrom<u64> for FrameType {
    type Error = Error;

    /// Unknown extension types are skippable; HTTP/2-only types are forbidden
    /// (RFC 9114 sections 7.2.8 and 9).
    fn try_from(value: u64) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Data),
            0x01 => Ok(Self::Headers),
            0x03 => Ok(Self::CancelPush),
            0x04 => Ok(Self::Settings),
            0x05 => Ok(Self::PushPromise),
            0x07 => Ok(Self::Goaway),
            0x0d => Ok(Self::MaxPushId),
            0x02 | 0x06 | 0x08 | 0x09 => Err(ErrorCode::FrameUnexpected
                .reason("HTTP/2-reserved frame type is forbidden in HTTP/3")),
            _ => VarInt::try_from(value).map(Self::Unknown).map_err(|error| {
                ErrorCode::FrameError.reason(format!(
                    "frame type exceeds the QUIC variable-integer range: {error}"
                ))
            }),
        }
    }
}

/// Common HTTP/3 envelope; only the payload representation varies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Frame<P: GetFrameType + EncodeSize> {
    pub(crate) length: VarInt,
    pub(crate) payload: P,
}

impl<P: GetFrameType + EncodeSize> Frame<P> {
    pub(crate) fn new(payload: P) -> Result<Self> {
        let length = VarInt::try_from(payload.encoding_size()).map_err(|error| {
            ErrorCode::FrameError.reason(format!(
                "encoded frame length exceeds the QUIC variable-integer range: {error}"
            ))
        })?;
        Ok(Self { length, payload })
    }
}

impl<P: GetFrameType + EncodeSize> GetFrameType for Frame<P> {
    fn frame_type(&self) -> FrameType {
        self.payload.frame_type()
    }
}

/// Payload variants returned by the unified stream decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum H3Frame {
    Data(Frame<Data>),
    Headers(Frame<Headers>),
    CancelPush(Frame<CancelPush>),
    Settings(Frame<Settings>),
    PushPromise(Frame<PushPromise>),
    Goaway(Frame<Goaway>),
    MaxPushId(Frame<MaxPushId>),
    /// Only the envelope is decoded; the caller must discard the payload.
    Unknown {
        ty: VarInt,
        length: VarInt,
    },
}

impl GetFrameType for H3Frame {
    fn frame_type(&self) -> FrameType {
        match self {
            Self::Data(payload) => payload.frame_type(),
            Self::Headers(payload) => payload.frame_type(),
            Self::CancelPush(payload) => payload.frame_type(),
            Self::Settings(payload) => payload.frame_type(),
            Self::PushPromise(payload) => payload.frame_type(),
            Self::Goaway(payload) => payload.frame_type(),
            Self::MaxPushId(payload) => payload.frame_type(),
            Self::Unknown { ty, .. } => FrameType::Unknown(*ty),
        }
    }
}

/// Read Type, Length, and one payload. DATA and unknown payload bytes remain in
/// the reader and must be consumed before calling again. HEADERS/PUSH_PROMISE
/// retain encoded QPACK bytes; after validating placement, pass the field section
/// to Qpack::decode to resolve its fields.
/// EOF (including a partial frame) is an error.
/// Cancellation can consume a prefix; keep polling the same future.
/// Return None at a frame boundary; a truncated type is a framing error.
pub(crate) async fn be_frame_type<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
) -> io::Result<Option<FrameType>> {
    let mut first = [0];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let ty = be_varint(&mut first.as_slice().chain(reader)).await?;
    ty.ok_or_else(|| ErrorCode::FrameError.reason("frame is missing a complete type"))?
        .into_u64()
        .try_into()
        .map(Some)
        .map_err(io::Error::other)
}

pub(crate) async fn be_frame_length<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
) -> io::Result<VarInt> {
    be_varint(reader).await?.ok_or_else(|| {
        io::Error::other(ErrorCode::FrameError.reason("frame is missing a complete length"))
    })
}

/// Discard exactly `length` bytes without allocating a buffer of that size.
pub(crate) async fn skip_payload<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: u64,
) -> io::Result<()> {
    let mut payload = reader.take(length);
    tokio::io::copy(&mut payload, &mut tokio::io::sink()).await?;
    if payload.limit() != 0 {
        return Err(ErrorCode::FrameError
            .reason("frame payload ended before its declared length")
            .into());
    }
    Ok(())
}

/// Decode a payload after the caller has validated its stream placement.
/// DATA and unknown payloads remain in the reader for the caller to consume.
pub(crate) async fn be_frame_payload<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    ty: FrameType,
    length: VarInt,
) -> io::Result<H3Frame> {
    let frame = match ty {
        FrameType::Data => H3Frame::Data(Frame {
            length,
            payload: Data(usize::try_from(length.into_u64()).map_err(|error| {
                io::Error::other(
                    ErrorCode::FrameError
                        .reason(format!("DATA length does not fit in memory: {error}")),
                )
            })?),
        }),
        FrameType::Headers => H3Frame::Headers(headers::be_headers_frame(reader, length).await?),
        FrameType::CancelPush => {
            H3Frame::CancelPush(Frame::<CancelPush>::be_frame(reader, length).await?)
        }
        FrameType::Settings => H3Frame::Settings(settings::be_setting_frame(reader, length).await?),
        FrameType::PushPromise => {
            H3Frame::PushPromise(push_promise::be_push_promise_frame(reader, length).await?)
        }
        FrameType::Goaway => H3Frame::Goaway(goaway::be_goaway_frame(reader, length).await?),
        FrameType::MaxPushId => {
            H3Frame::MaxPushId(max_push_id::be_max_push_id_frame(reader, length).await?)
        }
        FrameType::Unknown(ty) => H3Frame::Unknown { ty, length },
    };
    Ok(frame)
}

pub(crate) trait GetFrameType {
    fn frame_type(&self) -> FrameType;
}

pub(crate) trait EncodeSize {
    fn encoding_size(&self) -> usize;
}

async fn read_payload<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: u64,
) -> io::Result<Bytes> {
    if length > MAX_BUFFERED_FRAME_PAYLOAD as u64 {
        return Err(ErrorCode::ExcessiveLoad
            .reason("configured resource limit exceeded")
            .into());
    }
    let mut payload = vec![0; length as usize];
    reader.read_exact(&mut payload).await.map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::other(
                ErrorCode::FrameError.reason("frame payload ended before its declared length"),
            )
        } else {
            error
        }
    })?;
    Ok(payload.into())
}

/// Serialize a frame into a byte buffer. Payload validation precedes writes.
pub(crate) trait Write<F>: BufMut {
    fn put_frame(&mut self, frame: &F);
}

/// Write only the Type varint, without Length or payload.
pub(crate) trait WriteFrameType: BufMut {
    fn put_frame_type(&mut self, frame: &FrameType);
}

impl<B: BufMut> WriteFrameType for B {
    fn put_frame_type(&mut self, frame: &FrameType) {
        self.put_varint(&frame.frame_type().into());
    }
}

impl GetFrameType for FrameType {
    fn frame_type(&self) -> FrameType {
        *self
    }
}

impl From<FrameType> for VarInt {
    fn from(value: FrameType) -> Self {
        match value {
            FrameType::Data => VarInt::from_u32(0x00),
            FrameType::Headers => VarInt::from_u32(0x01),
            FrameType::CancelPush => VarInt::from_u32(0x03),
            FrameType::Settings => VarInt::from_u32(0x04),
            FrameType::PushPromise => VarInt::from_u32(0x05),
            FrameType::Goaway => VarInt::from_u32(0x07),
            FrameType::MaxPushId => VarInt::from_u32(0x0d),
            FrameType::Unknown(ty) => ty,
        }
    }
}

impl<B: BufMut> Write<H3Frame> for B {
    fn put_frame(&mut self, frame: &H3Frame) {
        match frame {
            H3Frame::Data(frame) => self.put_frame(frame),
            H3Frame::Headers(frame) => self.put_frame(frame),
            H3Frame::CancelPush(frame) => self.put_frame(frame),
            H3Frame::Settings(frame) => self.put_frame(frame),
            H3Frame::PushPromise(frame) => self.put_frame(frame),
            H3Frame::Goaway(frame) => self.put_frame(frame),
            H3Frame::MaxPushId(frame) => self.put_frame(frame),
            H3Frame::Unknown { .. } => unreachable!("unknown frames cannot be serialized"),
        }
    }
}
