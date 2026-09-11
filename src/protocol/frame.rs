//! HTTP/3 frames (RFC 9114 section 7.2). Stream placement is checked by the caller.
use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{Error, Result};

mod cancel_push;
mod data;
mod goaway;
mod headers;
mod max_push_id;
mod push_promise;
mod settings;
mod varint;

pub(crate) use varint::be_varint;

pub(crate) const MAX_BUFFERED_FRAME_PAYLOAD: usize = 64 * 1024;
pub(crate) const MAX_DATA_CHUNK: usize = 16 * 1024;

pub(crate) use cancel_push::CancelPush;
pub(crate) use data::Data;
pub(crate) use goaway::Goaway;
pub(crate) use headers::Headers;
pub(crate) use max_push_id::MaxPushId;
pub(crate) use push_promise::PushPromise;
pub(crate) use settings::Settings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameType {
    Data,
    Headers,
    Settings,
    Goaway,
    CancelPush,
    PushPromise,
    MaxPushId,
}

impl TryFrom<u64> for FrameType {
    type Error = Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Data),
            0x01 => Ok(Self::Headers),
            0x03 => Ok(Self::CancelPush),
            0x04 => Ok(Self::Settings),
            0x05 => Ok(Self::PushPromise),
            0x07 => Ok(Self::Goaway),
            0x0d => Ok(Self::MaxPushId),
            _ => Err(Error::H3_FRAME_UNEXPECTED),
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
        let length =
            VarInt::try_from(payload.encoding_size()).map_err(|_| Error::H3_FRAME_ERROR)?;
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
        }
    }
}

impl EncodeSize for H3Frame {
    fn encoding_size(&self) -> usize {
        match self {
            Self::Data(data) => data.payload.encoding_size(),
            Self::Headers(headers) => headers.payload.encoding_size(),
            Self::CancelPush(cancel_push) => cancel_push.payload.encoding_size(),
            Self::Settings(settings) => settings.payload.encoding_size(),
            Self::PushPromise(push_promise) => push_promise.payload.encoding_size(),
            Self::Goaway(goaway) => goaway.payload.encoding_size(),
            Self::MaxPushId(max_push_id) => max_push_id.payload.encoding_size(),
        }
    }
}

/// Read Type, Length, and one payload. DATA bytes remain in the reader and must
/// be consumed before calling again. EOF (including a partial frame) is an error.
/// Cancellation can consume a prefix; keep polling the same future.
pub(crate) async fn be_frame<T: AsyncRead + Unpin + ?Sized>(reader: &mut T) -> Result<H3Frame> {
    let ty: FrameType = be_varint(reader).await?.into_u64().try_into()?;
    let length = be_varint(reader).await?;
    let frame = match ty {
        FrameType::Data => H3Frame::Data(Frame {
            length,
            payload: Data(usize::try_from(length.into_u64()).map_err(|_| Error::H3_FRAME_ERROR)?),
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
    };
    Ok(frame)
}

pub(crate) trait GetFrameType {
    fn frame_type(&self) -> FrameType;
}

pub(crate) trait EncodeSize {
    fn encoding_size(&self) -> usize;
}

fn check_payload_length(length: u64) -> Result<usize> {
    usize::try_from(length)
        .ok()
        .filter(|&length| length <= MAX_BUFFERED_FRAME_PAYLOAD)
        .ok_or(Error::H3_EXCESSIVE_LOAD)
}

async fn read_payload<T: AsyncRead + Unpin + ?Sized>(reader: &mut T, length: u64) -> Result<Bytes> {
    let mut payload = vec![0; check_payload_length(length)?];
    reader.read_exact(&mut payload).await?;
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
        }
    }
}
