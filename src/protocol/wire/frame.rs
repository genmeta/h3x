//! HTTP/3 frames (RFC 9114 section 7.2). Stream placement is checked by the caller.
use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt};

use super::frame_error;
use crate::{Code, Error};

mod cancel_push;
mod data;
mod goaway;
mod headers;
mod max_push_id;
mod push_promise;
mod settings;

pub(crate) use cancel_push::CancelPushFrame;
pub(crate) use data::DataFrame;
pub(crate) use goaway::GoawayFrame;
pub(crate) use headers::HeadersFrame;
pub(crate) use max_push_id::MaxPushIdFrame;
pub(crate) use push_promise::PushPromiseFrame;
pub(crate) use settings::SettingsFrame;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameType {
    Data,
    Headers,
    Settings,
    Goaway,
    CancelPush,
    PushPromise,
    MaxPushId,
    ForbiddenHttp2(u64),
    Unknown(u64),
}

impl From<u64> for FrameType {
    fn from(value: u64) -> Self {
        match value {
            0x00 => Self::Data,
            0x01 => Self::Headers,
            0x04 => Self::Settings,
            0x07 => Self::Goaway,
            0x03 => Self::CancelPush,
            0x05 => Self::PushPromise,
            0x0d => Self::MaxPushId,
            0x02 | 0x06 | 0x08 | 0x09 => Self::ForbiddenHttp2(value),
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameHeader {
    pub(crate) frame_type: FrameType,
    pub(crate) length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Data(DataFrame),
    Headers(HeadersFrame),
    CancelPush(CancelPushFrame),
    Settings(SettingsFrame),
    PushPromise(PushPromiseFrame),
    Goaway(GoawayFrame),
    MaxPushId(MaxPushIdFrame),
    Unknown { ty: VarInt, payload: Bytes },
}

impl From<FrameType> for u64 {
    fn from(value: FrameType) -> Self {
        match value {
            FrameType::Data => 0x00,
            FrameType::Headers => 0x01,
            FrameType::CancelPush => 0x03,
            FrameType::Settings => 0x04,
            FrameType::PushPromise => 0x05,
            FrameType::Goaway => 0x07,
            FrameType::MaxPushId => 0x0d,
            FrameType::ForbiddenHttp2(ty) | FrameType::Unknown(ty) => ty,
        }
    }
}

pub(crate) type ParseResult<'a, T> = nom::IResult<&'a [u8], T, Error>;

pub(crate) fn be_frame_header(input: &[u8]) -> ParseResult<'_, FrameHeader> {
    let (input, ty) = qbase::varint::be_varint(input)
        .map_err(|error| error.map(|_| frame_error("invalid frame type")))?;
    let (input, length) = qbase::varint::be_varint(input)
        .map_err(|error| error.map(|_| frame_error("invalid frame length")))?;
    Ok((
        input,
        FrameHeader {
            frame_type: ty.into_u64().into(),
            length: length.into_u64(),
        },
    ))
}

/// A bounded complete payload. Missing bytes leave the input untouched.
pub(crate) fn be_payload(input: &Bytes, length: u64) -> ParseResult<'_, Bytes> {
    let len = usize::try_from(length)
        .ok()
        .filter(|len| *len <= super::MAX_BUFFERED_FRAME_PAYLOAD)
        .ok_or_else(|| {
            nom::Err::Failure(super::excessive_load(
                "buffered frame payload exceeds implementation limit",
            ))
        })?;
    if input.len() < len {
        return Err(nom::Err::Incomplete(nom::Needed::new(len - input.len())));
    }
    Ok((&input[len..], input.slice(..len)))
}

/// Take only available bytes, up to max. The caller restricts input to the frame boundary.
pub(crate) fn be_payload_chunk(input: &Bytes, max: usize) -> ParseResult<'_, Bytes> {
    assert!(max > 0);
    if input.is_empty() {
        return Err(nom::Err::Incomplete(nom::Needed::new(1)));
    }
    let len = input.len().min(max);
    Ok((&input[len..], input.slice(..len)))
}

/// Parse fields after an already consumed envelope.
pub(crate) fn be_frame(input: &Bytes, header: FrameHeader) -> ParseResult<'_, Frame> {
    if header.frame_type == FrameType::Data {
        return data::be_data_frame(input, header.length)
            .map(|(rest, frame)| (rest, Frame::Data(frame)));
    }
    if matches!(header.frame_type, FrameType::ForbiddenHttp2(_)) {
        return Err(nom::Err::Failure(Error::connection_protocol(
            Code::H3_FRAME_UNEXPECTED,
            "HTTP/2 frame type is forbidden in HTTP/3",
        )));
    }
    if matches!(
        header.frame_type,
        FrameType::Goaway | FrameType::CancelPush | FrameType::MaxPushId
    ) && header.length > VarInt::MAX_SIZE as u64
    {
        return Err(nom::Err::Failure(frame_error(
            "frame payload is longer than one QUIC varint",
        )));
    }
    let (remaining, payload) = be_payload(input, header.length)?;
    let parsed = match header.frame_type {
        FrameType::Headers => {
            headers::be_headers_frame(&payload).map(|(rest, frame)| (rest, Frame::Headers(frame)))
        }
        FrameType::CancelPush => cancel_push::be_cancel_push_frame(&payload)
            .map(|(rest, frame)| (rest, Frame::CancelPush(frame))),
        FrameType::Settings => settings::be_settings_frame(&payload)
            .map(|(rest, frame)| (rest, Frame::Settings(frame))),
        FrameType::PushPromise => push_promise::be_push_promise_frame(&payload)
            .map(|(rest, frame)| (rest, Frame::PushPromise(frame))),
        FrameType::Goaway => {
            goaway::be_goaway_frame(&payload).map(|(rest, frame)| (rest, Frame::Goaway(frame)))
        }
        FrameType::MaxPushId => max_push_id::be_max_push_id_frame(&payload)
            .map(|(rest, frame)| (rest, Frame::MaxPushId(frame))),
        FrameType::Unknown(ty) => Ok((
            &[][..],
            Frame::Unknown {
                ty: VarInt::try_from(ty)
                    .map_err(|_| nom::Err::Failure(frame_error("invalid frame type")))?,
                payload: payload.clone(),
            },
        )),
        FrameType::Data | FrameType::ForbiddenHttp2(_) => unreachable!(),
    };
    let (rest, frame) = parsed.map_err(|error| match error {
        nom::Err::Incomplete(_) => nom::Err::Failure(frame_error("incomplete frame payload value")),
        error => error,
    })?;
    if !rest.is_empty() {
        return Err(nom::Err::Failure(frame_error(
            "trailing bytes after frame payload value",
        )));
    }
    Ok((remaining, frame))
}

/// BufMut extension matching dquic's put_frame pattern. Validation precedes writes.
pub(crate) trait WriteFrame<F>: BufMut {
    fn put_frame(&mut self, frame: &F) -> Result<(), Error>;
}

impl<B: BufMut> WriteFrame<FrameHeader> for B {
    fn put_frame(&mut self, frame: &FrameHeader) -> Result<(), Error> {
        let ty = VarInt::try_from(u64::from(frame.frame_type))
            .map_err(|_| frame_error("invalid frame type"))?;
        let len =
            VarInt::try_from(frame.length).map_err(|_| frame_error("invalid frame length"))?;
        self.put_varint(&ty);
        self.put_varint(&len);
        Ok(())
    }
}

impl<B: BufMut> WriteFrame<Frame> for B {
    fn put_frame(&mut self, frame: &Frame) -> Result<(), Error> {
        match frame {
            Frame::Data(frame) => self.put_frame(frame),
            Frame::Headers(frame) => self.put_frame(frame),
            Frame::CancelPush(frame) => self.put_frame(frame),
            Frame::Settings(frame) => self.put_frame(frame),
            Frame::PushPromise(frame) => self.put_frame(frame),
            Frame::Goaway(frame) => self.put_frame(frame),
            Frame::MaxPushId(frame) => self.put_frame(frame),
            Frame::Unknown { ty, payload } => {
                if !matches!(FrameType::from(ty.into_u64()), FrameType::Unknown(_)) {
                    return Err(frame_error("known frame type encoded as unknown"));
                }
                self.put_frame(&FrameHeader {
                    frame_type: FrameType::Unknown(ty.into_u64()),
                    length: payload.len() as u64,
                })?;
                self.put_slice(payload);
                Ok(())
            }
        }
    }
}

#[cfg(any(test, feature = "fuzzing"))]
mod tests;
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) use tests::be_complete_frame;
