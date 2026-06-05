//! Direction-aware stream frame codecs for per-stream Unix socketpair IPC.
//!
//! Each QUIC stream is carried over an independent `SOCK_STREAM` socketpair.
//! The wire format is a simple QUIC-varint tag followed by optional varint
//! length/code fields and payload bytes. The frame vocabulary is shared with
//! `rpc::stream::frame`; this module only adapts that vocabulary to
//! `tokio_util::codec` for IPC pipes.

use std::borrow::Cow;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use snafu::ResultExt as _;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    quic,
    rpc::stream::frame::{self, ReadCommand, ReadEvent, WriteCommand, WriteEvent},
    varint::{self, VarInt},
};

const TAG_PULL: u8 = frame::TAG_PULL as u8;
const TAG_PUSH: u8 = frame::TAG_PUSH as u8;
const TAG_FLUSH: u8 = frame::TAG_FLUSH as u8;
const TAG_FLUSH_ACK: u8 = frame::TAG_FLUSH_ACK as u8;
const TAG_EOS: u8 = frame::TAG_EOS as u8;
const TAG_EOS_ACK: u8 = frame::TAG_EOS_ACK as u8;
const TAG_STOP: u8 = frame::TAG_STOP as u8;
const TAG_STOP_ACK: u8 = frame::TAG_STOP_ACK as u8;
const TAG_RESET: u8 = frame::TAG_RESET as u8;
const TAG_RESET_ACK: u8 = frame::TAG_RESET_ACK as u8;
const TAG_ERR_RESET: u8 = frame::TAG_ERR_RESET as u8;
const TAG_ERR_CONN: u8 = frame::TAG_ERR_CONN as u8;

const IPC_CODEC_ERROR_KIND: VarInt = VarInt::from_u32(0x0b);
const IPC_CODEC_ERROR_FRAME_TYPE: VarInt = VarInt::from_u32(0x00);

/// Maximum encoded header bytes for a PUSH frame: tag + varint length.
pub(super) const PUSH_HEADER_MAX_LEN: usize = 1 + VarInt::MAX_SIZE;

/// Codec error.
#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub(crate) enum CodecError {
    #[snafu(transparent)]
    Io { source: std::io::Error },
    #[snafu(display("unknown frame tag 0x{tag:02x}"))]
    UnknownTag { tag: u8 },
    #[snafu(display("frame tag 0x{tag:02x} is invalid for {direction}"))]
    InvalidDirection { tag: u8, direction: &'static str },
    #[snafu(display("failed to encode push payload length"))]
    EncodePushLength { source: varint::err::Overflow },
}

impl From<CodecError> for quic::ConnectionError {
    fn from(error: CodecError) -> Self {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: IPC_CODEC_ERROR_KIND,
                frame_type: IPC_CODEC_ERROR_FRAME_TYPE,
                // Lossy: QUIC transport error reason is a protocol string field
                // for local IPC codec failures.
                reason: Cow::Owned(error.to_string()),
            },
        }
    }
}

/// Try to decode one QUIC-style varint from `buf` without advancing it.
/// Returns `None` if not enough bytes are available yet.
fn try_decode_varint(buf: &[u8]) -> Option<(VarInt, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut raw = [0u8; 8];
    raw[..len].copy_from_slice(&buf[..len]);
    raw[0] &= 0x3f; // mask out the two high bits
    let value = u64::from_be_bytes(raw) >> (8 * (8 - len));
    // SAFETY: value < 2^62 because we masked two bits of the first byte.
    Some((unsafe { VarInt::from_u64_unchecked(value) }, len))
}

/// Encode a varint into `buf`.
fn encode_varint(buf: &mut BytesMut, v: VarInt) {
    let x = v.into_inner();
    if x < (1 << 6) {
        buf.put_u8(x as u8);
    } else if x < (1 << 14) {
        buf.put_u16((0b01 << 14) | x as u16);
    } else if x < (1 << 30) {
        buf.put_u32((0b10 << 30) | x as u32);
    } else {
        buf.put_u64((0b11 << 62) | x);
    }
}

pub(super) fn encode_varint_to_slice(dst: &mut [u8], v: VarInt) -> usize {
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

/// Encode PUSH frame header bytes (`TAG_PUSH + varint(payload_len)`).
pub(super) fn encode_push_header(
    payload_len: usize,
) -> Result<([u8; PUSH_HEADER_MAX_LEN], usize), CodecError> {
    let len = VarInt::try_from(payload_len).context(codec_error::EncodePushLengthSnafu)?;
    let mut header = [0u8; PUSH_HEADER_MAX_LEN];
    header[0] = TAG_PUSH;
    let varint_size = encode_varint_to_slice(&mut header[1..], len);
    Ok((header, 1 + varint_size))
}

#[derive(Debug, Default)]
struct WireCodec {
    state: DecodeState,
}

#[derive(Debug, Default)]
enum DecodeState {
    #[default]
    Tag,
    Push {
        len: usize,
    },
    Control {
        tag: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WireFrame {
    Pull,
    Push { data: Bytes },
    Flush,
    FlushAck,
    Eos,
    EosAck,
    Stop { code: VarInt },
    StopAck { code: VarInt },
    Reset { code: VarInt },
    ResetAck { code: VarInt },
    ErrReset { code: VarInt },
    ErrConn,
}

impl WireFrame {
    const fn tag(&self) -> u8 {
        match self {
            Self::Pull => TAG_PULL,
            Self::Push { .. } => TAG_PUSH,
            Self::Flush => TAG_FLUSH,
            Self::FlushAck => TAG_FLUSH_ACK,
            Self::Eos => TAG_EOS,
            Self::EosAck => TAG_EOS_ACK,
            Self::Stop { .. } => TAG_STOP,
            Self::StopAck { .. } => TAG_STOP_ACK,
            Self::Reset { .. } => TAG_RESET,
            Self::ResetAck { .. } => TAG_RESET_ACK,
            Self::ErrReset { .. } => TAG_ERR_RESET,
            Self::ErrConn => TAG_ERR_CONN,
        }
    }
}

impl WireCodec {
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<WireFrame>, CodecError> {
        loop {
            match self.state {
                DecodeState::Tag => {
                    if src.is_empty() {
                        return Ok(None);
                    }
                    let tag = src[0];
                    match tag {
                        TAG_PUSH => {
                            if src.len() < 2 {
                                return Ok(None);
                            }
                            let after_tag = &src[1..];
                            let Some((len_vi, vi_size)) = try_decode_varint(after_tag) else {
                                return Ok(None);
                            };
                            let len = len_vi.into_inner() as usize;
                            let header_size = 1 + vi_size;
                            let total = header_size + len;
                            if src.len() < total {
                                src.advance(header_size);
                                src.reserve(len.saturating_sub(src.len()));
                                self.state = DecodeState::Push { len };
                                return Ok(None);
                            }
                            src.advance(header_size);
                            let data = src.split_to(len).freeze();
                            return Ok(Some(WireFrame::Push { data }));
                        }
                        TAG_STOP | TAG_STOP_ACK | TAG_RESET | TAG_RESET_ACK | TAG_ERR_RESET => {
                            self.state = DecodeState::Control { tag };
                            src.advance(1);
                        }
                        TAG_PULL => {
                            src.advance(1);
                            return Ok(Some(WireFrame::Pull));
                        }
                        TAG_FLUSH => {
                            src.advance(1);
                            return Ok(Some(WireFrame::Flush));
                        }
                        TAG_FLUSH_ACK => {
                            src.advance(1);
                            return Ok(Some(WireFrame::FlushAck));
                        }
                        TAG_EOS => {
                            src.advance(1);
                            return Ok(Some(WireFrame::Eos));
                        }
                        TAG_EOS_ACK => {
                            src.advance(1);
                            return Ok(Some(WireFrame::EosAck));
                        }
                        TAG_ERR_CONN => {
                            src.advance(1);
                            return Ok(Some(WireFrame::ErrConn));
                        }
                        _ => return Err(CodecError::UnknownTag { tag }),
                    }
                }
                DecodeState::Push { len } => {
                    if src.len() < len {
                        src.reserve(len - src.len());
                        return Ok(None);
                    }
                    let data = src.split_to(len).freeze();
                    self.state = DecodeState::Tag;
                    return Ok(Some(WireFrame::Push { data }));
                }
                DecodeState::Control { tag } => {
                    let Some((code, vi_size)) = try_decode_varint(src) else {
                        return Ok(None);
                    };
                    src.advance(vi_size);
                    self.state = DecodeState::Tag;
                    return Ok(Some(match tag {
                        TAG_STOP => WireFrame::Stop { code },
                        TAG_STOP_ACK => WireFrame::StopAck { code },
                        TAG_RESET => WireFrame::Reset { code },
                        TAG_RESET_ACK => WireFrame::ResetAck { code },
                        TAG_ERR_RESET => WireFrame::ErrReset { code },
                        _ => unreachable!("control state only records control tags"),
                    }));
                }
            }
        }
    }

    fn encode(&mut self, item: WireFrame, dst: &mut BytesMut) -> Result<(), CodecError> {
        match item {
            WireFrame::Pull => dst.put_u8(TAG_PULL),
            WireFrame::Push { data } => {
                let (header, header_len) = encode_push_header(data.len())?;
                dst.reserve(header_len + data.len());
                dst.extend_from_slice(&header[..header_len]);
                dst.extend_from_slice(&data);
            }
            WireFrame::Flush => dst.put_u8(TAG_FLUSH),
            WireFrame::FlushAck => dst.put_u8(TAG_FLUSH_ACK),
            WireFrame::Eos => dst.put_u8(TAG_EOS),
            WireFrame::EosAck => dst.put_u8(TAG_EOS_ACK),
            WireFrame::Stop { code } => encode_control(dst, TAG_STOP, code),
            WireFrame::StopAck { code } => encode_control(dst, TAG_STOP_ACK, code),
            WireFrame::Reset { code } => encode_control(dst, TAG_RESET, code),
            WireFrame::ResetAck { code } => encode_control(dst, TAG_RESET_ACK, code),
            WireFrame::ErrReset { code } => encode_control(dst, TAG_ERR_RESET, code),
            WireFrame::ErrConn => dst.put_u8(TAG_ERR_CONN),
        }
        Ok(())
    }
}

fn encode_control(dst: &mut BytesMut, tag: u8, code: VarInt) {
    dst.reserve(1 + code.encoding_size());
    dst.put_u8(tag);
    encode_varint(dst, code);
}

fn wrong_direction(tag: u8, direction: &'static str) -> CodecError {
    CodecError::InvalidDirection { tag, direction }
}

/// Codec for worker-to-hypervisor read commands.
#[derive(Debug, Default)]
pub(super) struct ReadCommandCodec {
    wire: WireCodec,
}

impl ReadCommandCodec {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

impl Decoder for ReadCommandCodec {
    type Item = ReadCommand;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(frame) = self.wire.decode(src)? else {
            return Ok(None);
        };
        let tag = frame.tag();
        match frame {
            WireFrame::Pull => Ok(Some(ReadCommand::Pull)),
            WireFrame::Stop { code } => Ok(Some(ReadCommand::Stop { code })),
            _ => Err(wrong_direction(tag, "read command")),
        }
    }
}

impl Encoder<ReadCommand> for ReadCommandCodec {
    type Error = CodecError;

    fn encode(&mut self, item: ReadCommand, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.wire.encode(
            match item {
                ReadCommand::Pull => WireFrame::Pull,
                ReadCommand::Stop { code } => WireFrame::Stop { code },
            },
            dst,
        )
    }
}

/// Codec for hypervisor-to-worker read events.
#[derive(Debug, Default)]
pub(super) struct ReadEventCodec {
    wire: WireCodec,
}

impl ReadEventCodec {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

impl Decoder for ReadEventCodec {
    type Item = ReadEvent;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(frame) = self.wire.decode(src)? else {
            return Ok(None);
        };
        let tag = frame.tag();
        match frame {
            WireFrame::Push { data } => Ok(Some(ReadEvent::Push { data })),
            WireFrame::Eos => Ok(Some(ReadEvent::Eos)),
            WireFrame::StopAck { code } => Ok(Some(ReadEvent::StopAck { code })),
            WireFrame::ErrReset { code } => Ok(Some(ReadEvent::ErrReset { code })),
            WireFrame::ErrConn => Ok(Some(ReadEvent::ErrConn)),
            _ => Err(wrong_direction(tag, "read event")),
        }
    }
}

impl Encoder<ReadEvent> for ReadEventCodec {
    type Error = CodecError;

    fn encode(&mut self, item: ReadEvent, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.wire.encode(
            match item {
                ReadEvent::Push { data } => WireFrame::Push { data },
                ReadEvent::Eos => WireFrame::Eos,
                ReadEvent::StopAck { code } => WireFrame::StopAck { code },
                ReadEvent::ErrReset { code } => WireFrame::ErrReset { code },
                ReadEvent::ErrConn => WireFrame::ErrConn,
            },
            dst,
        )
    }
}

/// Codec for worker-to-hypervisor write commands.
#[derive(Debug, Default)]
pub(super) struct WriteCommandCodec {
    wire: WireCodec,
}

impl WriteCommandCodec {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

impl Decoder for WriteCommandCodec {
    type Item = WriteCommand;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(frame) = self.wire.decode(src)? else {
            return Ok(None);
        };
        let tag = frame.tag();
        match frame {
            WireFrame::Push { data } => Ok(Some(WriteCommand::Push { data })),
            WireFrame::Flush => Ok(Some(WriteCommand::Flush)),
            WireFrame::Eos => Ok(Some(WriteCommand::Eos)),
            WireFrame::Reset { code } => Ok(Some(WriteCommand::Reset { code })),
            _ => Err(wrong_direction(tag, "write command")),
        }
    }
}

impl Encoder<WriteCommand> for WriteCommandCodec {
    type Error = CodecError;

    fn encode(&mut self, item: WriteCommand, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.wire.encode(
            match item {
                WriteCommand::Push { data } => WireFrame::Push { data },
                WriteCommand::Flush => WireFrame::Flush,
                WriteCommand::Eos => WireFrame::Eos,
                WriteCommand::Reset { code } => WireFrame::Reset { code },
            },
            dst,
        )
    }
}

/// Codec for hypervisor-to-worker write events.
#[derive(Debug, Default)]
pub(super) struct WriteEventCodec {
    wire: WireCodec,
}

impl WriteEventCodec {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

impl Decoder for WriteEventCodec {
    type Item = WriteEvent;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(frame) = self.wire.decode(src)? else {
            return Ok(None);
        };
        let tag = frame.tag();
        match frame {
            WireFrame::Pull => Ok(Some(WriteEvent::Pull)),
            WireFrame::FlushAck => Ok(Some(WriteEvent::FlushAck)),
            WireFrame::EosAck => Ok(Some(WriteEvent::EosAck)),
            WireFrame::ResetAck { code } => Ok(Some(WriteEvent::ResetAck { code })),
            WireFrame::ErrReset { code } => Ok(Some(WriteEvent::ErrReset { code })),
            WireFrame::ErrConn => Ok(Some(WriteEvent::ErrConn)),
            _ => Err(wrong_direction(tag, "write event")),
        }
    }
}

impl Encoder<WriteEvent> for WriteEventCodec {
    type Error = CodecError;

    fn encode(&mut self, item: WriteEvent, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.wire.encode(
            match item {
                WriteEvent::Pull => WireFrame::Pull,
                WriteEvent::FlushAck => WireFrame::FlushAck,
                WriteEvent::EosAck => WireFrame::EosAck,
                WriteEvent::ResetAck { code } => WireFrame::ResetAck { code },
                WriteEvent::ErrReset { code } => WireFrame::ErrReset { code },
                WriteEvent::ErrConn => WireFrame::ErrConn,
            },
            dst,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode<C, F>(codec: &mut C, frame: F) -> BytesMut
    where
        C: Encoder<F, Error = CodecError>,
    {
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();
        buf
    }

    fn decode<C>(codec: &mut C, mut buf: BytesMut) -> Result<C::Item, CodecError>
    where
        C: Decoder<Error = CodecError>,
    {
        codec.decode(&mut buf).map(|item| item.unwrap())
    }

    fn assert_direction_error(error: CodecError, tag: u8, direction: &'static str) {
        match error {
            CodecError::InvalidDirection {
                tag: actual,
                direction: actual_direction,
            } => {
                assert_eq!(actual, tag);
                assert_eq!(actual_direction, direction);
            }
            other => panic!("expected invalid direction error, got {other:?}"),
        }
    }

    #[test]
    fn read_command_codec_accepts_pull_and_stop() {
        let code = VarInt::from_u32(0x42);
        let mut encoder = ReadCommandCodec::new();
        let mut decoder = ReadCommandCodec::new();

        let pull = encode(&mut encoder, ReadCommand::Pull);
        assert_eq!(decode(&mut decoder, pull).unwrap(), ReadCommand::Pull);

        let stop = encode(&mut encoder, ReadCommand::Stop { code });
        assert_eq!(
            decode(&mut decoder, stop).unwrap(),
            ReadCommand::Stop { code }
        );
    }

    #[test]
    fn read_event_codec_accepts_read_events() {
        let stop = VarInt::from_u32(0x43);
        let reset = VarInt::from_u32(0x44);
        let frames = [
            ReadEvent::Push {
                data: Bytes::from_static(b"read"),
            },
            ReadEvent::Eos,
            ReadEvent::StopAck { code: stop },
            ReadEvent::ErrReset { code: reset },
            ReadEvent::ErrConn,
        ];
        let mut encoder = ReadEventCodec::new();
        let mut decoder = ReadEventCodec::new();

        for frame in frames {
            let encoded = encode(&mut encoder, frame.clone());
            assert_eq!(decode(&mut decoder, encoded).unwrap(), frame);
        }
    }

    #[test]
    fn write_command_codec_accepts_write_commands() {
        let reset = VarInt::from_u32(0x45);
        let frames = [
            WriteCommand::Push {
                data: Bytes::from_static(b"write"),
            },
            WriteCommand::Flush,
            WriteCommand::Eos,
            WriteCommand::Reset { code: reset },
        ];
        let mut encoder = WriteCommandCodec::new();
        let mut decoder = WriteCommandCodec::new();

        for frame in frames {
            let encoded = encode(&mut encoder, frame.clone());
            assert_eq!(decode(&mut decoder, encoded).unwrap(), frame);
        }
    }

    #[test]
    fn write_event_codec_accepts_write_events() {
        let reset = VarInt::from_u32(0x46);
        let err_reset = VarInt::from_u32(0x47);
        let frames = [
            WriteEvent::Pull,
            WriteEvent::FlushAck,
            WriteEvent::EosAck,
            WriteEvent::ResetAck { code: reset },
            WriteEvent::ErrReset { code: err_reset },
            WriteEvent::ErrConn,
        ];
        let mut encoder = WriteEventCodec::new();
        let mut decoder = WriteEventCodec::new();

        for frame in frames {
            let encoded = encode(&mut encoder, frame.clone());
            assert_eq!(decode(&mut decoder, encoded).unwrap(), frame);
        }
    }

    #[test]
    fn tag_valid_in_wrong_direction_returns_direction_error() {
        let mut read_command_encoder = ReadCommandCodec::new();
        let mut read_command_decoder = ReadCommandCodec::new();
        let wrong = encode(&mut read_command_encoder, ReadCommand::Pull);
        assert_direction_error(
            decode(&mut ReadEventCodec::new(), wrong.clone()).unwrap_err(),
            TAG_PULL,
            "read event",
        );
        assert_direction_error(
            decode(&mut WriteCommandCodec::new(), wrong.clone()).unwrap_err(),
            TAG_PULL,
            "write command",
        );

        let mut write_command_encoder = WriteCommandCodec::new();
        let wrong = encode(&mut write_command_encoder, WriteCommand::Flush);
        assert_direction_error(
            decode(&mut read_command_decoder, wrong.clone()).unwrap_err(),
            TAG_FLUSH,
            "read command",
        );
        assert_direction_error(
            decode(&mut WriteEventCodec::new(), wrong).unwrap_err(),
            TAG_FLUSH,
            "write event",
        );
    }

    #[test]
    fn unknown_tag_error() {
        let mut decoder = ReadCommandCodec::new();
        let mut buf = BytesMut::from(&[0xff][..]);
        match decoder.decode(&mut buf).unwrap_err() {
            CodecError::UnknownTag { tag } => assert_eq!(tag, 0xff),
            other => panic!("expected unknown tag, got {other:?}"),
        }
    }

    #[test]
    fn incremental_push_decode() {
        let payload = Bytes::from_static(b"abc");
        let mut codec = ReadEventCodec::new();
        let mut buf = encode(
            &mut codec,
            ReadEvent::Push {
                data: payload.clone(),
            },
        );
        let full = buf.split();

        let mut decoder = ReadEventCodec::new();
        let mut partial = BytesMut::new();
        for i in 0..full.len() - 1 {
            partial.extend_from_slice(&full[i..i + 1]);
            assert!(decoder.decode(&mut partial).unwrap().is_none());
        }
        partial.extend_from_slice(&full[full.len() - 1..]);
        assert_eq!(
            decoder.decode(&mut partial).unwrap(),
            Some(ReadEvent::Push { data: payload })
        );
    }

    #[test]
    fn data_header_encoding_boundaries() {
        let lens = [0usize, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30];
        for len in lens {
            let (header, header_len) = encode_push_header(len).unwrap();
            assert_eq!(header[0], TAG_PUSH);
            let decoded = try_decode_varint(&header[1..header_len]).unwrap();
            assert_eq!(decoded.0.into_inner(), len as u64);
            assert_eq!(header_len, 1 + decoded.1);
        }
    }

    #[test]
    fn data_header_matches_frame_prefix() {
        let payload = Bytes::from(vec![0x5a; 1024]);
        let mut codec = WriteCommandCodec::new();
        let encoded = encode(
            &mut codec,
            WriteCommand::Push {
                data: payload.clone(),
            },
        );

        let (header, header_len) = encode_push_header(payload.len()).unwrap();
        assert_eq!(&encoded[..header_len], &header[..header_len]);
    }
}
