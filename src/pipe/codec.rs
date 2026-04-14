//! Minimal framing codec for per-stream Unix socketpair IPC.
//!
//! Each QUIC stream is carried over an independent `SOCK_STREAM` socketpair.
//! The codec multiplexes data and control signals on the same byte stream using
//! a simple tag-length-value encoding based on QUIC variable-length integers.
//!
//! # Frame types
//!
//! ```text
//! PULL        = type(varint 0x00)
//! DATA        = type(varint 0x01) + length(varint) + payload
//! STOP        = type(varint 0x02) + code(varint)
//! CANCEL      = type(varint 0x03) + code(varint)
//! CONN_CLOSED = type(varint 0x04)
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::varint::VarInt;

/// Frame type tags.
const TAG_PULL: u8 = 0x00;
const TAG_DATA: u8 = 0x01;
const TAG_STOP: u8 = 0x02;
const TAG_CANCEL: u8 = 0x03;
const TAG_CONN_CLOSED: u8 = 0x04;

/// Frames exchanged over a per-stream socketpair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Flow-control signal — reader grants the writer permission to send one
    /// DATA frame.
    Pull,
    /// Stream data payload.
    Data(Bytes),
    /// STOP_SENDING — reader asks the remote writer to stop (carries error code).
    Stop(VarInt),
    /// RESET_STREAM — writer cancels the stream (carries error code).
    Cancel(VarInt),
    /// Connection-level closure notification.
    ConnClosed,
}

/// Codec error.
#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum CodecError {
    #[snafu(transparent)]
    Io { source: std::io::Error },
    #[snafu(display("unknown frame tag: 0x{tag:02x}"))]
    UnknownTag { tag: u8 },
    #[snafu(display("varint overflow"))]
    VarIntOverflow,
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

/// Minimal framing codec for the per-stream pipe protocol.
#[derive(Debug, Default)]
pub struct PipeCodec {
    /// Partially decoded frame state: once we know the tag and payload length
    /// we store them here so we don't re-parse on the next `decode` call.
    state: DecodeState,
}

#[derive(Debug, Default)]
enum DecodeState {
    #[default]
    Tag,
    /// We have the tag and the payload length, waiting for payload bytes.
    Data { len: usize },
    /// Control frame (STOP/CANCEL): tag decoded, need varint code.
    Control { tag: u8 },
}

impl PipeCodec {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Decoder for PipeCodec {
    type Item = Frame;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, CodecError> {
        loop {
            match self.state {
                DecodeState::Tag => {
                    if src.is_empty() {
                        return Ok(None);
                    }
                    // Peek at the tag byte (first byte is always a 1-byte varint for 0x00..0x04).
                    let tag = src[0];
                    match tag {
                        TAG_DATA => {
                            // Need tag + varint length. Try to decode the length varint
                            // starting right after the tag byte.
                            if src.len() < 2 {
                                return Ok(None);
                            }
                            let after_tag = &src[1..];
                            let Some((len_vi, vi_size)) = try_decode_varint(after_tag) else {
                                // Not enough bytes for the varint yet.
                                return Ok(None);
                            };
                            let len = len_vi.into_inner() as usize;
                            let header_size = 1 + vi_size;
                            let total = header_size + len;
                            if src.len() < total {
                                // Consume the header so DecodeState::Data only waits for payload.
                                src.advance(header_size);
                                src.reserve(len.saturating_sub(src.len()));
                                self.state = DecodeState::Data { len };
                                return Ok(None);
                            }
                            src.advance(header_size);
                            let data = src.split_to(len).freeze();
                            // state stays Tag for next frame
                            return Ok(Some(Frame::Data(data)));
                        }
                        TAG_PULL => {
                            src.advance(1);
                            return Ok(Some(Frame::Pull));
                        }
                        TAG_STOP | TAG_CANCEL => {
                            self.state = DecodeState::Control { tag };
                            src.advance(1); // consume the tag byte
                        }
                        TAG_CONN_CLOSED => {
                            src.advance(1);
                            return Ok(Some(Frame::ConnClosed));
                        }
                        _ => return Err(CodecError::UnknownTag { tag }),
                    }
                }
                DecodeState::Data { len } => {
                    // We already consumed the header; just wait for the payload.
                    if src.len() < len {
                        src.reserve(len - src.len());
                        return Ok(None);
                    }
                    let data = src.split_to(len).freeze();
                    self.state = DecodeState::Tag;
                    return Ok(Some(Frame::Data(data)));
                }
                DecodeState::Control { tag } => {
                    let Some((code, vi_size)) = try_decode_varint(src) else {
                        return Ok(None);
                    };
                    src.advance(vi_size);
                    self.state = DecodeState::Tag;
                    return Ok(Some(match tag {
                        TAG_STOP => Frame::Stop(code),
                        TAG_CANCEL => Frame::Cancel(code),
                        _ => unreachable!(),
                    }));
                }
            }
        }
    }
}

impl Encoder<Frame> for PipeCodec {
    type Error = CodecError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), CodecError> {
        match item {
            Frame::Pull => {
                dst.reserve(1);
                dst.put_u8(TAG_PULL);
            }
            Frame::Data(data) => {
                let len = VarInt::try_from(data.len()).map_err(|_| CodecError::VarIntOverflow)?;
                dst.reserve(1 + len.encoding_size() + data.len());
                dst.put_u8(TAG_DATA);
                encode_varint(dst, len);
                dst.extend_from_slice(&data);
            }
            Frame::Stop(code) => {
                dst.reserve(1 + code.encoding_size());
                dst.put_u8(TAG_STOP);
                encode_varint(dst, code);
            }
            Frame::Cancel(code) => {
                dst.reserve(1 + code.encoding_size());
                dst.put_u8(TAG_CANCEL);
                encode_varint(dst, code);
            }
            Frame::ConnClosed => {
                dst.reserve(1);
                dst.put_u8(TAG_CONN_CLOSED);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(frame: Frame) {
        let mut codec = PipeCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let mut decoder = PipeCodec::new();
        let decoded = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn data_frame_round_trip() {
        round_trip(Frame::Data(Bytes::from_static(b"hello world")));
    }

    #[test]
    fn empty_data_frame_round_trip() {
        round_trip(Frame::Data(Bytes::new()));
    }

    #[test]
    fn pull_frame_round_trip() {
        round_trip(Frame::Pull);
    }

    #[test]
    fn stop_frame_round_trip() {
        round_trip(Frame::Stop(VarInt::from_u32(0x42)));
    }

    #[test]
    fn cancel_frame_round_trip() {
        round_trip(Frame::Cancel(VarInt::from_u32(0)));
    }

    #[test]
    fn conn_closed_round_trip() {
        round_trip(Frame::ConnClosed);
    }

    #[test]
    fn large_data_frame() {
        let data = Bytes::from(vec![0xab; 70_000]);
        round_trip(Frame::Data(data));
    }

    #[test]
    fn multiple_frames_in_sequence() {
        let mut codec = PipeCodec::new();
        let mut buf = BytesMut::new();

        let frames = vec![
            Frame::Pull,
            Frame::Data(Bytes::from_static(b"first")),
            Frame::Stop(VarInt::from_u32(1)),
            Frame::Data(Bytes::from_static(b"second")),
            Frame::Cancel(VarInt::from_u32(2)),
            Frame::ConnClosed,
        ];

        for f in &frames {
            codec.encode(f.clone(), &mut buf).unwrap();
        }

        let mut decoder = PipeCodec::new();
        for expected in &frames {
            let decoded = decoder.decode(&mut buf).unwrap().unwrap();
            assert_eq!(&decoded, expected);
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn incremental_decode() {
        let mut codec = PipeCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(Frame::Data(Bytes::from_static(b"abc")), &mut buf)
            .unwrap();

        let full = buf.split();

        // Feed one byte at a time.
        let mut decoder = PipeCodec::new();
        let mut partial = BytesMut::new();
        for i in 0..full.len() - 1 {
            partial.extend_from_slice(&full[i..i + 1]);
            assert!(decoder.decode(&mut partial).unwrap().is_none());
        }
        partial.extend_from_slice(&full[full.len() - 1..]);
        let decoded = decoder.decode(&mut partial).unwrap().unwrap();
        assert_eq!(decoded, Frame::Data(Bytes::from_static(b"abc")));
    }

    #[test]
    fn unknown_tag_error() {
        let mut decoder = PipeCodec::new();
        let mut buf = BytesMut::from(&[0xff][..]);
        assert!(decoder.decode(&mut buf).is_err());
    }
}
