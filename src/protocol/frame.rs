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

pub(crate) use varint::{be_varint, be_varint_or_eof};

pub(crate) const MAX_BUFFERED_FRAME_PAYLOAD: usize = 64 * 1024;
pub(crate) const MAX_DATA_CHUNK: usize = 16 * 1024;

pub(crate) use cancel_push::CancelPush;
pub(crate) use data::Data;
pub use goaway::Goaway;
pub(crate) use headers::Headers;
pub(crate) use max_push_id::MaxPushId;
pub(crate) use push_promise::PushPromise;
pub(crate) use settings::{
    SETTINGS_MAX_FIELD_SECTION_SIZE, SETTINGS_QPACK_BLOCKED_STREAMS,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY, Settings,
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
            0x02 | 0x06 | 0x08 | 0x09 => Err(Error::H3_FRAME_UNEXPECTED),
            _ => VarInt::try_from(value)
                .map(Self::Unknown)
                .map_err(|_| Error::H3_FRAME_ERROR),
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
pub(crate) async fn be_frame<T: AsyncRead + Unpin + ?Sized>(reader: &mut T) -> Result<H3Frame> {
    let ty: FrameType = be_varint(reader).await?.into_u64().try_into()?;
    let length = be_varint(reader).await?;
    be_frame_payload(reader, ty, length).await
}

/// Discard exactly `length` bytes without allocating a buffer of that size.
pub(crate) async fn skip_payload<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: u64,
) -> Result<()> {
    let mut payload = reader.take(length);
    tokio::io::copy(&mut payload, &mut tokio::io::sink()).await?;
    if payload.limit() != 0 {
        return Err(Error::H3_FRAME_ERROR);
    }
    Ok(())
}

/// Decode a payload after the caller has validated its stream placement.
/// DATA and unknown payloads remain in the reader for the caller to consume.
pub(crate) async fn be_frame_payload<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    ty: FrameType,
    length: VarInt,
) -> Result<H3Frame> {
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

async fn read_payload<T: AsyncRead + Unpin + ?Sized>(reader: &mut T, length: u64) -> Result<Bytes> {
    if length > MAX_BUFFERED_FRAME_PAYLOAD as u64 {
        return Err(Error::H3_EXCESSIVE_LOAD);
    }
    let mut payload = vec![0; length as usize];
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writing_unknown_frames_panics_without_mutating_the_buffer() {
        let frame = H3Frame::Unknown {
            ty: VarInt::from_u32(0x21),
            length: VarInt::from_u32(3),
        };
        let mut encoded = vec![4, 0];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            encoded.put_frame(&frame);
        }));
        assert!(result.is_err());
        assert_eq!(encoded, [4, 0]);
    }

    #[tokio::test]
    async fn decodes_one_unknown_frame_envelope_at_a_time() {
        // Unknown payload bytes can look like forbidden types or partial headers.
        let mut input = &[0x21, 3, 2, 0, 0x40, 0x22, 0, 0, 2, b'o', b'k'][..];
        assert_eq!(
            be_frame(&mut input).await.unwrap(),
            H3Frame::Unknown {
                ty: VarInt::from_u32(0x21),
                length: VarInt::from_u32(3),
            }
        );
        assert_eq!(&input[..3], &[2, 0, 0x40]);
        skip_payload(&mut input, 3).await.unwrap();
        assert_eq!(
            be_frame(&mut input).await.unwrap(),
            H3Frame::Unknown {
                ty: VarInt::from_u32(0x22),
                length: VarInt::from_u32(0),
            }
        );
        skip_payload(&mut input, 0).await.unwrap();
        assert_eq!(
            be_frame(&mut input).await.unwrap(),
            H3Frame::Data(Frame::new(Data(2)).unwrap())
        );
        assert_eq!(input, b"ok");
    }

    #[tokio::test]
    async fn skips_large_unknown_frames_with_bounded_reads() {
        use std::{
            io,
            pin::Pin,
            task::{Context, Poll},
        };

        use tokio::io::ReadBuf;

        struct BoundedRead<'a>(&'a [u8]);

        impl AsyncRead for BoundedRead<'_> {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                assert!(buf.remaining() <= MAX_DATA_CHUNK);
                Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
            }
        }

        for ty in [0x0au64, 0x21, 0x22, 0x40, 0x4000, 1 << 30, (1 << 62) - 1] {
            for length in [0, MAX_BUFFERED_FRAME_PAYLOAD + 1] {
                let mut encoded = Vec::new();
                encoded.put_varint(&VarInt::try_from(ty).unwrap());
                encoded.put_varint(&VarInt::try_from(length).unwrap());
                encoded.resize(encoded.len() + length, 0xff);
                encoded.extend_from_slice(&[0, 0]);
                let mut reader = BoundedRead(&encoded);
                assert_eq!(
                    be_frame(&mut reader).await.unwrap(),
                    H3Frame::Unknown {
                        ty: VarInt::try_from(ty).unwrap(),
                        length: VarInt::try_from(length).unwrap(),
                    }
                );
                skip_payload(&mut reader, length as u64).await.unwrap();
                assert_eq!(
                    be_frame(&mut reader).await.unwrap(),
                    H3Frame::Data(Frame::new(Data(0)).unwrap())
                );
                assert_eq!(
                    be_frame(&mut reader).await.unwrap_err(),
                    Error::H3_FRAME_ERROR
                );
            }
        }
    }

    #[tokio::test]
    async fn preserves_eof_errors_and_rejects_truncated_frames() {
        for complete in [&[][..], &[0x21, 0][..], &[0x21, 1, 0x40, 0x22, 0][..]] {
            let mut input = complete;
            while !input.is_empty() {
                let H3Frame::Unknown { length, .. } = be_frame(&mut input).await.unwrap() else {
                    panic!("expected unknown frame")
                };
                skip_payload(&mut input, length.into_u64()).await.unwrap();
            }
            // The caller checks EOF; be_frame itself still reports an error.
            assert_eq!(
                be_frame(&mut input).await.unwrap_err(),
                Error::H3_FRAME_ERROR
            );
        }

        let mut truncated = vec![vec![0], vec![1, 3, 0, 0], vec![0x21, 2, 0]];
        for ty in [0x21u64, 0x40, 0x4000, 1 << 30, (1 << 62) - 1] {
            let mut encoded = Vec::new();
            encoded.put_varint(&VarInt::try_from(ty).unwrap());
            for end in 1..encoded.len() {
                truncated.push(encoded[..end].to_vec());
            }
        }
        for length in [0u64, 64, 16384, 1 << 30, (1 << 62) - 1] {
            let mut encoded = vec![0x21];
            encoded.put_varint(&VarInt::try_from(length).unwrap());
            for end in 1..encoded.len() {
                truncated.push(encoded[..end].to_vec());
            }
            if length != 0 {
                // Even a huge declared length must be skipped without allocating it.
                truncated.push(encoded);
            }
        }
        for partial in truncated {
            for prefix in [&[][..], &[0x21, 0][..]] {
                let encoded = [prefix, partial.as_slice()].concat();
                let mut input = encoded.as_slice();
                let error = loop {
                    match be_frame(&mut input).await {
                        Err(error) => break error,
                        Ok(H3Frame::Unknown { length, .. }) => {
                            if let Err(error) = skip_payload(&mut input, length.into_u64()).await {
                                break error;
                            }
                        }
                        Ok(_) => panic!("expected truncated frame"),
                    }
                };
                assert_eq!(error, Error::H3_FRAME_ERROR, "{encoded:x?}");
            }
        }
    }

    #[tokio::test]
    async fn every_frame_round_trips_without_consuming_the_next_frame() {
        for value in [
            0u64,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let id = VarInt::try_from(value).unwrap();
            let frames = [
                H3Frame::Data(Frame::new(Data(3)).unwrap()),
                H3Frame::Headers(
                    Frame::new(Headers {
                        field_section: Bytes::from_static(b"abc"),
                    })
                    .unwrap(),
                ),
                H3Frame::CancelPush(Frame::new(CancelPush { push_id: id.into() }).unwrap()),
                H3Frame::Settings(Frame::new(Settings::default()).unwrap()),
                H3Frame::PushPromise(
                    Frame::new(PushPromise {
                        push_id: id,
                        field_section: Bytes::from_static(b"abc"),
                    })
                    .unwrap(),
                ),
                H3Frame::Goaway(Frame::new(Goaway { id }).unwrap()),
                H3Frame::MaxPushId(Frame::new(MaxPushId { push_id: id }).unwrap()),
            ];
            for (frame, (ty, length)) in frames.into_iter().zip([
                (0, 3),
                (1, 3),
                (3, id.encoding_size()),
                (4, 0),
                (5, id.encoding_size() + 3),
                (7, id.encoding_size()),
                (13, id.encoding_size()),
            ]) {
                let mut encoded = Vec::new();
                encoded.put_frame(&frame);
                assert_eq!(encoded[0], ty);
                assert_eq!(frame.frame_type(), FrameType::try_from(ty as u64).unwrap());
                let mut envelope = encoded.as_slice();
                assert_eq!(
                    be_varint(&mut envelope).await.unwrap().into_u64(),
                    ty as u64
                );
                assert_eq!(
                    be_varint(&mut envelope).await.unwrap().into_u64(),
                    length as u64
                );
                if ty == 0 {
                    encoded.extend_from_slice(b"abc");
                }
                encoded.extend_from_slice(&[0, 0]);
                let mut input = encoded.as_slice();
                assert_eq!(be_frame(&mut input).await.unwrap(), frame);
                if ty == 0 {
                    assert_eq!(&input[..3], b"abc");
                    input = &input[3..];
                }
                assert_eq!(
                    be_frame(&mut input).await.unwrap(),
                    H3Frame::Data(Frame::new(Data(0)).unwrap())
                );
                assert!(input.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn rejects_invalid_frame_lengths_and_forbidden_types() {
        for ty in [3, 7, 13] {
            for payload in [&[0][..], &[2, 0, 0], &[1, 0x40], &[9]] {
                let mut encoded = vec![ty];
                encoded.extend_from_slice(payload);
                assert_eq!(
                    be_frame(&mut encoded.as_slice()).await.unwrap_err(),
                    Error::H3_FRAME_ERROR
                );
            }
        }
        for ty in [1, 4, 5] {
            let mut encoded = vec![ty];
            encoded.put_varint(&VarInt::try_from(MAX_BUFFERED_FRAME_PAYLOAD + 1).unwrap());
            assert_eq!(
                be_frame(&mut encoded.as_slice()).await.unwrap_err(),
                Error::H3_EXCESSIVE_LOAD
            );
        }
        for ty in [2, 6, 8, 9] {
            assert_eq!(
                be_frame(&mut &[ty][..]).await.unwrap_err(),
                Error::H3_FRAME_UNEXPECTED
            );
        }
        assert_eq!(
            be_frame(&mut &[5, 0][..]).await.unwrap_err(),
            Error::H3_FRAME_ERROR
        );
    }
}
