//! Control frame variants and wire codec.
use bytes::BufMut;
use qbase::varint::{VarInt, WriteVarInt};
use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{self as frame, Frame, FrameType, H3Frame, Write as _};
use crate::{Error, ErrorCode, Result};

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
        .map_err(|error| {
            let error = error
                .get_ref()
                .and_then(|error| error.downcast_ref::<std::sync::Arc<std::io::Error>>())
                .map_or(&error, std::sync::Arc::as_ref);
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<crate::Error>())
                .cloned()
                .unwrap_or_else(|| {
                    let code = ErrorCode::H3_CLOSED_CRITICAL_STREAM;
                    code.with_reason(error.to_string())
                })
        })?
        .ok_or_else(|| {
            ErrorCode::H3_CLOSED_CRITICAL_STREAM.with_reason("critical HTTP/3 stream closed")
        })?;
    let known = match ty.into_u64() {
        4 => Some(FrameType::Settings),
        3 => Some(FrameType::CancelPush),
        7 => Some(FrameType::Goaway),
        13 => Some(FrameType::MaxPushId),
        0..=9 => {
            return Err(
                ErrorCode::H3_FRAME_UNEXPECTED.with_reason("frame is not allowed in this context")
            );
        }
        _ => None,
    };
    let length = frame::be_varint(recv)
        .await
        .map_err(|error| {
            let error = error
                .get_ref()
                .and_then(|error| error.downcast_ref::<std::sync::Arc<std::io::Error>>())
                .map_or(&error, std::sync::Arc::as_ref);
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<crate::Error>())
                .cloned()
                .unwrap_or_else(|| {
                    let code = ErrorCode::H3_CLOSED_CRITICAL_STREAM;
                    code.with_reason(error.to_string())
                })
        })?
        .ok_or_else(|| {
            ErrorCode::H3_CLOSED_CRITICAL_STREAM.with_reason("critical HTTP/3 stream closed")
        })?;
    let Some(known) = known else {
        return Ok(Control::Unknown { ty, length });
    };
    if length.into_u64() > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64 {
        return Err(ErrorCode::H3_EXCESSIVE_LOAD.with_reason("configured resource limit exceeded"));
    }
    let mut payload = vec![0; length.into_u64() as usize];
    recv.read_exact(&mut payload).await.map_err(|error| {
        let error = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<std::sync::Arc<std::io::Error>>())
            .map_or(&error, std::sync::Arc::as_ref);
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<crate::Error>())
            .cloned()
            .unwrap_or_else(|| {
                let code = ErrorCode::H3_CLOSED_CRITICAL_STREAM;
                code.with_reason(error.to_string())
            })
    })?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_stream_type_stops_only_its_stream_and_eof_needs_no_stop() {
        struct Reader<'a> {
            input: &'a [u8],
            stopped: Option<u64>,
        }
        impl AsyncRead for Reader<'_> {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.input).poll_read(cx, buf)
            }
        }
        impl StopSending for Reader<'_> {
            fn stop(&mut self, code: u64) {
                self.stopped = Some(code);
            }
        }
        let mut unknown = Reader {
            input: &[0x21, 0xff],
            stopped: None,
        };
        assert_eq!(be_stream_type(&mut unknown).await.unwrap(), None);
        assert_eq!(
            unknown.stopped,
            Some(ErrorCode::H3_STREAM_CREATION_ERROR.as_u64())
        );
        assert_eq!(unknown.input, &[0xff]);
        for input in [&[][..], &[0x40][..], &[0xc0, 0][..]] {
            let mut reader = Reader {
                input,
                stopped: None,
            };
            assert_eq!(be_stream_type(&mut reader).await.unwrap(), None);
            assert_eq!(reader.stopped, None);
        }
        let mut known = Reader {
            input: &[0, 4, 0],
            stopped: None,
        };
        assert_eq!(
            be_stream_type(&mut known).await.unwrap(),
            Some(StreamType::Control)
        );
        assert_eq!(known.input, &[4, 0]);
        assert_eq!(known.stopped, None);
    }

    #[tokio::test]
    async fn control_variants_round_trip_without_consuming_the_next_frame() {
        let controls = [
            Control::Settings(Frame::new(frame::Settings::default()).unwrap()),
            Control::Goaway(Frame::new(frame::Goaway { id: 4u32.into() }).unwrap()),
            Control::CancelPush(
                Frame::new(frame::CancelPush {
                    push_id: qbase::varint::VarInt::from(0u32).into(),
                })
                .unwrap(),
            ),
            Control::MaxPushId(
                Frame::new(frame::MaxPushId {
                    push_id: 64u32.into(),
                })
                .unwrap(),
            ),
        ];
        for control in controls {
            let mut wire = Vec::new();
            wire.put_control(&control);
            wire.extend_from_slice(&[0xff]);
            let mut input = wire.as_slice();
            assert_eq!(be_control(&mut input).await.unwrap(), control);
            assert_eq!(input, &[0xff]);
        }
    }

    #[tokio::test]
    async fn shared_varints_preserve_critical_io_and_malformed_payload_errors() {
        for partial in [&[][..], &[0x40][..], &[0xc0, 0, 0][..]] {
            assert_eq!(
                (be_control(&mut &partial[..]).await).map_err(ErrorCode::from),
                Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
            );
        }
        assert_eq!(
            (be_control(&mut &[4, 0x40][..]).await).map_err(ErrorCode::from),
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
        );
        assert_eq!(
            (be_control(&mut &[4, 1, 1][..]).await).map_err(ErrorCode::from),
            Err(ErrorCode::H3_FRAME_ERROR)
        );
        assert_eq!(
            (be_control(&mut &[4, 2, 1][..]).await).map_err(ErrorCode::from),
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
        );
    }

    #[tokio::test]
    async fn control_types_and_unknown_payloads_keep_their_wire_boundaries() {
        use qbase::varint::{VarInt, WriteVarInt};
        for ty in [0, 1, 2, 5, 6, 8, 9] {
            assert_eq!(
                (be_control(&mut &[ty, 0][..]).await).map_err(ErrorCode::from),
                Err(ErrorCode::H3_FRAME_UNEXPECTED)
            );
        }
        for ty in [3, 7, 13] {
            assert!(be_control(&mut &[ty, 1, 0][..]).await.is_ok());
        }
        let mut wire = vec![0x21];
        let length = frame::MAX_BUFFERED_FRAME_PAYLOAD + 1;
        wire.put_varint(&VarInt::try_from(length).unwrap());
        wire.resize(wire.len() + length, 0xff); // Unknown frames can exceed the known-frame budget.
        wire.extend_from_slice(&[0x22, 0, 7, 1, 4, 0xff]);
        let mut input = wire.as_slice();
        for expected in [0x21, 0x22] {
            let Control::Unknown { ty, length } = be_control(&mut input).await.unwrap() else {
                panic!()
            };
            assert_eq!(ty.into_u64(), expected);
            frame::skip_payload(&mut input, length.into_u64())
                .await
                .unwrap();
        }
        let Control::Goaway(frame) = be_control(&mut input).await.unwrap() else {
            panic!()
        };
        assert_eq!(frame.payload.id.into_u64(), 4);
        assert_eq!(input, &[0xff]);
        let mut input = &[0x21, 2, 0][..];
        let Control::Unknown { length, .. } = be_control(&mut input).await.unwrap() else {
            panic!()
        };
        assert!(
            frame::skip_payload(&mut input, length.into_u64())
                .await
                .is_err()
        );
    }
}
