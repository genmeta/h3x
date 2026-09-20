use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use qbase::varint::{VarInt, WriteVarInt};
use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, ReadBuf};

use super::*;

fn vi(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

fn assert_code(error: crate::Error, code: ErrorCode) {
    assert_eq!(error.code, code, "{}", error.reason);
}

async fn decode(input: &mut &[u8]) -> Result<Option<H3Frame>> {
    let Some(ty) = be_frame_type(input).await? else {
        return Ok(None);
    };
    let length = be_frame_length(input).await?;
    be_frame_payload(input, ty, length).await.map(Some)
}

#[tokio::test]
async fn every_frame_round_trips_at_varint_boundaries() {
    for value in [
        0,
        63,
        64,
        16_383,
        16_384,
        (1 << 30) - 1,
        1 << 30,
        (1 << 62) - 1,
    ] {
        let id = vi(value);
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
        for (expected, ty) in frames.into_iter().zip([0, 1, 3, 4, 5, 7, 13]) {
            let mut encoded = Vec::new();
            encoded.put_frame(&expected);
            assert_eq!(expected.frame_type(), FrameType::try_from(ty).unwrap());
            if ty == 0 {
                encoded.extend_from_slice(b"abc");
            }
            encoded.extend_from_slice(&[0, 0]);

            let mut input = encoded.as_slice();
            assert_eq!(decode(&mut input).await.unwrap().unwrap(), expected);
            if ty == 0 {
                assert_eq!(&input[..3], b"abc");
                input = &input[3..];
            }
            assert_eq!(
                decode(&mut input).await.unwrap(),
                Some(H3Frame::Data(Frame::new(Data(0)).unwrap()))
            );
            assert_eq!(decode(&mut input).await.unwrap(), None);
        }
    }
}

#[tokio::test]
async fn frame_envelopes_reject_invalid_types_lengths_and_payloads() {
    for ty in [2, 6, 8, 9] {
        assert_code(
            FrameType::try_from(ty).unwrap_err(),
            ErrorCode::H3_FRAME_UNEXPECTED,
        );
    }
    assert_code(
        FrameType::try_from(1 << 62).unwrap_err(),
        ErrorCode::H3_FRAME_ERROR,
    );
    assert_code(
        be_frame_type(&mut &[0x40][..]).await.unwrap_err(),
        ErrorCode::H3_FRAME_ERROR,
    );
    assert_code(
        be_frame_length(&mut &[0x40][..]).await.unwrap_err(),
        ErrorCode::H3_FRAME_ERROR,
    );

    let too_large = vi(MAX_BUFFERED_FRAME_PAYLOAD as u64 + 1);
    for ty in [
        FrameType::Headers,
        FrameType::Settings,
        FrameType::PushPromise,
    ] {
        assert_code(
            be_frame_payload(&mut &[][..], ty, too_large)
                .await
                .unwrap_err(),
            ErrorCode::H3_EXCESSIVE_LOAD,
        );
    }
    assert_code(
        skip_payload(&mut &[1, 2][..], 3).await.unwrap_err(),
        ErrorCode::H3_FRAME_ERROR,
    );
    let mut input = &[1, 2, 3, 4][..];
    skip_payload(&mut input, 3).await.unwrap();
    assert_eq!(input, &[4]);

    let unknown = H3Frame::Unknown {
        ty: vi(42),
        length: vi(3),
    };
    assert_eq!(unknown.frame_type(), FrameType::Unknown(vi(42)));
    assert_eq!(VarInt::from(FrameType::Unknown(vi(42))), vi(42));
    assert_eq!(
        be_frame_payload(&mut &[][..], FrameType::Unknown(vi(42)), vi(3))
            .await
            .unwrap(),
        unknown
    );
}

#[tokio::test]
async fn identifier_frames_reject_missing_trailing_and_oversized_payloads() {
    for ty in [
        FrameType::CancelPush,
        FrameType::Goaway,
        FrameType::MaxPushId,
    ] {
        for (payload, length) in [(&[][..], 0), (&[0, 0][..], 2), (&[0x40][..], 1)] {
            let mut input = payload;
            assert_code(
                be_frame_payload(&mut input, ty, vi(length))
                    .await
                    .unwrap_err(),
                ErrorCode::H3_FRAME_ERROR,
            );
        }
        assert_code(
            be_frame_payload(&mut &[][..], ty, vi(9)).await.unwrap_err(),
            ErrorCode::H3_FRAME_ERROR,
        );
    }
    assert_code(
        be_frame_payload(&mut &[0x40][..], FrameType::PushPromise, vi(1))
            .await
            .unwrap_err(),
        ErrorCode::H3_FRAME_ERROR,
    );
}

#[tokio::test]
async fn settings_validate_ids_values_duplicates_and_truncation() {
    assert_code(
        be_frame_payload(&mut &[][..], FrameType::Settings, vi(1))
            .await
            .unwrap_err(),
        ErrorCode::H3_FRAME_ERROR,
    );
    for payload in [
        &[2, 0][..],
        &[8, 2][..],
        &[1, 0, 1, 1][..],
        &[1][..],
        &[1, 0x40][..],
    ] {
        let mut input = payload;
        assert!(
            be_frame_payload(&mut input, FrameType::Settings, vi(payload.len() as u64))
                .await
                .is_err()
        );
    }

    let mut values = std::collections::HashMap::new();
    values.insert(vi(1), vi(64));
    values.insert(vi(8), vi(1));
    let expected = Frame::new(Settings { values }).unwrap();
    assert_eq!(expected.payload.get(1, 0), 64);
    assert_eq!(expected.payload.get(99, 7), 7);
    let mut bytes = Vec::new();
    bytes.put_frame(&expected);
    assert!(matches!(
        decode(&mut bytes.as_slice()).await.unwrap(),
        Some(H3Frame::Settings(_))
    ));
}

#[derive(Default)]
struct StoppableReader {
    bytes: Vec<u8>,
    offset: usize,
    stopped: Option<u64>,
}

impl AsyncRead for StoppableReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = (self.bytes.len() - self.offset).min(buf.remaining());
        buf.put_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl StopSending for StoppableReader {
    fn stop(&mut self, code: u64) {
        self.stopped = Some(code);
    }
}

#[tokio::test]
async fn stream_types_and_controls_cover_known_unknown_and_forbidden_values() {
    for (byte, expected) in [
        (0, StreamType::Control),
        (1, StreamType::Push),
        (2, StreamType::QpackEncoder),
        (3, StreamType::QpackDecoder),
    ] {
        let mut reader = StoppableReader {
            bytes: vec![byte],
            ..Default::default()
        };
        assert_eq!(be_stream_type(&mut reader).await.unwrap(), Some(expected));
        assert_eq!(reader.stopped, None);
    }
    let mut unknown = StoppableReader {
        bytes: vec![63],
        ..Default::default()
    };
    assert_eq!(be_stream_type(&mut unknown).await.unwrap(), None);
    assert_eq!(
        unknown.stopped,
        Some(ErrorCode::H3_STREAM_CREATION_ERROR.as_u64())
    );
    assert_eq!(
        be_stream_type(&mut StoppableReader::default())
            .await
            .unwrap(),
        None
    );

    for (frame, expected) in [
        (
            Control::Settings(Frame::new(Settings::default()).unwrap()),
            FrameType::Settings,
        ),
        (
            Control::Goaway(Frame::new(Goaway { id: vi(3) }).unwrap()),
            FrameType::Goaway,
        ),
        (
            Control::CancelPush(
                Frame::new(CancelPush {
                    push_id: vi(4).into(),
                })
                .unwrap(),
            ),
            FrameType::CancelPush,
        ),
        (
            Control::MaxPushId(Frame::new(MaxPushId { push_id: vi(5) }).unwrap()),
            FrameType::MaxPushId,
        ),
    ] {
        let mut encoded = Vec::new();
        encoded.put_control(&frame);
        let decoded = be_control(&mut encoded.as_slice()).await.unwrap();
        let actual = match decoded {
            Control::Settings(frame) => frame.frame_type(),
            Control::Goaway(frame) => frame.frame_type(),
            Control::CancelPush(frame) => frame.frame_type(),
            Control::MaxPushId(frame) => frame.frame_type(),
            Control::Unknown { .. } => unreachable!(),
        };
        assert_eq!(actual, expected);
    }

    let unknown = Control::Unknown {
        ty: vi(42),
        length: vi(3),
    };
    let mut encoded = Vec::new();
    encoded.put_control(&unknown);
    assert_eq!(be_control(&mut encoded.as_slice()).await.unwrap(), unknown);
    for bytes in [&[][..], &[0][..], &[1, 0][..], &[4][..], &[4, 2, 0][..]] {
        let mut input = bytes;
        assert!(be_control(&mut input).await.is_err());
    }
    let mut oversized = vec![4];
    oversized.put_varint(&vi(MAX_BUFFERED_FRAME_PAYLOAD as u64 + 1));
    assert_code(
        be_control(&mut oversized.as_slice()).await.unwrap_err(),
        ErrorCode::H3_EXCESSIVE_LOAD,
    );
}

struct FailingReader;

impl AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("boom")))
    }
}

impl StopSending for FailingReader {
    fn stop(&mut self, _: u64) {}
}

#[tokio::test]
async fn io_failures_are_mapped_by_decoder_context() {
    assert_code(
        be_frame_type(&mut FailingReader).await.unwrap_err(),
        ErrorCode::H3_INTERNAL_ERROR,
    );
    assert_code(
        be_stream_type(&mut FailingReader).await.unwrap_err(),
        ErrorCode::H3_INTERNAL_ERROR,
    );
    assert_code(
        be_control(&mut FailingReader).await.unwrap_err(),
        ErrorCode::H3_CLOSED_CRITICAL_STREAM,
    );
}
