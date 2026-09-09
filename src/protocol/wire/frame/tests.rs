use super::*;

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn be_complete_frame(raw: &Bytes) -> Result<(usize, Frame), Error> {
    let parsed = (|| {
        let (payload, header) = be_frame_header(raw)?;
        let payload = raw.slice(raw.len() - payload.len()..);
        let (remaining, frame) = be_frame(&payload, header)?;
        Ok((raw.len() - remaining.len(), frame))
    })();
    let (mut consumed, frame) = parsed.map_err(|error| match error {
        nom::Err::Incomplete(_) => frame_error("incomplete HTTP/3 frame"),
        nom::Err::Error(error) | nom::Err::Failure(error) => error,
    })?;
    if let Frame::Data(data) = &frame {
        if data.length > (raw.len() - consumed) as u64 {
            return Err(frame_error("incomplete DATA payload"));
        }
        consumed += data.length as usize;
    }
    Ok((consumed, frame))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_frames_round_trip_without_consuming_the_next_frame() {
        let id = VarInt::from_u32(16384);
        let data = Bytes::from_static(b"field section or body");
        let frames = [
            Frame::Data(DataFrame { length: 0 }),
            Frame::Headers(HeadersFrame {
                field_section: data.clone(),
            }),
            Frame::CancelPush(CancelPushFrame { push_id: id }),
            Frame::Settings(SettingsFrame {
                settings: crate::Settings::default(),
            }),
            Frame::PushPromise(PushPromiseFrame {
                push_id: id,
                field_section: data,
            }),
            Frame::Goaway(GoawayFrame { id }),
            Frame::MaxPushId(MaxPushIdFrame { push_id: id }),
            Frame::Unknown {
                ty: VarInt::from_u32(0x21),
                payload: Bytes::from_static(b"extension"),
            },
        ];
        for expected in frames {
            let mut raw = Vec::new();
            raw.put_frame(&expected).unwrap();
            let len = raw.len();
            for end in 0..len {
                assert!(be_complete_frame(&Bytes::copy_from_slice(&raw[..end])).is_err());
            }
            raw.extend_from_slice(&[0, 0]);
            let raw = Bytes::from(raw);
            let (used, actual) = be_complete_frame(&raw).unwrap();
            assert_eq!(used, len);
            assert_eq!(actual, expected);
            match actual {
                Frame::Headers(frame) => {
                    assert_eq!(frame.field_section.as_ptr(), raw[2..].as_ptr())
                }
                Frame::PushPromise(frame) => {
                    assert_eq!(frame.field_section.as_ptr(), raw[6..].as_ptr())
                }
                _ => {}
            }
            assert_eq!(be_complete_frame(&raw.slice(used..)).unwrap().0, 2);
        }
    }

    #[test]
    fn malformed_payloads_and_forbidden_types_are_rejected() {
        for ty in [3, 7, 13] {
            for payload in [&[][..], &[0, 0], &[0x40], &[0; 9]] {
                let mut raw = Vec::new();
                raw.put_frame(&FrameHeader {
                    frame_type: ty.into(),
                    length: payload.len() as u64,
                })
                .unwrap();
                raw.extend_from_slice(payload);
                let raw = Bytes::from(raw);
                assert_eq!(
                    be_complete_frame(&raw).unwrap_err().code(),
                    Some(Code::H3_FRAME_ERROR)
                );
            }
        }
        for raw in [&[5, 0][..], &[5, 1, 0x40], &[4, 1, 0]] {
            assert_eq!(
                be_complete_frame(&Bytes::copy_from_slice(raw))
                    .unwrap_err()
                    .code(),
                Some(Code::H3_FRAME_ERROR)
            );
        }
        for ty in [2, 6, 8, 9] {
            assert_eq!(
                be_complete_frame(&Bytes::from(vec![ty, 0]))
                    .unwrap_err()
                    .code(),
                Some(Code::H3_FRAME_UNEXPECTED)
            );
        }
        let mut raw = Vec::new();
        assert!(
            raw.put_frame(&Frame::Unknown {
                ty: VarInt::from_u32(3),
                payload: Bytes::new()
            })
            .is_err()
        );
        assert!(raw.is_empty());
    }
}

#[test]
fn wire_types_round_trip() {
    use crate::wire::StreamType;
    for value in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0d, 0x54, 0x21, (1 << 62) - 1] {
        assert_eq!(u64::from(FrameType::from(value)), value);
        assert_eq!(u64::from(StreamType::from(value)), value);
    }
    assert_eq!(FrameType::from(0), FrameType::Data);
    assert_eq!(FrameType::from(1), FrameType::Headers);
    assert_eq!(FrameType::from(4), FrameType::Settings);
    assert_eq!(FrameType::from(7), FrameType::Goaway);
    assert_eq!(StreamType::from(0), StreamType::Control);
    assert_eq!(StreamType::from(1), StreamType::Push);
    assert_eq!(StreamType::from(2), StreamType::QpackEncoder);
    assert_eq!(StreamType::from(3), StreamType::QpackDecoder);
    assert_eq!(FrameType::from(0x21), FrameType::Unknown(0x21));
    assert_eq!(StreamType::from(0x21), StreamType::Unknown(0x21));
}
