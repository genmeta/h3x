use std::{
    future::Future,
    task::{Context, Waker},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::test_support::{connection, read_stream};

#[tokio::test]
async fn frame_rules_and_terminal_errors() {
    for (wire, expected) in [
        (vec![], None),
        (vec![0, 0, 0, 1, b'x', 0x21, 3, 1, 2, 3, 0, 0], None),
        (vec![0x40], Some(ErrorCode::H3_FRAME_ERROR)),
        (vec![0], Some(ErrorCode::H3_FRAME_ERROR)),
        (vec![0, 0x40], Some(ErrorCode::H3_FRAME_ERROR)),
        (vec![0, 2, 1], Some(ErrorCode::H3_FRAME_ERROR)),
        (vec![0x21, 2, 1], Some(ErrorCode::H3_FRAME_ERROR)),
        (vec![1], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
        (vec![1, 0], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
        (vec![4, 0], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
        (vec![2, 0], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
    ] {
        let connection = connection().await;
        let mut body = receive(
            read_stream(0, std::io::Cursor::new(wire)),
            BodyMode::Connect,
            connection.qpack().clone(),
        );
        let mut bytes = Vec::new();
        let result = body.read_to_end(&mut bytes).await;
        assert_eq!(result.err().map(ErrorCode::from), expected);
        assert_eq!(connection.qpack().error().map(ErrorCode::from), expected);
        if let Some(expected) = expected {
            assert_eq!(
                ErrorCode::from(body.read(&mut [0]).await.unwrap_err()),
                expected
            );
        }
    }
}

#[tokio::test]
async fn cancelled_reads_resume_partial_varints_without_losing_bytes() {
    use qbase::varint::{EncodeBytes, VarInt, WriteVarInt};
    for size in [1, 2, 4, 8] {
        let width = || match size {
            1 => EncodeBytes::One,
            2 => EncodeBytes::Two,
            4 => EncodeBytes::Four,
            _ => EncodeBytes::Eight,
        };
        let connection = connection().await;
        let (mut peer, recv) = tokio::io::duplex(1);
        let mut body = receive(
            read_stream(0, recv),
            BodyMode::Connect,
            connection.qpack().clone(),
        );
        // Encode unknown type 33, length 1, payload 9, then DATA length 2.
        // Include non-minimal varints and cancel after every header byte.
        let mut wire = Vec::new();
        wire.encode_varint(&VarInt::from_u32(33), width());
        wire.encode_varint(&VarInt::from_u32(1), width());
        wire.push(9);
        wire.encode_varint(&VarInt::from_u32(0), width());
        wire.encode_varint(&VarInt::from_u32(2), width());
        for byte in wire {
            peer.write_all(&[byte]).await.unwrap();
            let mut output = [0; 2];
            let mut reading = Box::pin(body.read(&mut output));
            assert!(
                reading
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        let ((), ()) = tokio::join!(
            async {
                peer.write_all(b"ok").await.unwrap();
            },
            async {
                let mut output = [0; 2];
                body.read_exact(&mut output).await.unwrap();
                assert_eq!(&output, b"ok");
            }
        );
    }
}

#[tokio::test]
async fn empty_frames_yield_to_other_tasks() {
    let connection = connection().await;
    let mut recv = read_stream(0, std::io::Cursor::new(vec![0; 1000]));
    let mut sink = tokio::io::sink();
    let mut reading = Box::pin(read_body(
        &mut recv,
        &mut sink,
        BodyMode::Connect,
        connection.qpack(),
    ));
    assert!(
        reading
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    reading.await.unwrap();
}
