use std::{future::Future, task::Waker};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::test_support::{TestStream, connection, read_stream, write_stream};

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
        (vec![1, 0], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
        (vec![4, 0], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
        (vec![2, 0], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
    ] {
        let connection = connection().await;
        let mut tunnel = Tunnel::new(
            read_stream(0, std::io::Cursor::new(wire)),
            write_stream(0, tokio::io::sink()),
            connection.qpack().clone(),
        );
        let mut bytes = Vec::new();
        let result = tunnel.read_to_end(&mut bytes).await;
        assert_eq!(result.err().map(ErrorCode::from), expected);
        assert_eq!(connection.qpack().error().map(ErrorCode::from), expected);
        if let Some(expected) = expected {
            assert_eq!(
                ErrorCode::from(tunnel.read(&mut [0]).await.unwrap_err()),
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
        let mut tunnel = Tunnel::new(
            read_stream(0, recv),
            write_stream(0, tokio::io::sink()),
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
            let mut reading = Box::pin(tunnel.read(&mut output));
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
                tunnel.read_exact(&mut output).await.unwrap();
                assert_eq!(&output, b"ok");
            }
        );
    }
}

#[tokio::test]
async fn cancelled_flush_resumes_partial_write_and_abort_discards_buffer() {
    let connection = connection().await;
    let (send, mut peer) = tokio::io::duplex(1);
    let send = TestStream::new(send);
    let cancelled = send.cancelled.clone();
    let recv = TestStream::new(tokio::io::empty());
    let stopped = recv.stopped.clone();
    let mut tunnel = Tunnel::new(
        H3ReadStream::new(0, recv),
        H3WriteStream::new(0, send),
        connection.qpack().clone(),
    );
    assert_eq!(tunnel.write(b"abc").await.unwrap(), 3);
    let mut wire = Vec::new();
    for _ in 0..4 {
        let mut flushing = Box::pin(tunnel.flush());
        assert!(
            flushing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(flushing);
        wire.push(peer.read_u8().await.unwrap());
    }
    tunnel.flush().await.unwrap();
    wire.push(peer.read_u8().await.unwrap());
    assert_eq!(wire, [0, 3, b'a', b'b', b'c']);
    tunnel.write_all(b"unsent").await.unwrap();
    tunnel.abort();
    tunnel.abort();
    assert_eq!(
        *cancelled.lock().unwrap(),
        [ErrorCode::H3_REQUEST_CANCELLED.as_u64()]
    );
    assert_eq!(
        *stopped.lock().unwrap(),
        [ErrorCode::H3_REQUEST_CANCELLED.as_u64()]
    );
    assert!(tunnel.flush().await.is_err());
    assert!(tunnel.read(&mut [0]).await.is_err());
    assert!(connection.qpack().error().is_none());
}

#[tokio::test]
async fn empty_frames_have_a_poll_budget() {
    let connection = connection().await;
    let mut tunnel = Tunnel::new(
        read_stream(0, std::io::Cursor::new(vec![0; 1000])),
        write_stream(0, tokio::io::sink()),
        connection.qpack().clone(),
    );
    let mut output = [0; 1];
    let mut future = Box::pin(tunnel.read(&mut output));
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(future.await.unwrap(), 0);
}

#[tokio::test]
async fn cancelled_shutdown_drains_once_and_preserves_receive_direction() {
    let connection = connection().await;
    let (send, mut peer) = tokio::io::duplex(1);
    let mut tunnel = Tunnel::new(
        read_stream(0, std::io::Cursor::new(vec![0, 2, b'o', b'k'])),
        write_stream(0, send),
        connection.qpack().clone(),
    );
    tunnel.write_all(b"abc").await.unwrap();
    let mut closing = Box::pin(tunnel.finish());
    assert!(
        closing
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(closing);
    let ((), wire) = tokio::join!(
        async {
            tunnel.flush().await.unwrap();
            assert_eq!(
                tunnel.write(b"late").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            tunnel.finish().await.unwrap();
            tunnel.finish().await.unwrap();
            let mut reply = Vec::new();
            tunnel.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"ok");
        },
        async {
            let mut wire = Vec::new();
            peer.read_to_end(&mut wire).await.unwrap();
            wire
        }
    );
    assert_eq!(wire, [0, 3, b'a', b'b', b'c']);
}
