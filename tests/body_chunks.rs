use std::{
    future::Future,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bytes::Bytes;
use h3x::{ArcWndBuf, Error, ErrorCode};
use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn owned_chunks_preserve_allocation_across_partial_reads() {
    let data = Bytes::from(vec![42; 32]);
    let mut window = ArcWndBuf::new(32);
    window.write_bytes(data.clone()).await.unwrap();
    window.shutdown().await.unwrap();
    let first = window.read_chunk(7).await.unwrap();
    let rest = window.read_chunk(64).await.unwrap();
    assert_eq!(first.as_ptr(), data.as_ptr());
    assert_eq!(rest.as_ptr(), data[7..].as_ptr());
    assert_eq!(first.len() + rest.len(), data.len());
    assert!(window.read_chunk(1).await.unwrap().is_empty());
    assert!(window.write_bytes(Bytes::from_static(b"x")).await.is_err());
}

#[tokio::test]
async fn borrowed_and_owned_io_preserve_order() {
    let mut window = ArcWndBuf::new(32);
    window.write_all(b"a").await.unwrap();
    window.write_all(b"b").await.unwrap();
    assert_eq!(window.read_chunk(32).await.unwrap(), b"a"[..]);
    assert_eq!(window.read_chunk(32).await.unwrap(), b"b"[..]);
    window.write_all(b"cd").await.unwrap();
    window
        .write_bytes(Bytes::from_static(b"efgh"))
        .await
        .unwrap();
    window.write_all(b"ij").await.unwrap();
    window.shutdown().await.unwrap();
    assert_eq!(window.read_chunk(1).await.unwrap(), b"c"[..]);
    let mut bytes = [0; 4];
    window.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"defg");
    assert_eq!(window.read_chunk(32).await.unwrap(), b"h"[..]);
    assert_eq!(window.read_chunk(32).await.unwrap(), b"ij"[..]);
    assert!(window.read_chunk(1).await.unwrap().is_empty());
}

#[test]
fn bounded_partial_writes_preserve_remaining_bytes_and_wake_producer() {
    let window = ArcWndBuf::new(3);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut data = Bytes::from_static(b"abcdef");
    assert!(matches!(
        window.poll_write_bytes(&mut cx, &mut data),
        Poll::Ready(Ok(3))
    ));
    assert_eq!(data, b"def"[..]);
    assert!(window.poll_write_bytes(&mut cx, &mut data).is_pending());
    assert_eq!(data, b"def"[..]);
    assert!(matches!(window.poll_read_chunk(&mut cx, 2), Poll::Ready(Ok(b)) if b == b"ab"[..]));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert!(matches!(
        window.poll_write_bytes(&mut cx, &mut data),
        Poll::Ready(Ok(2))
    ));
    assert_eq!(data, b"f"[..]);
}

#[tokio::test]
async fn chunk_readers_wake_on_data_and_eof_and_zero_length_reads_do_not_consume() {
    let mut window = ArcWndBuf::new(4);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(window.poll_read_chunk(&mut cx, 4).is_pending());
    window
        .write_bytes(Bytes::from_static(b"test"))
        .await
        .unwrap();
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    let mut empty = ReadBuf::new(&mut []);
    assert!(
        std::pin::Pin::new(&mut window)
            .poll_read(&mut cx, &mut empty)
            .is_ready()
    );
    assert_eq!(window.read_chunk(4).await.unwrap(), b"test"[..]);
    assert!(window.poll_read_chunk(&mut cx, 4).is_pending());
    window.shutdown().await.unwrap();
    assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
    assert!(window.read_chunk(4).await.unwrap().is_empty());
}

#[tokio::test]
async fn cancellation_wakes_blocked_chunk_io_and_preserves_first_error() {
    for full in [false, true] {
        let mut window = ArcWndBuf::new(1);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        if full {
            window.write_bytes(Bytes::from_static(b"x")).await.unwrap();
            assert!(
                window
                    .poll_write_bytes(&mut cx, &mut Bytes::from_static(b"y"))
                    .is_pending()
            );
        } else {
            assert!(window.poll_read_chunk(&mut cx, 1).is_pending());
        }
        window.stop(ErrorCode::RequestCancelled.as_u64());
        window.stop(ErrorCode::InternalError.as_u64());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            Error::from(window.read_chunk(1).await.unwrap_err()).code,
            ErrorCode::RequestCancelled
        );
        assert_eq!(
            Error::from(
                window
                    .write_bytes(Bytes::from_static(b"z"))
                    .await
                    .unwrap_err()
            )
            .code,
            ErrorCode::RequestCancelled
        );
    }
}

#[tokio::test]
async fn dropping_partial_write_leaves_only_accepted_prefix() {
    let mut window = ArcWndBuf::new(2);
    {
        let mut writing = pin!(window.write_bytes(Bytes::from_static(b"abcd")));
        assert!(
            writing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    window.shutdown().await.unwrap();
    assert_eq!(window.read_chunk(4).await.unwrap(), b"ab"[..]);
    assert!(window.read_chunk(4).await.unwrap().is_empty());
}
