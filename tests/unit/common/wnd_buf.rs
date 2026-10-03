use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::ErrorCode;

#[test]
fn error_callback_observes_the_first_error_once() {
    let window = ArcWndBuf::new(1);
    let calls = Arc::new(AtomicUsize::new(0));
    window.on_error({
        let calls = calls.clone();
        move |error| {
            assert_eq!(error.code, ErrorCode::RequestCancelled);
            calls.fetch_add(1, Ordering::SeqCst);
        }
    });
    window.cancel(ErrorCode::RequestCancelled.as_u64());
    window.cancel(ErrorCode::InternalError.as_u64());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn callback_registered_after_failure_runs_immediately() {
    let window = ArcWndBuf::new(1);
    window.cancel(ErrorCode::RequestCancelled.as_u64());
    let calls = Arc::new(AtomicUsize::new(0));
    window.on_error({
        let calls = calls.clone();
        move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
        }
    });
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropping_window_clones_does_not_change_io_or_terminal_state() {
    use tokio::io::AsyncWriteExt;
    let mut window = ArcWndBuf::new(1);
    drop(window.clone());
    window.write_bytes(Bytes::from_static(b"a")).await.unwrap();
    window.shutdown().await.unwrap();
    drop(window.clone());
    assert_eq!(window.read_chunk(1).await.unwrap(), "a");
    assert!(window.read_chunk(1).await.unwrap().is_empty());

    let failed = ArcWndBuf::new(1);
    failed.error(ErrorCode::MessageError.stream("invalid message"));
    drop(failed.clone());
    assert_eq!(
        Error::from_stream_io(failed.read_chunk(1).await.unwrap_err()).code,
        ErrorCode::MessageError
    );
}

#[tokio::test]
async fn initial_bytes_are_shared_and_backpressure_subsequent_writes() {
    use tokio::io::AsyncWriteExt;
    let initial = Bytes::from(vec![42; 12]);
    let address = initial.as_ptr();
    let window = ArcWndBuf::with_initial(4, initial);
    let mut writer = window.clone();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        Pin::new(&mut writer)
            .poll_write(&mut cx, b"tail")
            .is_pending()
    );
    let prefix = window.read_chunk(8).await.unwrap();
    assert_eq!(prefix.as_ptr(), address);
    assert_eq!(prefix.len(), 8);
    assert!(
        Pin::new(&mut writer)
            .poll_write(&mut cx, b"tail")
            .is_pending()
    );
    assert_eq!(window.read_chunk(2).await.unwrap().as_ref(), &[42; 2]);
    writer.write_all(b"xy").await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(window.read_chunk(4).await.unwrap().as_ref(), &[42; 2]);
    assert_eq!(window.read_chunk(4).await.unwrap(), "xy");
    assert!(window.read_chunk(4).await.unwrap().is_empty());
}
