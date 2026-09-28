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
