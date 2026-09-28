use super::*;
use crate::ErrorCode;

#[test]
fn stream_state_retains_normal_and_failed_terminal_states() {
    let failed = ArcH3Stream::new(1);
    let error = ErrorCode::RequestCancelled.stream("cancelled");
    assert!(failed.fail(error.clone(), |io| *io += 1));
    assert!(
        !failed.fail(ErrorCode::InternalError.stream("later"), |_| panic!(
            "failed I/O is untouched"
        ))
    );
    assert_eq!(failed.0.lock().unwrap().as_ref().unwrap_err(), &error);

    let waker = Waker::noop().clone();
    let polling = ArcH3Stream(Arc::new(Mutex::new(Ok(H3Stream::Polling(3, waker)))));
    assert!(polling.fail(error.clone(), |io| *io += 1));

    let finished = ArcH3Stream::new(7);
    assert!(finished.finish());
    assert!(!finished.finish());
    assert!(matches!(
        *finished.0.lock().unwrap(),
        Ok(H3Stream::Finished)
    ));
    assert!(finished.fail(error.clone(), |_| {
        panic!("finished I/O has already been released")
    }));
    assert_eq!(finished.0.lock().unwrap().as_ref().unwrap_err(), &error);
}
