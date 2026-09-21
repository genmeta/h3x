use h3x::{ArcWndBuf, Error, ErrorCode};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn error_code_conversion() {
    for code in (0x100..=0x110).chain(0x200..=0x202) {
        assert_eq!(ErrorCode::try_from(code).unwrap().as_u64(), code);
    }
    for code in [0, 0xff, 0x111, 0x1ff, 0x203, u64::MAX] {
        assert_eq!(ErrorCode::try_from(code), Err(code));
    }
}

#[tokio::test]
async fn cancellation_affects_all_clones_and_preserves_first_error() {
    for mode in 0..4 {
        for code in [ErrorCode::RequestCancelled.as_u64(), 0xdead] {
            let mut window = ArcWndBuf::new(8);
            let mut reader = window.clone();
            let mut writer = window.clone();
            match mode {
                0 => window.stop(code),
                1 => window.cancel(code),
                2 => (&window).stop(code),
                _ => (&window).cancel(code),
            }
            window.stop(ErrorCode::MessageError.as_u64());
            let expected = ErrorCode::try_from(code).unwrap_or(ErrorCode::InternalError);
            let error = reader.read(&mut [0; 1]).await.unwrap_err();
            let error = Error::from(error);
            assert!(matches!(error, Error::Stream(_)));
            assert_eq!(error.code, expected);
            let error = writer.write(b"x").await.unwrap_err();
            let error = Error::from(error);
            assert!(matches!(error, Error::Stream(_)));
            assert_eq!(error.code, expected);
        }
    }
}
