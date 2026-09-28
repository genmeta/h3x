use super::*;

#[test]
fn conversions_preserve_protocol_errors_and_cover_every_registered_code() {
    let stream = ErrorCode::RequestRejected.stream("rejected");
    assert!(matches!(stream, Error::Stream(_)));
    let connection = ErrorCode::IdError.connection("id");
    assert!(matches!(connection, Error::Connection(_)));
    assert_eq!(ErrorCode::from(connection.clone()), ErrorCode::IdError);
    assert_eq!(
        ErrorCode::from(io::Error::other(connection)),
        ErrorCode::IdError
    );
    for code in 0x100..=0x110 {
        assert_eq!(ErrorCode::try_from(code).unwrap().as_u64(), code);
    }
    for code in 0x200..=0x202 {
        assert_eq!(ErrorCode::try_from(code).unwrap().as_u64(), code);
    }
    assert_eq!(ErrorCode::try_from(42), Err(42));
    assert_eq!(ErrorCode::NoError.to_string(), "NoError (0x100)");
}
