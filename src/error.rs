use std::{fmt, io, sync::Arc};

/// A protocol error and the reason for this particular failure.
#[derive(Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct Error {
    pub code: ErrorCode,
    pub reason: String,
}

impl Error {
    pub fn new(code: ErrorCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    /// Preserve embedded protocol errors, using `fallback` for plain I/O failures.
    pub(crate) fn from_io(error: io::Error, code: ErrorCode) -> Self {
        Self::from_io_with(error, |_| code)
    }

    /// Frame truncation is a framing error; other plain I/O failures are internal.
    pub(crate) fn from_frame_io(error: io::Error) -> Self {
        Self::from_io_with(error, |kind| match kind {
            io::ErrorKind::UnexpectedEof => ErrorCode::H3_FRAME_ERROR,
            _ => ErrorCode::H3_INTERNAL_ERROR,
        })
    }

    fn from_io_with(error: io::Error, fallback: impl FnOnce(io::ErrorKind) -> ErrorCode) -> Self {
        let error = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Arc<io::Error>>())
            .map_or(&error, Arc::as_ref);
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Self>())
            .cloned()
            .unwrap_or_else(|| fallback(error.kind()).reason(error.to_string()))
    }
}

impl From<Error> for ErrorCode {
    fn from(error: Error) -> Self {
        error.code
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::from_io(error, ErrorCode::H3_INTERNAL_ERROR)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        Self::other(error)
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum ErrorCode {
    H3_NO_ERROR = 0x0100,
    H3_GENERAL_PROTOCOL_ERROR = 0x0101,
    H3_INTERNAL_ERROR = 0x0102,
    H3_STREAM_CREATION_ERROR = 0x0103,
    H3_CLOSED_CRITICAL_STREAM = 0x0104,
    H3_FRAME_UNEXPECTED = 0x0105,
    H3_FRAME_ERROR = 0x0106,
    H3_EXCESSIVE_LOAD = 0x0107,
    H3_ID_ERROR = 0x0108,
    H3_SETTINGS_ERROR = 0x0109,
    H3_MISSING_SETTINGS = 0x010a,
    H3_REQUEST_REJECTED = 0x010b,
    H3_REQUEST_CANCELLED = 0x010c,
    H3_REQUEST_INCOMPLETE = 0x010d,
    H3_MESSAGE_ERROR = 0x010e,
    H3_CONNECT_ERROR = 0x010f,
    H3_VERSION_FALLBACK = 0x0110,
    QPACK_DECOMPRESSION_FAILED = 0x0200,
    QPACK_ENCODER_STREAM_ERROR = 0x0201,
    QPACK_DECODER_STREAM_ERROR = 0x0202,
}

impl ErrorCode {
    /// Attach context explaining why this protocol error occurred.
    pub fn reason(self, reason: impl Into<String>) -> Error {
        Error::new(self, reason)
    }

    pub const fn as_u64(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?} (0x{:x})", *self as u64)
    }
}

impl From<io::Error> for ErrorCode {
    fn from(error: io::Error) -> Self {
        Error::from(error).code
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_conversion_uses_fallback_only_for_plain_io_errors() {
        let original = ErrorCode::QPACK_DECODER_STREAM_ERROR.reason("invalid acknowledgment");
        for shared in [false, true] {
            for cause in [
                io::Error::from(original.clone()),
                io::Error::new(io::ErrorKind::BrokenPipe, "writer closed"),
            ] {
                let expected = if cause.kind() == io::ErrorKind::BrokenPipe {
                    ErrorCode::H3_CLOSED_CRITICAL_STREAM.reason("writer closed")
                } else {
                    original.clone()
                };
                let cause = if shared {
                    io::Error::new(cause.kind(), Arc::new(cause))
                } else {
                    cause
                };
                assert_eq!(
                    Error::from_io(cause, ErrorCode::H3_CLOSED_CRITICAL_STREAM),
                    expected
                );
            }
        }
    }

    #[tokio::test]
    async fn frame_boundary_classifies_eof_after_stream_state_wrapping() {
        use std::{
            pin::Pin,
            task::{Context, Poll},
        };

        use tokio::io::{AsyncRead, ReadBuf};
        struct Truncated;
        impl AsyncRead for Truncated {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated transport record",
                )))
            }
        }
        let mut stream = crate::test_support::read_stream(0, Truncated);
        let error = crate::protocol::frame::be_frame(&mut stream)
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::H3_FRAME_ERROR);
        assert_eq!(error.reason, "truncated transport record");
    }

    #[test]
    fn io_conversion_preserves_code_and_reason() {
        let error = ErrorCode::H3_MESSAGE_ERROR.reason("missing pseudo-header :status");
        let io_error = io::Error::from(error.clone());
        assert_eq!(Error::from(io_error), error);
        assert_eq!(ErrorCode::from(io::Error::from(error.clone())), error.code);
        assert_eq!(
            error.to_string(),
            "H3_MESSAGE_ERROR (0x10e): missing pseudo-header :status"
        );
        for (kind, code) in [
            (io::ErrorKind::UnexpectedEof, ErrorCode::H3_INTERNAL_ERROR),
            (io::ErrorKind::BrokenPipe, ErrorCode::H3_INTERNAL_ERROR),
        ] {
            let error = Error::from(io::Error::new(kind, "transport detail"));
            assert_eq!(error.code, code);
            assert_eq!(error.reason, "transport detail");
        }
    }

    #[tokio::test]
    async fn body_preserves_first_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let error = ErrorCode::H3_REQUEST_CANCELLED.reason("application cancelled upload");
        let mut body = crate::ArcWndBuf::new(8);
        body.on_error(error.clone());
        body.on_error(ErrorCode::H3_INTERNAL_ERROR.reason("later failure"));
        assert_eq!(Error::from(body.read(&mut [0]).await.unwrap_err()), error);
        assert_eq!(Error::from(body.write(b"x").await.unwrap_err()), error);
    }

    #[tokio::test]
    async fn stream_returns_each_io_error_without_caching() {
        use std::{
            pin::Pin,
            task::{Context, Poll},
        };

        use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

        struct FailingReader(Option<io::Error>);
        impl AsyncRead for FailingReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Err(self
                    .0
                    .take()
                    .unwrap_or_else(|| io::Error::from_raw_os_error(5))))
            }
        }

        for cause in [
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                "peer reset while reading headers",
            ),
            io::Error::from(ErrorCode::H3_REQUEST_REJECTED.reason("peer rejected request")),
        ] {
            let expected = Error::from(cause);
            let mut stream =
                crate::test_support::read_stream(0, FailingReader(Some(expected.clone().into())));
            let error = stream.read(&mut [0]).await.unwrap_err();
            assert!(error.get_ref().unwrap().is::<Error>());
            assert_eq!(Error::from(error), expected);
            // A subsequent read reaches the transport and preserves its OS error.
            assert_eq!(
                stream.read(&mut [0]).await.unwrap_err().raw_os_error(),
                Some(5)
            );
        }
    }

    #[tokio::test]
    async fn connection_failure_preserves_reason_in_qpack_and_transport() {
        use crate::Transport;

        let connection = crate::test_support::connection().await;
        let error = ErrorCode::QPACK_DECOMPRESSION_FAILED.reason("invalid dynamic reference");
        let _ = connection
            .transport
            .close(error.reason.clone(), error.code.as_u64());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while connection.qpack().error().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(connection.qpack().error(), Some(error.clone()));
        assert_eq!(connection.qpack().cancel(0).unwrap_err(), error);
        assert_eq!(connection.open_bi().await.err(), Some(error.clone()));

        let transport = crate::test_support::TestTransport::default();
        transport
            .close(error.reason.clone(), error.code.as_u64())
            .unwrap();
        assert_eq!(transport.terminated().await, error);
    }

    #[test]
    fn same_code_distinguishes_header_validation_failures() {
        use http::{HeaderMap, HeaderValue, header::CONTENT_LENGTH};

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("abc"));
        let invalid = crate::common::headers::content_length(&headers).unwrap_err();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("1"));
        let duplicate = crate::common::headers::content_length(&headers).unwrap_err();
        assert_eq!(invalid.code, ErrorCode::H3_MESSAGE_ERROR);
        assert_eq!(duplicate.code, invalid.code);
        assert_eq!(
            invalid.reason,
            "Content-Length must contain only decimal digits"
        );
        assert_eq!(
            duplicate.reason,
            "multiple Content-Length fields are not allowed"
        );
    }

    #[test]
    fn preserves_rfc_error_through_io() {
        let error = ErrorCode::from(io::Error::from(
            ErrorCode::H3_MESSAGE_ERROR.reason("invalid response headers"),
        ));
        assert_eq!(error, ErrorCode::H3_MESSAGE_ERROR);
        assert_eq!(error.as_u64(), 0x010e);
        assert_eq!(
            ErrorCode::from(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                ErrorCode::H3_REQUEST_REJECTED.reason("peer rejected the request")
            )),
            ErrorCode::H3_REQUEST_REJECTED,
        );
        for (kind, expected) in [
            (io::ErrorKind::UnexpectedEof, ErrorCode::H3_INTERNAL_ERROR),
            (io::ErrorKind::BrokenPipe, ErrorCode::H3_INTERNAL_ERROR),
            (io::ErrorKind::ConnectionReset, ErrorCode::H3_INTERNAL_ERROR),
        ] {
            assert_eq!(ErrorCode::from(io::Error::from(kind)), expected);
        }
    }
}
