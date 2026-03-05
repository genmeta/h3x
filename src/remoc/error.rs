use std::borrow::Cow;

use snafu::Snafu;

use crate::{
    error::Code,
    quic::{
        self,
        agent::{SignError, VerifyError},
    },
    varint::VarInt,
};

/// Error type for remote QUIC trait forwarding via remoc RTC.
///
/// This enum unifies QUIC stream/connection errors, agent signing/verification errors,
/// and remoc RTC call errors into a single serializable error type suitable for
/// transmission across remoc channels.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Snafu)]
#[snafu(visibility(pub))]
pub enum RemoteError {
    /// A QUIC stream-level error.
    #[snafu(transparent)]
    Stream { source: quic::StreamError },

    /// A QUIC connection-level error.
    #[snafu(transparent)]
    Connection { source: quic::ConnectionError },

    /// A signing operation failed.
    ///
    /// The original `rustls::Error` is not serde-serializable, so we store the
    /// string representation instead.
    #[snafu(display("signing error: {message}"))]
    Sign { message: String },

    /// A signature verification operation failed.
    #[snafu(display("verification error: {message}"))]
    Verify { message: String },

    /// A remoc RTC call failed.
    #[snafu(display("remoc call error: {message}"))]
    Call { message: String },
}

impl From<remoc::rtc::CallError> for RemoteError {
    fn from(err: remoc::rtc::CallError) -> Self {
        RemoteError::Call {
            message: err.to_string(),
        }
    }
}

impl From<SignError> for RemoteError {
    fn from(err: SignError) -> Self {
        RemoteError::Sign {
            message: err.to_string(),
        }
    }
}

impl From<VerifyError> for RemoteError {
    fn from(err: VerifyError) -> Self {
        RemoteError::Verify {
            message: err.to_string(),
        }
    }
}

impl RemoteError {
    /// Convert this error into a [`quic::StreamError`].
    ///
    /// - `Stream` variants are returned as-is.
    /// - `Connection` variants are wrapped in `StreamError::Connection`.
    /// - All other variants are mapped to a `StreamError::Reset` with `H3_INTERNAL_ERROR` (0x0102).
    pub fn into_stream_error(self) -> quic::StreamError {
        match self {
            RemoteError::Stream { source } => source,
            RemoteError::Connection { source } => quic::StreamError::Connection { source },
            _ => quic::StreamError::Reset {
                code: VarInt::from_u32(0x0102),
            },
        }
    }

    /// Convert this error into a [`quic::ConnectionError`].
    ///
    /// - `Connection` variants are returned as-is.
    /// - `Stream` variants containing a `ConnectionError` are unwrapped.
    /// - All other variants are mapped to a `ConnectionError::Application` with `H3_INTERNAL_ERROR` (0x0102).
    pub fn into_connection_error(self) -> quic::ConnectionError {
        match self {
            RemoteError::Connection { source } => source,
            RemoteError::Stream {
                source: quic::StreamError::Connection { source },
            } => source,
            _ => quic::ConnectionError::Application {
                source: quic::ApplicationError {
                    code: Code::new(VarInt::from_u32(0x0102)),
                    reason: Cow::Owned(self.to_string()),
                },
            },
        }
    }
}
