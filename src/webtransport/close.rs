use std::{convert::Infallible, error::Error as StdError, io, string::FromUtf8Error};

use bytes::Bytes;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    buflist::BufList,
    codec::{DecodeFrom, EncodeExt, EncodeInto},
};

const CLOSE_SESSION_MESSAGE_MAX_LEN: usize = 1024;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseSession {
    application_error_code: u32,
    message: CloseSessionMessage,
}

impl CloseSession {
    pub const fn new(application_error_code: u32, message: CloseSessionMessage) -> Self {
        Self {
            application_error_code,
            message,
        }
    }

    pub const fn application_error_code(&self) -> u32 {
        self.application_error_code
    }

    pub const fn message(&self) -> &CloseSessionMessage {
        &self.message
    }

    pub fn try_from_parts<C, M>(
        application_error_code: C,
        message: M,
    ) -> Result<Self, TryFromCloseSessionPartsError<C::Error, M::Error>>
    where
        C: TryInto<u32>,
        C::Error: StdError + Send + Sync + 'static,
        M: TryInto<CloseSessionMessage>,
        M::Error: StdError + Send + Sync + 'static,
    {
        let application_error_code = application_error_code
            .try_into()
            .context(try_from_close_session_parts_error::ApplicationErrorCodeSnafu)?;
        let message = message
            .try_into()
            .context(try_from_close_session_parts_error::MessageSnafu)?;
        Ok(Self {
            application_error_code,
            message,
        })
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseSessionMessage(String);

impl CloseSessionMessage {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CloseSessionMessage {
    type Error = CloseSessionMessageTooLong;

    fn try_from(message: String) -> Result<Self, Self::Error> {
        let len = message.len();
        if len > CLOSE_SESSION_MESSAGE_MAX_LEN {
            Err(CloseSessionMessageTooLong { len })
        } else {
            Ok(Self(message))
        }
    }
}

impl TryFrom<&str> for CloseSessionMessage {
    type Error = CloseSessionMessageTooLong;

    fn try_from(message: &str) -> Result<Self, Self::Error> {
        Self::try_from(message.to_owned())
    }
}

impl TryFrom<Bytes> for CloseSessionMessage {
    type Error = TryFromCloseSessionMessageBytesError;

    fn try_from(message: Bytes) -> Result<Self, Self::Error> {
        let message = String::from_utf8(message.to_vec())
            .context(try_from_close_session_message_bytes_error::Utf8Snafu)?;
        Ok(Self::try_from(message)?)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
#[snafu(display("webtransport close session message is {len} bytes, exceeding 1024 bytes"))]
pub struct CloseSessionMessageTooLong {
    len: usize,
}

impl CloseSessionMessageTooLong {
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Debug, Snafu)]
#[snafu(
    module(try_from_close_session_message_bytes_error),
    visibility(pub(super))
)]
pub enum TryFromCloseSessionMessageBytesError {
    #[snafu(display("webtransport close session message is not utf-8"))]
    Utf8 { source: FromUtf8Error },
    #[snafu(transparent)]
    TooLong { source: CloseSessionMessageTooLong },
}

#[derive(Debug, Snafu)]
#[snafu(module(try_from_close_session_parts_error), visibility(pub(super)))]
pub enum TryFromCloseSessionPartsError<C, M>
where
    C: StdError + Send + Sync + 'static,
    M: StdError + Send + Sync + 'static,
{
    #[snafu(display("invalid webtransport close session application error code"))]
    ApplicationErrorCode { source: C },
    #[snafu(display("invalid webtransport close session message"))]
    Message { source: M },
}

impl TryFrom<(u32, String)> for CloseSession {
    type Error = TryFromCloseSessionPartsError<Infallible, CloseSessionMessageTooLong>;

    fn try_from((application_error_code, message): (u32, String)) -> Result<Self, Self::Error> {
        Self::try_from_parts(application_error_code, message)
    }
}

impl<'m> TryFrom<(u32, &'m str)> for CloseSession {
    type Error = TryFromCloseSessionPartsError<Infallible, CloseSessionMessageTooLong>;

    fn try_from((application_error_code, message): (u32, &'m str)) -> Result<Self, Self::Error> {
        Self::try_from_parts(application_error_code, message)
    }
}

impl TryFrom<(u32, Bytes)> for CloseSession {
    type Error = TryFromCloseSessionPartsError<Infallible, TryFromCloseSessionMessageBytesError>;

    fn try_from((application_error_code, message): (u32, Bytes)) -> Result<Self, Self::Error> {
        Self::try_from_parts(application_error_code, message)
    }
}

#[derive(Debug, Snafu)]
#[snafu(module(decode_close_session_error), visibility(pub(super)))]
pub enum DecodeCloseSessionError {
    #[snafu(display("failed to decode webtransport close session application error code"))]
    ApplicationErrorCode { source: io::Error },
    #[snafu(display("failed to decode webtransport close session message"))]
    Message { source: io::Error },
    #[snafu(display("invalid webtransport close session message"))]
    InvalidMessage {
        source: TryFromCloseSessionMessageBytesError,
    },
}

impl<S> DecodeFrom<S> for CloseSession
where
    S: AsyncRead + Unpin + Send,
{
    type Error = DecodeCloseSessionError;

    async fn decode_from(mut stream: S) -> Result<Self, Self::Error> {
        let application_error_code = stream
            .read_u32()
            .await
            .context(decode_close_session_error::ApplicationErrorCodeSnafu)?;

        let mut message = Vec::new();
        stream
            .take((CLOSE_SESSION_MESSAGE_MAX_LEN + 1) as u64)
            .read_to_end(&mut message)
            .await
            .context(decode_close_session_error::MessageSnafu)?;
        let message = CloseSessionMessage::try_from(Bytes::from(message))
            .context(decode_close_session_error::InvalidMessageSnafu)?;

        Ok(Self::new(application_error_code, message))
    }
}

impl<'s, S> EncodeInto<&'s mut S> for CloseSession
where
    S: AsyncWrite + Unpin + Send,
{
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: &'s mut S) -> Result<Self::Output, Self::Error> {
        stream.write_u32(self.application_error_code()).await?;
        stream.write_all(self.message().as_str().as_bytes()).await?;
        Ok(())
    }
}

impl EncodeInto<BufList> for CloseSession {
    type Output = BufList;
    type Error = Infallible;

    async fn encode_into(self, mut stream: BufList) -> Result<Self::Output, Self::Error> {
        stream
            .encode_one(self)
            .await
            .expect("encoding CloseSession into a buflist is infallible");
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_session_message_rejects_message_above_1024_bytes() {
        let message = "x".repeat(1025);
        let error = CloseSessionMessage::try_from(message).expect_err("too long");
        assert_eq!(error.len(), 1025);
    }

    #[test]
    fn close_session_try_from_tuple_preserves_parts() {
        let close = CloseSession::try_from((7_u32, "done")).expect("valid close");
        assert_eq!(close.application_error_code(), 7);
        assert_eq!(close.message().as_str(), "done");
    }
}
