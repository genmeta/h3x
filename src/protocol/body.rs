//! Transfer body bytes between application buffers and HTTP/3 frames.

use http::{Method, StatusCode};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use super::{
    frame::{self, Data, Frame, H3Frame, Write as _, be_frame},
    headers,
    qpack::Qpack,
    stream::H3ReadStream,
};
use crate::{Error, Result};

/// Content rules resolved from the message headers and request/response semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyMode {
    Forbidden,
    Infinity,
    Length { content_length: u64 },
}

impl BodyMode {
    /// Resolve body rules from final response headers and the request method.
    pub(crate) fn resolve(
        response: &http::response::Parts,
        method: Option<&Method>,
    ) -> Result<Self> {
        let content_length = headers::content_length(&response.headers)?;
        if method == Some(&Method::HEAD) {
            return Ok(Self::Forbidden);
        }
        if matches!(
            response.status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        ) {
            return Ok(Self::Forbidden);
        }
        Ok(match content_length {
            Some(content_length) => Self::Length { content_length },
            None => Self::Infinity,
        })
    }

    /// Whether to receive the body as Streaming; otherwise use Bytes.
    /// Unknown lengths and lengths exceeding the buffering limit use Streaming.
    pub(crate) fn streaming(self) -> bool {
        match self {
            Self::Forbidden => false,
            Self::Infinity => true,
            Self::Length { content_length } => {
                content_length > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64
            }
        }
    }

    pub(crate) fn content_length(self) -> Option<u64> {
        match self {
            Self::Forbidden | Self::Infinity => None,
            Self::Length { content_length } => Some(content_length),
        }
    }

    pub(crate) fn is_forbidden(self) -> bool {
        matches!(self, Self::Forbidden)
    }
}

/// Receive DATA into an application destination and validate trailing HEADERS.
/// QPACK is used only to decode trailers. The destination is shut down at EOF.
pub(crate) async fn read_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin, RW>(
    receive: &mut BufReader<H3ReadStream<R, RW>>,
    destination: &mut W,
    mode: BodyMode,
    qpack: &Qpack,
) -> Result<()> {
    let mut remaining = mode.content_length();
    let mut trailers = false;
    let mut buf = vec![0; frame::MAX_DATA_CHUNK];
    while !receive.fill_buf().await?.is_empty() {
        match be_frame(receive).await? {
            H3Frame::Data(frame) => {
                if trailers || mode.is_forbidden() {
                    return Err(Error::H3_FRAME_UNEXPECTED);
                }
                let mut count = frame.length.into_u64();
                if let Some(left) = &mut remaining {
                    *left = left.checked_sub(count).ok_or(Error::H3_MESSAGE_ERROR)?;
                }
                while count != 0 {
                    let chunk = count.min(buf.len() as u64) as usize;
                    receive.read_exact(&mut buf[..chunk]).await?;
                    destination.write_all(&buf[..chunk]).await?;
                    count -= chunk as u64;
                }
            }
            H3Frame::Headers(frame) => {
                if trailers || mode.is_forbidden() {
                    return Err(Error::H3_FRAME_UNEXPECTED);
                }
                if remaining.is_some_and(|left| left != 0) {
                    return Err(Error::H3_MESSAGE_ERROR);
                }
                headers::trailer_fields(frame.decode(qpack, receive.get_ref().stream_id()).await?)?;
                trailers = true;
            }
            _ => {
                return Err(Error::H3_FRAME_UNEXPECTED);
            }
        }
    }
    if remaining.is_some_and(|left| left != 0) {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    destination.shutdown().await?;
    Ok(())
}

/// Send an application source as DATA frames and shut down the send stream at EOF.
pub(crate) async fn write_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    source: &mut R,
    send: &mut W,
    mode: BodyMode,
) -> Result<()> {
    let mut buf = vec![0; frame::MAX_DATA_CHUNK];
    let mut sent = 0u64;
    loop {
        let count = source.read(&mut buf).await?;
        sent = sent
            .checked_add(count as u64)
            .ok_or(Error::H3_MESSAGE_ERROR)?;
        let invalid = match mode {
            BodyMode::Forbidden => count != 0,
            BodyMode::Infinity => false,
            BodyMode::Length { content_length } => {
                sent > content_length || (count == 0 && sent != content_length)
            }
        };
        if invalid {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        if count == 0 {
            send.shutdown().await?;
            return Ok(());
        }
        let mut frame = Vec::new();
        frame.put_frame(&Frame::new(Data(count))?);
        send.write_all(&frame).await?;
        send.write_all(&buf[..count]).await?;
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::protocol::{
        frame::Headers,
        qpack::{self, WriteFieldSection},
    };

    #[tokio::test]
    async fn body_trailers_enforce_order_and_content_length() {
        let mut trailers = Vec::new();
        let mut field_section = Vec::new();
        field_section
            .put_field_section(vec![qpack::Field {
                never_index: false,
                name: Bytes::from_static(b"x-checksum"),
                value: Bytes::from_static(b"ok"),
            }])
            .unwrap();
        trailers.put_frame(
            &Frame::new(Headers {
                field_section: field_section.into(),
            })
            .unwrap(),
        );
        for (suffix, length, expected) in [
            (&[][..], None, Ok(())),
            (&[][..], Some(0), Ok(())),
            (&[][..], Some(1), Err(Error::H3_MESSAGE_ERROR)),
            (trailers.as_slice(), None, Err(Error::H3_FRAME_UNEXPECTED)),
            (&[0, 0][..], None, Err(Error::H3_FRAME_UNEXPECTED)),
        ] {
            let encoded = [trailers.as_slice(), suffix].concat();
            let mut input = encoded.as_slice();
            let mut body = Vec::new();
            assert_eq!(
                read_body(
                    &mut BufReader::new(H3ReadStream::new(0, &mut input)),
                    &mut body,
                    match length {
                        Some(content_length) => BodyMode::Length { content_length },
                        None => BodyMode::Infinity,
                    },
                    &Qpack::default()
                )
                .await,
                expected
            );
            assert!(body.is_empty());
        }
        let mut input = &[7, 1, 0][..]; // GOAWAY is forbidden in a message body.
        let mut body = Vec::new();
        assert_eq!(
            read_body(
                &mut BufReader::new(H3ReadStream::new(0, &mut input)),
                &mut body,
                BodyMode::Infinity,
                &Qpack::default()
            )
            .await,
            Err(Error::H3_FRAME_UNEXPECTED)
        );
    }
}
