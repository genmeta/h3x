//! Application body handles, incoming-body driving, and HTTP/3 body framing.

use std::marker::PhantomData;

use bytes::Bytes;
use http::{Method, StatusCode};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use super::{Read, Write, headers, headers::ResponseHead};
use crate::{
    ArcWndBuf, ErrorCode, Result, Transport,
    protocol::{
        connection::H3Connection,
        frame::{self, Data, Frame, H3Frame, Write as _, be_frame},
        qpack::Qpack,
        stream::H3ReadStream,
    },
};

/// Application body storage, independent of message headers and network streams.
/// `B` is Bytes or WndBuf; `IO` is R (read) or W (write).
#[derive(Debug)]
pub struct Body<B, IO> {
    pub(crate) storage: B,
    _io: PhantomData<IO>,
}

impl<B, IO> Body<B, IO> {
    pub(crate) fn from_storage(storage: B) -> Self {
        Self {
            storage,
            _io: PhantomData,
        }
    }
}

impl<B: Default, IO> Default for Body<B, IO> {
    fn default() -> Self {
        Self::from_storage(B::default())
    }
}

impl<B: Clone> Clone for Body<B, Write> {
    fn clone(&self) -> Self {
        Self::from_storage(self.storage.clone())
    }
}

impl Body<Bytes, Write> {
    pub fn new(bytes: Bytes) -> Self {
        Self::from_storage(bytes)
    }
}

impl Body<ArcWndBuf, Write> {
    /// Panics if capacity is zero. One producer may be writing at a time.
    pub fn new(capacity: usize) -> Self {
        Self::from_storage(ArcWndBuf::new(capacity))
    }

    pub async fn write(&mut self, bytes: impl AsRef<[u8]> + Send) -> Result<usize> {
        Ok(self.storage.write(bytes.as_ref()).await?)
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.storage.write_all(bytes).await?;
        Ok(())
    }

    /// Finish production. The send future must still drain data and finish the transport.
    pub async fn finish(&mut self) -> Result<()> {
        self.storage.shutdown().await?;
        Ok(())
    }

    pub async fn reset(self) -> Result<()> {
        self.storage.set_error(ErrorCode::H3_REQUEST_CANCELLED);
        Ok(())
    }
}

impl Body<Bytes, Read> {
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        let remaining = &mut self.storage;
        let n = bytes.len().min(remaining.len());
        bytes[..n].copy_from_slice(&remaining.split_to(n));
        Ok(n)
    }

    pub fn into_bytes(self) -> Bytes {
        self.storage
    }

    pub async fn collect(self) -> Result<Bytes> {
        Ok(self.into_bytes())
    }
}

impl Body<ArcWndBuf, Read> {
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        Ok(self.storage.read(bytes).await?)
    }
    pub async fn stop(self) {
        self.storage.set_error(ErrorCode::H3_REQUEST_CANCELLED);
    }
    pub async fn collect(mut self) -> Result<Bytes> {
        let mut bytes = Vec::new();
        self.storage.read_to_end(&mut bytes).await?;
        Ok(bytes.into())
    }
}

/// Return a body window immediately and drive DATA, trailers, and FIN in the background.
pub(crate) fn receive<RS, T>(
    mut rs: BufReader<H3ReadStream<RS>>,
    mode: BodyMode,
    connection: H3Connection<T>,
) -> Body<ArcWndBuf, Read>
where
    RS: AsyncRead + Unpin + Send + 'static,
    T: Transport,
{
    let stream_id = rs.get_ref().stream_id();
    let mut buffer = ArcWndBuf::new(frame::MAX_DATA_CHUNK);
    let body = Body::from_storage(buffer.clone());
    let cancellation = buffer.clone();
    tokio::spawn(async move {
        let result = tokio::select! {
            biased;
            error = cancellation.error() => Err(error),
            result = read_body(&mut rs, &mut buffer, mode, connection.qpack()) => result,
        };
        if let Err(error) = result {
            let _ = connection.qpack().cancel(stream_id);
            connection.receive_error(error).await;
            buffer.set_error(error);
        }
        // read_body validates FIN/trailers and marks buffer EOF on success.
    });
    body
}

/// Content rules resolved from the message headers and request/response semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyMode {
    Forbidden,
    Infinity,
    Length { content_length: u64 },
}

impl BodyMode {
    /// Resolve body rules from final response headers and the request method.
    pub(crate) fn resolve(response: &ResponseHead, method: Option<&Method>) -> Result<Self> {
        let content_length = headers::content_length(&response.headers)?;
        let status = response.status()?;
        if method == Some(&Method::HEAD) {
            return Ok(Self::Forbidden);
        }
        if matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED) {
            return Ok(Self::Forbidden);
        }
        Ok(match content_length {
            Some(content_length) => Self::Length { content_length },
            None => Self::Infinity,
        })
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
pub(crate) async fn read_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    receive: &mut BufReader<H3ReadStream<R>>,
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
                    return Err(ErrorCode::H3_FRAME_UNEXPECTED);
                }
                let mut count = frame.length.into_u64();
                if let Some(left) = &mut remaining {
                    *left = left.checked_sub(count).ok_or(ErrorCode::H3_MESSAGE_ERROR)?;
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
                    return Err(ErrorCode::H3_FRAME_UNEXPECTED);
                }
                if remaining.is_some_and(|left| left != 0) {
                    return Err(ErrorCode::H3_MESSAGE_ERROR);
                }
                let fields = qpack
                    .decode(receive.get_ref().stream_id(), frame.payload.field_section)
                    .await?;
                headers::be_trailers(fields)?;
                trailers = true;
            }
            H3Frame::Unknown { length, .. } => {
                frame::skip_payload(receive, length.into_u64()).await?;
            }
            _ => {
                return Err(ErrorCode::H3_FRAME_UNEXPECTED);
            }
        }
    }
    if remaining.is_some_and(|left| left != 0) {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
    }
    destination.shutdown().await?;
    Ok(())
}

/// Send and validate a streaming body as DATA frames, leaving shutdown to the caller.
pub(crate) async fn write_streaming_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
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
            .ok_or(ErrorCode::H3_MESSAGE_ERROR)?;
        match mode {
            BodyMode::Forbidden if count != 0 => return Err(ErrorCode::H3_MESSAGE_ERROR),
            BodyMode::Length { content_length }
                if sent > content_length || (count == 0 && sent != content_length) =>
            {
                return Err(ErrorCode::H3_MESSAGE_ERROR);
            }
            _ => {}
        }
        if count == 0 {
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
    async fn streaming_body_leaves_shutdown_to_the_caller() {
        use std::{
            future::Future,
            task::{Context, Waker},
        };
        let (mut send, mut recv) = tokio::io::duplex(64);
        write_streaming_body(
            &mut &b"bc"[..],
            &mut send,
            BodyMode::Length { content_length: 2 },
        )
        .await
        .unwrap();
        assert!(matches!(
            be_frame(&mut recv).await.unwrap(),
            H3Frame::Data(_)
        ));
        let mut bytes = [0; 2];
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"bc");
        let mut reading = Box::pin(recv.read(&mut bytes));
        assert!(
            reading
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        send.shutdown().await.unwrap();
        assert_eq!(reading.await.unwrap(), 0);
    }

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
            (&[0x21, 0][..], Some(0), Ok(())),
            (&[][..], Some(1), Err(ErrorCode::H3_MESSAGE_ERROR)),
            (trailers.as_slice(), None, Err(ErrorCode::H3_FRAME_UNEXPECTED)),
            (&[0, 0][..], None, Err(ErrorCode::H3_FRAME_UNEXPECTED)),
            (&[0x21, 0, 0, 0][..], None, Err(ErrorCode::H3_FRAME_UNEXPECTED)),
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
                    crate::test_support::connection().qpack()
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
                crate::test_support::connection().qpack()
            )
            .await,
            Err(ErrorCode::H3_FRAME_UNEXPECTED)
        );
    }
}
