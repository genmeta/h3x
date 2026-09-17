//! Application body handles, incoming-body driving, and HTTP/3 body framing.
use std::marker::PhantomData;

use bytes::Bytes;
use http::{Method, StatusCode};
use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use super::{Read, Write, head, head::ResponseHead};
use crate::{
    ArcWndBuf, ErrorCode, Result,
    protocol::{
        frame::{self, Data, Frame, FrameType, H3Frame, Write as _},
        qpack::ArcQpack,
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
    pub fn new(storage: B) -> Self {
        Self {
            storage,
            _io: PhantomData,
        }
    }
}

impl<B: Default, IO> Default for Body<B, IO> {
    fn default() -> Self {
        Self::new(B::default())
    }
}

impl<B: Clone> Clone for Body<B, Write> {
    fn clone(&self) -> Self {
        Self::new(self.storage.clone())
    }
}

impl Body<ArcWndBuf, Write> {
    /// Panics if capacity is zero. One producer may be writing at a time.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(ArcWndBuf::new(capacity))
    }

    pub async fn write(&mut self, bytes: impl AsRef<[u8]> + Send) -> Result<usize> {
        Ok(self.storage.write(bytes.as_ref()).await?)
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.storage.write_all(bytes).await?;
        Ok(())
    }

    /// Finish production. The request's upload task still drains data and finishes the transport.
    pub async fn finish(&mut self) -> Result<()> {
        self.storage.shutdown().await?;
        Ok(())
    }

    pub async fn reset(self) -> Result<()> {
        self.storage
            .on_error(ErrorCode::H3_REQUEST_CANCELLED.reason("request cancelled"));
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

impl AsyncRead for Body<Bytes, Read> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let storage = &mut self.get_mut().storage;
        let count = output.remaining().min(storage.len());
        output.put_slice(&storage.split_to(count));
        std::task::Poll::Ready(Ok(()))
    }
}

impl Body<ArcWndBuf, Read> {
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        Ok(self.storage.read(bytes).await?)
    }

    pub async fn stop(self) {
        self.storage
            .on_error(ErrorCode::H3_REQUEST_CANCELLED.reason("request cancelled"));
    }

    pub async fn collect(mut self) -> Result<Bytes> {
        let mut bytes = Vec::new();
        self.storage.read_to_end(&mut bytes).await?;
        Ok(bytes.into())
    }
}

// Directional bodies can be passed to Tokio copy helpers and application codecs.
impl AsyncRead for Body<ArcWndBuf, Read> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().storage).poll_read(cx, output)
    }
}

impl AsyncWrite for Body<ArcWndBuf, Write> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        input: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().storage).poll_write(cx, input)
    }

    /// Flush exposes bytes to the upload task; it does not await transport delivery.
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().storage).poll_flush(cx)
    }

    /// Finish production; the upload task drains the buffer before sending FIN.
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().storage).poll_shutdown(cx)
    }
}

/// Return a body window immediately and drive DATA, trailers, and FIN in the background.
pub(crate) fn receive<RS>(
    mut rs: H3ReadStream<RS>,
    mode: BodyMode,
    qpack: ArcQpack,
) -> Body<ArcWndBuf, Read>
where
    RS: AsyncRead + StopSending + Unpin + Send + 'static,
{
    let mut buffer = ArcWndBuf::new(frame::MAX_DATA_CHUNK);
    let body = Body::new(buffer.clone());
    tokio::spawn(async move {
        let cancellation = buffer.clone();
        let result = tokio::select! {
            biased;
            error = cancellation.wait_error() => Err(error),
            result = read_body(&mut rs, &mut buffer, mode, &qpack) => result,
        };
        if let Err(error) = &result {
            super::receive_error(&rs, &qpack, error);
            buffer.on_error(error.clone());
        }
        // read_body validates FIN/trailers and marks buffer EOF on success.
    });
    body
}

/// Content rules resolved from the message headers and request/response semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyMode {
    Forbidden,
    UnspecifiedLength,
    /// CONNECT DATA has no Content-Length or trailing HEADERS.
    Connect,
    Length {
        content_length: u64,
    },
}

impl BodyMode {
    /// Validate an outgoing final response and resolve its body framing.
    pub(crate) fn resolve(response: &ResponseHead, method: Option<&Method>) -> Result<Self> {
        let status = response.response_status()?;
        if status.is_informational() {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .reason("a final response cannot use an informational status"));
        }
        if method == Some(&Method::CONNECT) && status.is_success() {
            if response.headers.contains_key(http::header::CONTENT_LENGTH) {
                return Err(ErrorCode::H3_MESSAGE_ERROR
                    .reason("successful CONNECT must not include Content-Length"));
            }
            return Ok(Self::Connect);
        }
        if status == StatusCode::NO_CONTENT
            && response.headers.contains_key(http::header::CONTENT_LENGTH)
        {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.reason("204 response must not include Content-Length")
            );
        }
        let content_length = head::content_length(&response.headers)?;
        Ok(Self::from_parts(status, method, content_length))
    }

    /// Resolve ordinary body framing from already validated metadata.
    pub(crate) fn from_parts(
        status: StatusCode,
        method: Option<&Method>,
        content_length: Option<u64>,
    ) -> Self {
        if method == Some(&Method::HEAD) {
            return Self::Forbidden;
        }
        if matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED) {
            return Self::Forbidden;
        }
        match content_length {
            Some(content_length) => Self::Length { content_length },
            None => Self::UnspecifiedLength,
        }
    }

    pub(crate) fn content_length(self) -> Option<u64> {
        match self {
            Self::Forbidden | Self::UnspecifiedLength | Self::Connect => None,
            Self::Length { content_length } => Some(content_length),
        }
    }

    pub(crate) fn is_forbidden(self) -> bool {
        matches!(self, Self::Forbidden)
    }
}

/// Receive DATA into an application destination and validate trailing HEADERS.
/// QPACK is used only to decode trailers. The destination is shut down at EOF.
pub(crate) async fn read_body<R: AsyncRead + StopSending + Unpin, W: AsyncWrite + Unpin>(
    read_stream: &mut H3ReadStream<R>,
    body: &mut W,
    mode: BodyMode,
    qpack: &ArcQpack,
) -> Result<()> {
    // Body reception owns buffering until FIN; callers pass the stream directly.
    let mut reader = BufReader::new(read_stream);
    let read_stream = &mut reader;
    let mut remaining = mode.content_length();
    let mut trailers = false;
    let mut frames = 0;
    while let Some(ty) = frame::be_frame_type(read_stream).await? {
        frames += 1;
        if frames == 64 {
            frames = 0;
            tokio::task::yield_now().await;
        }
        let allowed = match ty {
            FrameType::Unknown(_) => true,
            FrameType::Data => !trailers && !mode.is_forbidden(),
            FrameType::Headers => !trailers && !mode.is_forbidden() && mode != BodyMode::Connect,
            _ => false,
        };
        if !allowed {
            return Err(ErrorCode::H3_FRAME_UNEXPECTED
                .reason("frame is not allowed in the current body or trailer state"));
        }
        let length = frame::be_frame_length(read_stream).await?;
        let frame = frame::be_frame_payload(read_stream, ty, length).await?;
        match frame {
            H3Frame::Data(frame) => {
                let count = frame.length.into_u64();
                if let Some(left) = &mut remaining {
                    *left = left.checked_sub(count).ok_or_else(|| {
                        ErrorCode::H3_MESSAGE_ERROR
                            .reason("DATA exceeds the remaining Content-Length")
                    })?;
                }
                let mut payload = (&mut *read_stream).take(count);
                tokio::io::copy_buf(&mut payload, body).await?;
                if payload.limit() != 0 {
                    return Err(ErrorCode::H3_FRAME_ERROR
                        .reason("DATA payload ended before the declared frame length"));
                }
            }
            H3Frame::Headers(frame) => {
                if remaining.is_some_and(|left| left != 0) {
                    return Err(ErrorCode::H3_MESSAGE_ERROR
                        .reason("trailers arrived before Content-Length bytes were received"));
                }
                let fields = qpack
                    .decode(
                        read_stream.get_ref().stream_id(),
                        frame.payload.field_section,
                    )
                    .await?;
                head::be_trailers(fields)?;
                trailers = true;
            }
            H3Frame::Unknown { length, .. } => {
                frame::skip_payload(read_stream, length.into_u64()).await?;
            }
            _ => {
                return Err(ErrorCode::H3_FRAME_UNEXPECTED
                    .reason("frame is not allowed in the current body or trailer state"));
            }
        }
    }
    if remaining.is_some_and(|left| left != 0) {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .reason("body ended before Content-Length bytes were received"));
    }
    body.shutdown().await?;
    Ok(())
}

/// Write a nonempty buffered body as one DATA frame, leaving shutdown to the caller.
pub(crate) async fn write_bytes_body<W: AsyncWrite + Unpin>(
    body: &[u8],
    send: &mut W,
) -> Result<()> {
    if body.is_empty() {
        return Ok(());
    }
    let mut buf = Vec::new();
    buf.put_frame(&Frame::new(Data(body.len()))?);
    send.write_all(&buf).await?;
    for chunk in body.chunks(frame::MAX_DATA_CHUNK) {
        send.write_all(chunk).await?;
    }
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
            .ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.reason("sent body length overflowed u64"))?;
        match mode {
            BodyMode::Forbidden if count != 0 => {
                return Err(ErrorCode::H3_MESSAGE_ERROR.reason("response semantics forbid a body"));
            }
            BodyMode::Length { content_length }
                if sent > content_length || (count == 0 && sent != content_length) =>
            {
                return Err(ErrorCode::H3_MESSAGE_ERROR
                    .reason("streamed body length does not match Content-Length"));
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
        send.flush().await?;
    }
}
