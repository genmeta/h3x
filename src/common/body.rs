//! Application body handles and HTTP/3 body framing.
use std::{
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{Method, StatusCode};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};

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
/// `IO` is Read or Write; `B` is Bytes or ArcWndBuf, as in Request and Response.
#[derive(Debug)]
pub struct Body<IO, B> {
    pub(crate) storage: B,
    _io: PhantomData<IO>,
}

impl<IO, B> Body<IO, B> {
    pub fn new(storage: B) -> Self {
        Self {
            storage,
            _io: PhantomData,
        }
    }
}

impl<IO, B: Default> Default for Body<IO, B> {
    fn default() -> Self {
        Self::new(B::default())
    }
}

impl<B: Clone> Clone for Body<Write, B> {
    fn clone(&self) -> Self {
        Self::new(self.storage.clone())
    }
}

impl<B> Body<Read, B>
where
    Self: AsyncRead + Unpin,
{
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        Ok(AsyncReadExt::read(self, bytes).await?)
    }
}

impl Body<Read, Bytes> {
    pub async fn collect(self) -> Result<Bytes> {
        Ok(self.storage)
    }
}

impl AsyncRead for Body<Read, Bytes> {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let storage = &mut self.get_mut().storage;
        let count = output.remaining().min(storage.len());
        output.put_slice(&storage.split_to(count));
        Poll::Ready(Ok(()))
    }
}

impl Body<Read, ArcWndBuf> {
    pub async fn collect(mut self) -> Result<Bytes> {
        let mut bytes = Vec::new();
        self.storage.read_to_end(&mut bytes).await?;
        Ok(bytes.into())
    }

    /// Return a body window immediately and drive DATA, trailers, and FIN in the background.
    pub(crate) fn receive<RS>(mut rs: H3ReadStream<RS>, mode: ContentType, qpack: ArcQpack) -> Self
    where
        RS: AsyncRead + StopSending + Unpin + Send + 'static,
    {
        let mut buffer = ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        let body = Self::new(buffer.clone());
        tokio::spawn(async move {
            let cancellation = buffer.clone();
            let result = tokio::select! {
                biased;
                error = cancellation.wait_error() => {
                    rs.stop(error.code.as_u64());
                    let _ = qpack.cancel(rs.stream_id());
                    return;
                },
                result = Self::decode(&mut rs, &mut buffer, mode, &qpack) => result,
            };
            if let Err(error) = &result {
                crate::error::receive_error(&rs, &qpack, error);
                buffer.on_error(error.clone());
            }
            // decode validates FIN/trailers and marks buffer EOF on success.
        });
        body
    }

    /// Receive DATA into an application destination and validate trailing HEADERS.
    /// QPACK is used only to decode trailers. The destination is shut down at EOF.
    async fn decode<R: AsyncRead + StopSending + Unpin, W: AsyncWrite + Unpin>(
        read_stream: &mut H3ReadStream<R>,
        body: &mut W,
        mode: ContentType,
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
                FrameType::Headers => {
                    !trailers && !mode.is_forbidden() && mode != ContentType::Connect
                }
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
                    head::Trailers::decode(fields)?;
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
}

// Directional bodies can be passed to Tokio copy helpers and application codecs.
impl AsyncRead for Body<Read, ArcWndBuf> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().storage).poll_read(cx, output)
    }
}

impl Body<Write, ArcWndBuf> {
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

    /// Send and validate a streaming body as DATA frames, leaving shutdown to the caller.
    pub(crate) async fn encode<W: AsyncWrite + Unpin>(
        &mut self,
        send: &mut W,
        mode: ContentType,
    ) -> Result<()> {
        let mut buf = vec![0; frame::MAX_DATA_CHUNK];
        let mut sent = 0u64;
        loop {
            let count = self.storage.read(&mut buf).await?;
            sent = sent.checked_add(count as u64).ok_or_else(|| {
                ErrorCode::H3_MESSAGE_ERROR.reason("sent body length overflowed u64")
            })?;
            match mode {
                ContentType::NoContent if count != 0 => {
                    return Err(
                        ErrorCode::H3_MESSAGE_ERROR.reason("response semantics forbid a body")
                    );
                }
                ContentType::Length { content_length }
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
            Body::<Write, _>::new(&buf[..count]).encode(send).await?;
            send.flush().await?;
        }
    }
}

impl AsyncWrite for Body<Write, ArcWndBuf> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().storage).poll_write(cx, input)
    }

    /// Flush exposes bytes to the upload task; it does not await transport delivery.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().storage).poll_flush(cx)
    }

    /// Finish production; the upload task drains the buffer before sending FIN.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().storage).poll_shutdown(cx)
    }
}

/// Content rules resolved from the message headers and request/response semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContentType {
    NoContent,
    Streaming,
    Connect,
    Length { content_length: u64 },
}

impl ContentType {
    /// Validate request metadata and resolve its body framing.
    pub(crate) fn from_request(head: &head::RequestHead) -> Result<Self> {
        let length = head.content_length()?;
        Ok(if head.request_method() == Method::CONNECT {
            if length.is_some() {
                return Err(
                    ErrorCode::H3_MESSAGE_ERROR.reason("CONNECT must not include Content-Length")
                );
            }
            Self::Connect
        } else {
            match length {
                Some(content_length) => Self::Length { content_length },
                None => Self::Streaming,
            }
        })
    }

    /// Validate an outgoing final response and resolve its body framing.
    pub(crate) fn from_response(response: &ResponseHead, method: Option<&Method>) -> Result<Self> {
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
        let content_length = response.content_length()?;
        Ok(Self::from_parts(status, method, content_length))
    }

    /// Resolve received response framing, including informational responses.
    /// Successful CONNECT ignores Content-Length on reception.
    pub(crate) fn from_received_response(
        response: &ResponseHead,
        method: Option<&Method>,
    ) -> Result<Self> {
        let status = response.response_status()?;
        if status == StatusCode::SWITCHING_PROTOCOLS {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("status 101 is forbidden in HTTP/3"));
        }
        if method == Some(&Method::CONNECT) && status.is_success() {
            return Ok(Self::Connect);
        }
        if (status.is_informational() || status == StatusCode::NO_CONTENT)
            && response.headers.contains_key(http::header::CONTENT_LENGTH)
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .reason("informational and 204 responses must not include Content-Length"));
        }
        if status.is_informational() {
            return Ok(Self::NoContent);
        }
        Ok(Self::from_parts(status, method, response.content_length()?))
    }

    /// Resolve ordinary body framing from already validated metadata.
    fn from_parts(
        status: StatusCode,
        method: Option<&Method>,
        content_length: Option<u64>,
    ) -> Self {
        if method == Some(&Method::HEAD) {
            return Self::NoContent;
        }
        if matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED) {
            return Self::NoContent;
        }
        match content_length {
            Some(content_length) => Self::Length { content_length },
            None => Self::Streaming,
        }
    }

    pub(crate) fn content_length(self) -> Option<u64> {
        match self {
            Self::NoContent | Self::Streaming | Self::Connect => None,
            Self::Length { content_length } => Some(content_length),
        }
    }

    pub(crate) fn is_forbidden(self) -> bool {
        matches!(self, Self::NoContent)
    }
}

impl<B: AsRef<[u8]>> Body<Write, B> {
    /// Encode nonempty bytes as one DATA frame, leaving shutdown to the caller.
    pub(crate) async fn encode<W: AsyncWrite + Unpin>(&self, send: &mut W) -> Result<()> {
        let body = self.storage.as_ref();
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
}

impl StopSending for Body<Read, Bytes> {
    fn stop(&mut self, _: u64) {}
}

impl StopSending for &Body<Read, ArcWndBuf> {
    fn stop(&mut self, error_code: u64) {
        self.storage.cancel(error_code);
    }
}

impl StopSending for Body<Read, ArcWndBuf> {
    fn stop(&mut self, error_code: u64) {
        (&*self).stop(error_code);
    }
}

impl CancelStream for &Body<Write, ArcWndBuf> {
    fn cancel(&mut self, error_code: u64) {
        self.storage.cancel(error_code);
    }
}

impl CancelStream for Body<Write, ArcWndBuf> {
    fn cancel(&mut self, error_code: u64) {
        (&*self).cancel(error_code);
    }
}

impl Body<Write, Bytes> {
    /// Validate buffered content before sending HEADERS.
    pub(crate) fn validate(&self, mode: ContentType) -> Result<()> {
        if mode == ContentType::Connect {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("CONNECT requires a streaming body"));
        }
        if mode.is_forbidden() && !self.storage.is_empty() {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("message semantics forbid a body"));
        }
        if mode
            .content_length()
            .is_some_and(|length| length != self.storage.len() as u64)
        {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.reason("body length does not match Content-Length")
            );
        }
        Ok(())
    }
}
