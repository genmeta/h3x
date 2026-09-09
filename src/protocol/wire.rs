pub(crate) mod frame;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use dquic::prelude::{StreamReader, StreamWriter};
pub(crate) use frame::{Frame, FrameHeader, FrameType, WriteFrame};
use futures::{SinkExt, future::poll_fn};
use qbase::varint::{VarInt, be_varint};

use crate::{Code, Error, transport};

pub(crate) const MAX_BUFFERED_FRAME_PAYLOAD: usize = 64 * 1024;
pub(crate) const MAX_DATA_CHUNK: usize = 16 * 1024;
/// Preserves transport chunk boundaries without copying DATA into an accumulator.
pub(crate) struct ChunkReader {
    #[cfg(feature = "webtransport")]
    id: crate::StreamId,
    stream: StreamReader,
    pending: Bytes,
    tail: Bytes,
    ended: bool,
    ready_reads: u8,
    stop_code: Code,
}

impl ChunkReader {
    pub(crate) fn new(_id: crate::StreamId, stream: StreamReader) -> Self {
        Self {
            #[cfg(feature = "webtransport")]
            id: _id,
            stream,
            pending: Bytes::new(),
            tail: Bytes::new(),
            ended: false,
            ready_reads: 0,
            stop_code: Code::H3_REQUEST_CANCELLED,
        }
    }

    pub(crate) fn stop(&mut self, code: Code) -> Result<(), Error> {
        self.ended = true;
        self.pending = Bytes::new();
        self.tail = Bytes::new();
        dquic::prelude::StopSending::stop(&mut self.stream, code.as_u64());
        Ok(())
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn stream_id(&self) -> crate::StreamId {
        self.id
    }

    fn poll_parse<T>(
        &mut self,
        cx: &mut Context<'_>,
        parser: &mut impl for<'a> FnMut(&'a Bytes) -> frame::ParseResult<'a, T>,
        limit: usize,
    ) -> Poll<Result<Option<T>, Error>> {
        loop {
            if self.ready_reads == 64 {
                self.ready_reads = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.ready_reads += 1;
            let needed = match parser(&self.pending) {
                Ok((remaining, value)) => {
                    let consumed = self.pending.len() - remaining.len();
                    self.pending.advance(consumed);
                    return Poll::Ready(Ok(Some(value)));
                }
                Err(nom::Err::Incomplete(needed)) => needed,
                Err(nom::Err::Error(error) | nom::Err::Failure(error)) => {
                    return Poll::Ready(Err(error));
                }
            };
            if self.ended && self.tail.is_empty() {
                return Poll::Ready(if self.pending.is_empty() {
                    Ok(None)
                } else {
                    Err(frame_error("incomplete HTTP/3 input"))
                });
            }
            let needed = match needed {
                nom::Needed::Size(size) => size.get(),
                nom::Needed::Unknown => 1,
            };
            if needed > limit.saturating_sub(self.pending.len()) {
                return Poll::Ready(Err(excessive_load(
                    "buffered input exceeds implementation limit",
                )));
            }
            if self.tail.is_empty() {
                match Pin::new(&mut self.stream).poll_next(cx) {
                    Poll::Ready(Some(Ok(bytes))) => self.tail = bytes,
                    Poll::Ready(Some(Err(error))) => {
                        self.ended = true;
                        return Poll::Ready(Err(map_stream_error(error)));
                    }
                    Poll::Ready(None) => self.ended = true,
                    Poll::Pending => {
                        self.ready_reads = 0;
                        return Poll::Pending;
                    }
                }
            }
            if self.pending.is_empty() {
                self.pending = std::mem::take(&mut self.tail);
            } else if !self.tail.is_empty() {
                // Only join the missing prefix. Keep later DATA in its transport allocation.
                let take = needed.min(self.tail.len());
                let mut prefix = std::mem::take(&mut self.pending)
                    .try_into_mut()
                    .unwrap_or_else(|bytes| BytesMut::from(bytes.as_ref()));
                prefix.extend_from_slice(&self.tail.split_to(take));
                self.pending = prefix.freeze();
            }
        }
    }

    /// Retry an incomplete parser without consuming its input or copying subsequent DATA.
    async fn read<T>(
        &mut self,
        mut parser: impl for<'a> FnMut(&'a Bytes) -> frame::ParseResult<'a, T>,
        limit: usize,
    ) -> Result<Option<T>, Error> {
        poll_fn(|cx| self.poll_parse(cx, &mut parser, limit)).await
    }

    fn poll_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max: usize,
    ) -> Poll<Result<Option<Bytes>, Error>> {
        self.poll_parse(cx, &mut |input| frame::be_payload_chunk(input, max), max)
    }

    /// Raw QPACK and WebTransport bytes, including any unconsumed prefix chunk.
    pub(crate) async fn read_chunk(&mut self) -> Result<Option<Bytes>, Error> {
        self.read(
            |input| frame::be_payload_chunk(input, usize::MAX),
            usize::MAX,
        )
        .await
    }

    /// None means clean EOF; a partial integer at EOF is an error.
    pub(crate) async fn read_varint(&mut self) -> Result<Option<u64>, Error> {
        self.read(
            |input| {
                be_varint(input)
                    .map(|(remaining, value)| (remaining, value.into_u64()))
                    .map_err(|error| error.map(|_| frame_error("invalid QUIC varint")))
            },
            VarInt::MAX_SIZE,
        )
        .await
    }
}

impl Drop for ChunkReader {
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.stop(self.stop_code);
        }
    }
}

impl futures::Stream for ChunkReader {
    type Item = Result<Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_chunk(cx, usize::MAX).map(Result::transpose)
    }
}

/// HTTP frame envelope; DATA is consumed separately and never aggregated.
pub(crate) struct FrameReader {
    input: ChunkReader,
    remaining: u64,
}

impl FrameReader {
    pub(crate) fn new(input: ChunkReader) -> Self {
        Self {
            input,
            remaining: 0,
        }
    }

    pub(crate) fn stop(&mut self, code: Code) -> Result<(), Error> {
        self.input.stop(code)
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.remaining
    }

    pub(crate) async fn next_header(&mut self) -> Result<Option<FrameHeader>, Error> {
        assert_eq!(
            self.remaining, 0,
            "consume the previous frame payload first"
        );
        let header = self
            .input
            .read(|input| frame::be_frame_header(input), 2 * VarInt::MAX_SIZE)
            .await?;
        if let Some(header) = header {
            self.remaining = header.length;
        }
        Ok(header)
    }

    pub(crate) async fn next_type(&mut self) -> Result<Option<u64>, Error> {
        assert_eq!(
            self.remaining, 0,
            "consume the previous frame payload first"
        );
        self.input.read_varint().await
    }

    pub(crate) async fn header_after_type(
        &mut self,
        frame_type: u64,
    ) -> Result<FrameHeader, Error> {
        let length = self
            .input
            .read_varint()
            .await?
            .ok_or_else(|| frame_error("missing frame length"))?;
        self.remaining = length;
        Ok(FrameHeader {
            frame_type: frame_type.into(),
            length,
        })
    }

    /// Apply a parser only to this frame's remaining payload. Incomplete input is retried;
    /// an incomplete value at the declared frame boundary is a malformed frame.
    pub(crate) async fn read<T>(
        &mut self,
        mut parser: impl for<'a> FnMut(&'a Bytes) -> frame::ParseResult<'a, T>,
    ) -> Result<T, Error> {
        let remaining = self.remaining;
        let (consumed, value) = self
            .input
            .read(
                |input| {
                    let payload = input.slice(
                        ..input
                            .len()
                            .min(usize::try_from(remaining).unwrap_or(usize::MAX)),
                    );
                    match parser(&payload) {
                        Ok((rest, value)) => {
                            let consumed = payload.len() - rest.len();
                            Ok((&input[consumed..], (consumed, value)))
                        }
                        Err(nom::Err::Incomplete(_)) if payload.len() as u64 == remaining => Err(
                            nom::Err::Failure(frame_error("incomplete value at frame boundary")),
                        ),
                        Err(error) => Err(error),
                    }
                },
                MAX_BUFFERED_FRAME_PAYLOAD,
            )
            .await?
            .ok_or_else(|| frame_error("incomplete HTTP/3 frame payload"))?;
        self.remaining -= consumed as u64;
        Ok(value)
    }

    pub(crate) async fn discard_payload(&mut self) -> Result<(), Error> {
        while self.remaining != 0 {
            self.read(|input| frame::be_payload_chunk(input, MAX_DATA_CHUNK))
                .await?;
        }
        Ok(())
    }
}

fn excessive_load(message: &'static str) -> Error {
    Error::connection_protocol(Code::H3_EXCESSIVE_LOAD, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamType {
    Control,
    Push,
    QpackEncoder,
    QpackDecoder,
    #[cfg(feature = "webtransport")]
    WebTransport,
    Unknown(u64),
}

impl From<u64> for StreamType {
    fn from(value: u64) -> Self {
        match value {
            0x00 => Self::Control,
            0x01 => Self::Push,
            0x02 => Self::QpackEncoder,
            0x03 => Self::QpackDecoder,
            #[cfg(feature = "webtransport")]
            0x54 => Self::WebTransport,
            _ => Self::Unknown(value),
        }
    }
}

impl From<StreamType> for u64 {
    fn from(value: StreamType) -> Self {
        match value {
            StreamType::Control => 0x00,
            StreamType::Push => 0x01,
            StreamType::QpackEncoder => 0x02,
            StreamType::QpackDecoder => 0x03,
            #[cfg(feature = "webtransport")]
            StreamType::WebTransport => 0x54,
            StreamType::Unknown(value) => value,
        }
    }
}

#[cfg(feature = "webtransport")]
pub(crate) const WEBTRANSPORT_BIDI_SIGNAL: u64 = 0x41;

fn frame_error(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::connection_protocol(Code::H3_FRAME_ERROR, message)
}

pub(crate) fn map_stream_error(error: impl Into<transport::StreamError>) -> Error {
    let error = error.into();
    let code = error.code();
    if error.is_connection() {
        Error::connection(code, "QUIC connection failed while reading a stream", error)
    } else {
        Error::stream_with_source(code, "QUIC stream was reset", error)
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) use crate::test_streams::fuzz_frame;

/// Header and payload are separate Sink items; DATA retains its Bytes allocation.
pub(crate) async fn write_frame(
    writer: &mut StreamWriter,
    kind: FrameType,
    payload: Bytes,
) -> Result<(), Error> {
    let mut header = Vec::with_capacity(16);
    WriteFrame::put_frame(
        &mut header,
        &FrameHeader {
            frame_type: kind,
            length: payload.len() as u64,
        },
    )?;
    writer
        .feed(Bytes::from(header))
        .await
        .map_err(map_stream_error)?;
    if !payload.is_empty() {
        writer.feed(payload).await.map_err(map_stream_error)?;
    }
    Ok(()) // feed has already submitted both items to QUIC; do not wait for ACKs.
}
