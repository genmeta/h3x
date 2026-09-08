use std::{
    collections::BTreeSet,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{Stream, future::poll_fn};
use qbase::varint::{VarInt, WriteVarInt, be_varint};

use crate::{Code, Error, Settings, transport};

pub(crate) type BoxRecvStream = Box<dyn transport::RecvStream>;
pub(crate) const MAX_BUFFERED_FRAME_PAYLOAD: usize = 64 * 1024;
pub(crate) const MAX_DATA_CHUNK: usize = 16 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameType {
    Data,
    Headers,
    Settings,
    Goaway,
    CancelPush,
    PushPromise,
    MaxPushId,
    ForbiddenHttp2,
    Unknown(u64),
}

impl From<u64> for FrameType {
    fn from(value: u64) -> Self {
        match value {
            DATA_FRAME_TYPE => Self::Data,
            HEADERS_FRAME_TYPE => Self::Headers,
            SETTINGS_FRAME_TYPE => Self::Settings,
            GOAWAY_FRAME_TYPE => Self::Goaway,
            0x03 => Self::CancelPush,
            0x05 => Self::PushPromise,
            0x0d => Self::MaxPushId,
            0x02 | 0x06 | 0x08 | 0x09 => Self::ForbiddenHttp2,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameHeader {
    pub(crate) frame_type: FrameType,
    pub(crate) length: u64,
}

/// Preserves transport chunk boundaries without copying DATA into an accumulator.
pub(crate) struct ChunkReader {
    #[cfg(feature = "webtransport")]
    id: crate::StreamId,
    stream: BoxRecvStream,
    pending: Bytes,
    ended: bool,
    ready_reads: u8,
    stop_code: Code,
}

impl ChunkReader {
    pub(crate) fn new(_id: crate::StreamId, stream: impl transport::RecvStream) -> Self {
        Self {
            #[cfg(feature = "webtransport")]
            id: _id,
            stream: Box::new(stream),
            pending: Bytes::new(),
            ended: false,
            ready_reads: 0,
            stop_code: Code::H3_REQUEST_CANCELLED,
        }
    }

    pub(crate) fn stop(&mut self, code: Code) -> Result<(), Error> {
        self.ended = true;
        self.pending = Bytes::new();
        self.stream.stop(code).map_err(map_stream_error)
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn stream_id(&self) -> crate::StreamId {
        self.id
    }

    fn poll_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max: usize,
    ) -> Poll<Result<Option<Bytes>, Error>> {
        assert!(max > 0);
        loop {
            // Bound always-ready input, including empty chunks and zero-length frames.
            if self.ready_reads == 64 {
                self.ready_reads = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.ready_reads += 1;
            if !self.pending.is_empty() {
                return Poll::Ready(Ok(Some(self.pending.split_to(self.pending.len().min(max)))));
            }
            if self.ended {
                return Poll::Ready(Ok(None));
            }
            match self.stream.poll_next(cx) {
                Poll::Ready(Some(Ok(bytes))) => self.pending = bytes,
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
    }

    async fn read_chunk_limited(&mut self, max: usize) -> Result<Option<Bytes>, Error> {
        poll_fn(|cx| self.poll_chunk(cx, max)).await
    }

    /// Raw QPACK and WebTransport bytes, including any unconsumed prefix chunk.
    pub(crate) async fn read_chunk(&mut self) -> Result<Option<Bytes>, Error> {
        self.read_chunk_limited(usize::MAX).await
    }

    /// Cancellation terminates this reader; a partially consumed varint cannot be retried.
    pub(crate) async fn read_varint_opt(&mut self) -> Result<Option<u64>, Error> {
        let Some(first) = self.read_chunk_limited(1).await? else {
            return Ok(None);
        };
        let mut encoded = [0u8; VarInt::MAX_SIZE];
        encoded[0] = first[0];
        let len = 1usize << (encoded[0] >> 6);
        let mut filled = 1;
        while filled < len {
            let chunk = self
                .read_chunk_limited(len - filled)
                .await?
                .ok_or_else(|| frame_error("incomplete QUIC variable-length integer"))?;
            encoded[filled..filled + chunk.len()].copy_from_slice(&chunk);
            filled += chunk.len();
        }
        decode_varint(&encoded[..len]).map(|(value, _)| Some(value))
    }

    pub(crate) async fn read_varint(&mut self) -> Result<u64, Error> {
        self.read_varint_opt()
            .await?
            .ok_or_else(|| frame_error("missing QUIC variable-length integer"))
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

    /// Keep polling the same future after Pending; cancellation discards the reader.
    pub(crate) async fn next_header(&mut self) -> Result<Option<FrameHeader>, Error> {
        let Some(frame_type) = self.next_type().await? else {
            return Ok(None);
        };
        self.header_after_type(frame_type).await.map(Some)
    }

    pub(crate) async fn next_type(&mut self) -> Result<Option<u64>, Error> {
        assert_eq!(
            self.remaining, 0,
            "consume the previous frame payload first"
        );
        self.input.read_varint_opt().await
    }

    pub(crate) async fn header_after_type(
        &mut self,
        frame_type: u64,
    ) -> Result<FrameHeader, Error> {
        let length = self.input.read_varint().await?;
        self.remaining = length;
        Ok(FrameHeader {
            frame_type: frame_type.into(),
            length,
        })
    }

    pub(crate) async fn read_payload_chunk(&mut self, max: usize) -> Result<Option<Bytes>, Error> {
        assert!(max > 0);
        if self.remaining == 0 {
            return Ok(None);
        }
        let max = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(max);
        let bytes = self
            .input
            .read_chunk_limited(max)
            .await?
            .ok_or_else(|| frame_error("incomplete HTTP/3 frame payload"))?;
        self.remaining -= bytes.len() as u64;
        Ok(Some(bytes))
    }

    /// Reads a VarInt inside the current payload without crossing its frame boundary.
    pub(crate) async fn read_payload_varint(&mut self) -> Result<u64, Error> {
        let first = self
            .read_payload_chunk(1)
            .await?
            .ok_or_else(|| frame_error("missing frame payload integer"))?;
        let mut encoded = [0u8; VarInt::MAX_SIZE];
        encoded[0] = first[0];
        let len = 1usize << (encoded[0] >> 6);
        let mut filled = 1;
        while filled < len {
            let chunk = self
                .read_payload_chunk(len - filled)
                .await?
                .ok_or_else(|| frame_error("incomplete frame payload integer"))?;
            encoded[filled..filled + chunk.len()].copy_from_slice(&chunk);
            filled += chunk.len();
        }
        decode_varint(&encoded[..len]).map(|(value, _)| value)
    }

    pub(crate) async fn read_id_payload(&mut self) -> Result<u64, Error> {
        if self.remaining > VarInt::MAX_SIZE as u64 {
            return Err(frame_error("frame payload is longer than one QUIC varint"));
        }
        let value = self.read_payload_varint().await?;
        if self.remaining != 0 {
            return Err(frame_error("trailing bytes after frame payload integer"));
        }
        Ok(value)
    }

    pub(crate) async fn read_payload(&mut self, limit: usize) -> Result<Bytes, Error> {
        let len = usize::try_from(self.remaining)
            .ok()
            .filter(|len| *len <= limit.min(MAX_BUFFERED_FRAME_PAYLOAD))
            .ok_or_else(|| excessive_load("buffered frame payload exceeds implementation limit"))?;
        let mut bytes = BytesMut::with_capacity(len);
        while let Some(chunk) = self.read_payload_chunk(MAX_DATA_CHUNK).await? {
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes.freeze())
    }

    pub(crate) async fn discard_payload(&mut self) -> Result<(), Error> {
        while self.read_payload_chunk(MAX_DATA_CHUNK).await?.is_some() {}
        Ok(())
    }
}

fn excessive_load(message: &'static str) -> Error {
    Error::connection_protocol(Code::H3_EXCESSIVE_LOAD, message)
}

pub(crate) const CONTROL_STREAM_TYPE: u64 = 0x00;
pub(crate) const PUSH_STREAM_TYPE: u64 = 0x01;
pub(crate) const QPACK_ENCODER_STREAM_TYPE: u64 = 0x02;
pub(crate) const QPACK_DECODER_STREAM_TYPE: u64 = 0x03;

pub(crate) const DATA_FRAME_TYPE: u64 = 0x00;
pub(crate) const HEADERS_FRAME_TYPE: u64 = 0x01;
pub(crate) const SETTINGS_FRAME_TYPE: u64 = 0x04;
pub(crate) const GOAWAY_FRAME_TYPE: u64 = 0x07;

#[cfg(feature = "webtransport")]
pub(crate) const WEBTRANSPORT_BIDI_SIGNAL: u64 = 0x41;
#[cfg(feature = "webtransport")]
pub(crate) const WEBTRANSPORT_UNI_STREAM_TYPE: u64 = 0x54;

const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const QPACK_BLOCKED_STREAMS: u64 = 0x07;
const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
#[cfg(feature = "webtransport")]
const H3_DATAGRAM: u64 = 0x33;
#[cfg(feature = "webtransport")]
const WEBTRANSPORT: u64 = 0x2c7cf000;

const HTTP2_RESERVED_SETTINGS: [u64; 4] = [0x02, 0x03, 0x04, 0x05];

pub(crate) fn encode_stream_type(stream_type: u64) -> Result<Bytes, Error> {
    let mut bytes = Vec::with_capacity(8);
    encode_varint(stream_type, &mut bytes)?;
    Ok(Bytes::from(bytes))
}

pub(crate) fn encode_settings_frame(settings: &Settings) -> Result<Bytes, Error> {
    let mut payload = Vec::new();

    if let Some(value) = settings.encoded_qpack_max_table_capacity() {
        encode_setting(QPACK_MAX_TABLE_CAPACITY, value, &mut payload)?;
    }
    if let Some(value) = settings.max_field_section_size() {
        encode_setting(MAX_FIELD_SECTION_SIZE, value, &mut payload)?;
    }
    if let Some(value) = settings.encoded_qpack_blocked_streams() {
        encode_setting(QPACK_BLOCKED_STREAMS, value, &mut payload)?;
    }
    if let Some(value) = settings.encoded_enable_connect_protocol() {
        encode_setting(ENABLE_CONNECT_PROTOCOL, u64::from(value), &mut payload)?;
    }
    #[cfg(feature = "webtransport")]
    if let Some(value) = settings.encoded_h3_datagram() {
        encode_setting(H3_DATAGRAM, u64::from(value), &mut payload)?;
    }
    #[cfg(feature = "webtransport")]
    if let Some(value) = settings.encoded_webtransport() {
        encode_setting(WEBTRANSPORT, u64::from(value), &mut payload)?;
    }

    encode_frame(SETTINGS_FRAME_TYPE, &payload)
}

pub(crate) fn decode_settings_payload(mut payload: &[u8]) -> Result<Settings, Error> {
    let mut settings = Settings::default();
    let mut identifiers = BTreeSet::new();

    while !payload.is_empty() {
        let (identifier, identifier_len) = decode_varint(payload)?;
        payload = &payload[identifier_len..];
        let (value, value_len) = decode_varint(payload)?;
        payload = &payload[value_len..];

        if !identifiers.insert(identifier) {
            return Err(settings_error(format!(
                "duplicate SETTINGS identifier 0x{identifier:x}"
            )));
        }
        if HTTP2_RESERVED_SETTINGS.contains(&identifier) {
            return Err(settings_error(format!(
                "HTTP/2 SETTINGS identifier 0x{identifier:x} is forbidden in HTTP/3"
            )));
        }

        match identifier {
            QPACK_MAX_TABLE_CAPACITY => settings.set_qpack_max_table_capacity(value),
            MAX_FIELD_SECTION_SIZE => settings.set_max_field_section_size(Some(value)),
            QPACK_BLOCKED_STREAMS => settings.set_qpack_blocked_streams(value),
            ENABLE_CONNECT_PROTOCOL => match value {
                0 => settings.set_enable_connect_protocol(false),
                1 => settings.set_enable_connect_protocol(true),
                _ => {
                    return Err(settings_error(format!(
                        "SETTINGS_ENABLE_CONNECT_PROTOCOL must be 0 or 1, got {value}"
                    )));
                }
            },
            #[cfg(feature = "webtransport")]
            H3_DATAGRAM => match value {
                0 => settings.set_h3_datagram(false),
                1 => settings.set_h3_datagram(true),
                _ => {
                    return Err(settings_error(format!(
                        "SETTINGS_H3_DATAGRAM must be 0 or 1, got {value}"
                    )));
                }
            },
            #[cfg(feature = "webtransport")]
            WEBTRANSPORT => match value {
                0 => settings.set_webtransport(false),
                1 => settings.set_webtransport(true),
                _ => {
                    return Err(settings_error(format!(
                        "SETTINGS_WT_ENABLED must be 0 or 1, got {value}"
                    )));
                }
            },
            _ => {}
        }
    }

    Ok(settings)
}

pub(crate) fn encode_frame(frame_type: u64, payload: &[u8]) -> Result<Bytes, Error> {
    let mut bytes = Vec::with_capacity(16 + payload.len());
    encode_varint(frame_type, &mut bytes)?;
    encode_varint(payload.len() as u64, &mut bytes)?;
    bytes.extend_from_slice(payload);
    Ok(Bytes::from(bytes))
}

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn decode_frame(bytes: &[u8]) -> Result<(u64, &[u8], usize), Error> {
    let (frame_type, type_len) = decode_varint(bytes)?;
    let (payload_len, length_len) = decode_varint(&bytes[type_len..])?;
    let payload_len = usize::try_from(payload_len).map_err(|_| {
        Error::connection_protocol(Code::H3_FRAME_ERROR, "frame length does not fit in memory")
    })?;
    let header_len = type_len + length_len;
    let frame_len = header_len.checked_add(payload_len).ok_or_else(|| {
        Error::connection_protocol(Code::H3_FRAME_ERROR, "HTTP/3 frame length overflow")
    })?;
    if bytes.len() < frame_len {
        return Err(frame_error("incomplete HTTP/3 frame payload"));
    }
    Ok((frame_type, &bytes[header_len..frame_len], frame_len))
}

pub(crate) fn encode_varint(value: u64, output: &mut Vec<u8>) -> Result<(), Error> {
    let value = VarInt::try_from(value).map_err(|_| {
        settings_error(format!(
            "value {value} exceeds the QUIC variable-length integer range"
        ))
    })?;
    output.put_varint(&value);
    Ok(())
}

pub(crate) fn decode_varint(bytes: &[u8]) -> Result<(u64, usize), Error> {
    let (remaining, value) =
        be_varint(bytes).map_err(|_| frame_error("incomplete QUIC variable-length integer"))?;
    Ok((value.into_u64(), bytes.len() - remaining.len()))
}

fn encode_setting(identifier: u64, value: u64, output: &mut Vec<u8>) -> Result<(), Error> {
    encode_varint(identifier, output)?;
    encode_varint(value, output)
}

fn settings_error(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::connection_protocol(Code::H3_SETTINGS_ERROR, message)
}

fn frame_error(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::connection_protocol(Code::H3_FRAME_ERROR, message)
}

pub(crate) fn map_stream_error(error: transport::StreamError) -> Error {
    let code = error.code();
    if error.is_connection() {
        Error::connection(code, "QUIC connection failed while reading a stream", error)
    } else {
        Error::stream_with_source(code, "QUIC stream was reset", error)
    }
}

#[cfg(any(test, feature = "fuzzing"))]
struct TestInput {
    chunks: std::collections::VecDeque<Result<Bytes, transport::StreamError>>,
    pending: bool,
}

#[cfg(any(test, feature = "fuzzing"))]
impl Stream for TestInput {
    type Item = Result<Bytes, transport::StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.pending = true;
        Poll::Ready(self.chunks.pop_front())
    }
}

#[cfg(any(test, feature = "fuzzing"))]
impl transport::RecvStream for TestInput {
    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, transport::StreamError>>> {
        Stream::poll_next(Pin::new(self), cx)
    }

    fn stop(&mut self, _code: Code) -> Result<(), transport::StreamError> {
        Ok(())
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_frame(data: &[u8]) {
    // Exercise the production reader with fragmentation and Pending, not a shadow codec.
    let width = data.first().map_or(1, |byte| 1 + usize::from(*byte));
    let input = TestInput {
        chunks: data
            .chunks(width)
            .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
            .collect(),
        pending: false,
    };
    let mut frames = FrameReader::new(ChunkReader::new(
        crate::stream_id::from_u64_unchecked(0),
        input,
    ));
    let _: Result<(), Error> = futures::executor::block_on(async {
        while let Some(header) = frames.next_header().await? {
            match header.frame_type {
                FrameType::Headers => {
                    frames.read_payload(MAX_BUFFERED_FRAME_PAYLOAD).await?;
                }
                FrameType::Settings => {
                    decode_settings_payload(
                        &frames.read_payload(MAX_BUFFERED_FRAME_PAYLOAD).await?,
                    )?;
                }
                FrameType::Goaway | FrameType::CancelPush | FrameType::MaxPushId => {
                    frames.read_id_payload().await?;
                }
                _ => frames.discard_payload().await?,
            }
        }
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_id::MAX_VARINT;

    fn frames(chunks: impl IntoIterator<Item = Bytes>) -> FrameReader {
        FrameReader::new(ChunkReader::new(
            crate::stream_id::from_u64_unchecked(0),
            TestInput {
                chunks: chunks.into_iter().map(Ok).collect(),
                pending: true,
            },
        ))
    }

    #[test]
    fn an_always_ready_empty_transport_yields() {
        struct Empty;
        impl Stream for Empty {
            type Item = Result<Bytes, transport::StreamError>;
            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Ready(Some(Ok(Bytes::new())))
            }
        }
        impl transport::RecvStream for Empty {
            fn poll_next(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Bytes, transport::StreamError>>> {
                Stream::poll_next(Pin::new(self), cx)
            }

            fn stop(&mut self, _: Code) -> Result<(), transport::StreamError> {
                Ok(())
            }
        }
        let mut reader = ChunkReader::new(crate::stream_id::from_u64_unchecked(0), Empty);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(reader.poll_chunk(&mut cx, 1).is_pending());
        assert!(reader.poll_chunk(&mut cx, 1).is_pending());
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn fuzz_entry_exercises_fragmented_frame_streams() {
        for first in 0..=255u8 {
            for len in 0..=32 {
                fuzz_frame(&vec![first; len]);
            }
        }
        fuzz_frame(&[0, 2, 1, 2, 4, 0, 7, 1, 0]);
    }

    #[tokio::test]
    async fn data_is_zero_copy_and_preserves_the_next_header_across_pending() {
        let first = Bytes::from_static(&[0, 4, b'a', b'b']);
        let second = Bytes::from_static(&[b'c', b'd', 1, 2, 0, 0]);
        let mut reader = frames([first.clone(), second.clone()]);
        let header = reader.next_header().await.unwrap().unwrap();
        assert_eq!(header.frame_type, FrameType::Data);
        assert_eq!(header.length, 4);
        let chunk = reader.read_payload_chunk(16).await.unwrap().unwrap();
        assert_eq!(&chunk[..], b"ab");
        assert_eq!(chunk.as_ptr(), first[2..].as_ptr());
        let chunk = reader.read_payload_chunk(16).await.unwrap().unwrap();
        assert_eq!(&chunk[..], b"cd");
        assert_eq!(chunk.as_ptr(), second.as_ptr());
        assert!(reader.read_payload_chunk(16).await.unwrap().is_none());
        assert_eq!(
            reader.next_header().await.unwrap().unwrap().frame_type,
            FrameType::Headers
        );
        assert_eq!(&*reader.read_payload(2).await.unwrap(), &[0, 0]);
        assert!(reader.next_header().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn varints_at_every_width_survive_bytewise_chunks() {
        for value in [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, MAX_VARINT] {
            let mut bytes = Vec::new();
            encode_varint(value, &mut bytes).unwrap();
            let mut reader = ChunkReader::new(
                crate::stream_id::from_u64_unchecked(0),
                TestInput {
                    chunks: bytes
                        .into_iter()
                        .map(|byte| Ok(Bytes::from(vec![byte])))
                        .collect(),
                    pending: true,
                },
            );
            assert_eq!(reader.read_varint_opt().await.unwrap(), Some(value));
            assert_eq!(reader.read_varint_opt().await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn unknown_payloads_are_discarded_and_data_chunks_are_bounded() {
        let data = Bytes::from(vec![42; MAX_BUFFERED_FRAME_PAYLOAD + 1]);
        let mut encoded = encode_frame(0x21, &data).unwrap().to_vec();
        encoded.extend_from_slice(&encode_frame(DATA_FRAME_TYPE, &data).unwrap());
        let mut reader = frames([Bytes::from(encoded)]);
        assert_eq!(
            reader.next_header().await.unwrap().unwrap().frame_type,
            FrameType::Unknown(0x21)
        );
        reader.discard_payload().await.unwrap();
        assert_eq!(
            reader.next_header().await.unwrap().unwrap().frame_type,
            FrameType::Data
        );
        let mut count = 0;
        while let Some(bytes) = reader.read_payload_chunk(MAX_DATA_CHUNK).await.unwrap() {
            assert!(bytes.len() <= MAX_DATA_CHUNK);
            count += bytes.len();
        }
        assert_eq!(count, data.len());
        assert!(reader.next_header().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn eof_and_transport_errors_keep_their_scope() {
        for input in [&[0x40][..], &[0][..], &[0, 0x40][..], &[0, 2, 1][..]] {
            let mut reader = frames([Bytes::copy_from_slice(input)]);
            let result = async {
                reader.next_header().await?;
                reader.discard_payload().await
            }
            .await;
            assert_eq!(result.unwrap_err().code(), Some(Code::H3_FRAME_ERROR));
        }
        for error in [
            transport::StreamError::reset(Code::H3_REQUEST_CANCELLED),
            transport::StreamError::connection(transport::ConnectionError::transport(
                std::io::Error::other("network failed"),
            )),
        ] {
            for input in [&[0x40][..], &[0, 0x40][..], &[0, 2, 1][..]] {
                let mut reader = FrameReader::new(ChunkReader::new(
                    crate::stream_id::from_u64_unchecked(0),
                    TestInput {
                        chunks: [Ok(Bytes::copy_from_slice(input)), Err(error.clone())].into(),
                        pending: true,
                    },
                ));
                let actual = async {
                    reader.next_header().await?;
                    reader.discard_payload().await
                }
                .await
                .unwrap_err();
                assert_eq!(actual.is_connection(), error.is_connection());
                assert_eq!(actual.code(), error.code());
                assert!(std::error::Error::source(&actual).is_some());
            }
        }
    }

    #[tokio::test]
    async fn buffered_payload_size_is_bounded() {
        let mut large = Vec::new();
        encode_varint(1, &mut large).unwrap();
        encode_varint((MAX_BUFFERED_FRAME_PAYLOAD + 1) as u64, &mut large).unwrap();
        let mut reader = frames([Bytes::from(large)]);
        reader.next_header().await.unwrap();
        assert_eq!(
            reader.read_payload(usize::MAX).await.unwrap_err().code(),
            Some(Code::H3_EXCESSIVE_LOAD)
        );
    }

    #[tokio::test]
    async fn id_payloads_are_exactly_one_varint() {
        for payload in [&[][..], &[0, 0][..], &[0x40][..], &[0; 9][..]] {
            let mut reader = frames([encode_frame(GOAWAY_FRAME_TYPE, payload).unwrap()]);
            reader.next_header().await.unwrap();
            assert_eq!(
                reader.read_id_payload().await.unwrap_err().code(),
                Some(Code::H3_FRAME_ERROR)
            );
        }
        let mut reader = frames([Bytes::from_static(&[7, 2, 0x40, 0, 0, 0])]);
        reader.next_header().await.unwrap();
        assert_eq!(reader.read_id_payload().await.unwrap(), 0);
        assert_eq!(
            reader.next_header().await.unwrap().unwrap().frame_type,
            FrameType::Data
        );
    }

    #[test]
    fn quic_varints_round_trip_at_each_width_boundary() {
        for expected in [
            0,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            MAX_VARINT,
        ] {
            let mut encoded = Vec::new();
            encode_varint(expected, &mut encoded).expect("encode");
            let (actual, consumed) = decode_varint(&encoded).expect("decode");

            assert_eq!(actual, expected);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn default_settings_frame_is_wire_compatible_and_empty() {
        let frame = encode_settings_frame(&Settings::default()).expect("encode settings");

        assert_eq!(frame.as_ref(), &[SETTINGS_FRAME_TYPE as u8, 0]);
    }

    #[test]
    fn typed_settings_round_trip_through_the_wire_format() {
        let mut expected = Settings::default();
        expected.set_qpack_max_table_capacity(4096);
        expected.set_max_field_section_size(Some(32 * 1024));
        expected.set_qpack_blocked_streams(12);
        expected.set_enable_connect_protocol(true);
        #[cfg(feature = "webtransport")]
        expected.enable_webtransport();

        let frame = encode_settings_frame(&expected).expect("encode settings");
        let (frame_type, payload, consumed) = decode_frame(&frame).expect("decode frame");
        let actual = decode_settings_payload(payload).expect("decode settings");

        assert_eq!(frame_type, SETTINGS_FRAME_TYPE);
        assert_eq!(consumed, frame.len());
        assert_eq!(actual, expected);
    }

    #[test]
    fn duplicate_settings_are_rejected() {
        let payload = [
            QPACK_BLOCKED_STREAMS as u8,
            0,
            QPACK_BLOCKED_STREAMS as u8,
            1,
        ];
        let error = decode_settings_payload(&payload).expect_err("duplicate is invalid");

        assert_eq!(error.code(), Some(Code::H3_SETTINGS_ERROR));
    }

    #[test]
    fn unknown_settings_are_ignored() {
        let payload = [0x21, 42];
        let settings = decode_settings_payload(&payload).expect("unknown setting is ignored");

        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn invalid_boolean_and_http2_identifiers_are_rejected() {
        for payload in [[ENABLE_CONNECT_PROTOCOL as u8, 2], [0x02, 0]] {
            let error = decode_settings_payload(&payload).expect_err("invalid settings");
            assert_eq!(error.code(), Some(Code::H3_SETTINGS_ERROR));
        }
    }

    #[cfg(feature = "webtransport")]
    #[test]
    fn webtransport_settings_use_the_draft_16_codepoints() {
        let mut expected = Settings::default();
        expected.enable_webtransport();

        let frame = encode_settings_frame(&expected).expect("encode settings");
        let (_, payload, _) = decode_frame(&frame).expect("decode frame");
        let actual = decode_settings_payload(payload).expect("decode settings");

        assert!(actual.enable_connect_protocol());
        assert!(actual.h3_datagram());
        assert!(actual.webtransport());
    }

    #[cfg(feature = "webtransport")]
    #[test]
    fn invalid_webtransport_boolean_settings_are_rejected() {
        for identifier in [H3_DATAGRAM, WEBTRANSPORT] {
            let mut payload = Vec::new();
            encode_varint(identifier, &mut payload).expect("setting identifier");
            encode_varint(2, &mut payload).expect("setting value");

            let error = decode_settings_payload(&payload).expect_err("invalid boolean setting");
            assert_eq!(error.code(), Some(Code::H3_SETTINGS_ERROR));
        }
    }
}
