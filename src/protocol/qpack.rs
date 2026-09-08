use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use bytes::{Buf, Bytes, BytesMut};
use futures::SinkExt;
use httlib_huffman::DecoderSpeed;
use http::HeaderMap;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

#[cfg(test)]
use super::headers::request_fields;
use super::headers::{
    regular_fields, request_parts, response_fields, response_parts, trailer_fields,
};
use crate::{
    Code, Error, Settings, StreamId,
    stream_id::{MAX_VARINT, StreamIdExt as _},
    transport,
    wire::ChunkReader,
};

mod decoder;
mod encoder;
mod instruction;
#[path = "qpack/static.rs"]
mod static_table;
mod table;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    pub(crate) name: Bytes,
    pub(crate) value: Bytes,
}

type BoxSendStream = Box<dyn transport::SendStream>;

const MAX_PENDING_DECODER_INSTRUCTION_BYTES: usize = 64 * 1024;
const MIN_ENCODER_INSTRUCTION_BUFFER_BYTES: usize = 64;

struct EncoderSide {
    state: encoder::Encoder,
    stream: BoxSendStream,
}

/// Connection-scoped QPACK state shared by every request stream.
pub(crate) struct Qpack {
    encoder: AsyncMutex<EncoderSide>,
    decoder: Mutex<decoder::Decoder>,
    insertions: Notify,
    max_encoder_instruction_buffer_bytes: usize,
    failure: Mutex<Option<Error>>,
    failed: Notify,
    decoder_instructions: Arc<InstructionQueue>,
    connection_state: Arc<crate::connection::ConnectionState>,
}

pub(crate) struct DecoderWriter {
    stream: BoxSendStream,
    commands: mpsc::UnboundedReceiver<Bytes>,
    queue: Arc<InstructionQueue>,
}

struct InstructionQueue {
    commands: mpsc::UnboundedSender<Bytes>,
    pending_bytes: AtomicUsize,
    failure: Mutex<Option<Error>>,
    failed: Notify,
}

impl Qpack {
    pub(crate) fn new(
        settings: &Settings,
        encoder_stream: BoxSendStream,
        decoder_stream: BoxSendStream,
        connection_state: Arc<crate::connection::ConnectionState>,
    ) -> (Arc<Self>, DecoderWriter) {
        let (commands_tx, commands_rx) = mpsc::unbounded_channel();
        let queue = Arc::new(InstructionQueue {
            commands: commands_tx,
            pending_bytes: AtomicUsize::new(0),
            failure: Mutex::new(None),
            failed: Notify::new(),
        });
        let qpack = Arc::new(Self {
            encoder: AsyncMutex::new(EncoderSide {
                state: encoder::Encoder::new(),
                stream: encoder_stream,
            }),
            decoder: Mutex::new(decoder::Decoder::new(
                settings.qpack_max_table_capacity(),
                settings.qpack_blocked_streams(),
                settings.max_field_section_size(),
            )),
            insertions: Notify::new(),
            max_encoder_instruction_buffer_bytes: usize::try_from(
                settings.qpack_max_table_capacity(),
            )
            .unwrap_or(usize::MAX)
            .max(MIN_ENCODER_INSTRUCTION_BUFFER_BYTES),
            failure: Mutex::new(None),
            failed: Notify::new(),
            decoder_instructions: Arc::clone(&queue),
            connection_state,
        });
        let writer = DecoderWriter {
            stream: decoder_stream,
            commands: commands_rx,
            queue,
        };
        (qpack, writer)
    }

    pub(crate) async fn apply_peer_settings(&self, settings: &Settings) -> Result<(), Error> {
        let result = async {
            let mut encoder = self.encoder.lock().await;
            let instruction = encoder
                .state
                .configure(settings.qpack_max_table_capacity())?;
            if !instruction.is_empty() {
                send_critical(&mut encoder.stream, instruction, "QPACK encoder").await?;
            }
            Ok(())
        }
        .await;
        self.fail_on_connection(result)
    }

    pub(crate) async fn encode_fields(
        &self,
        stream_id: StreamId,
        fields: Vec<Field>,
    ) -> Result<Bytes, Error> {
        self.encode(stream_id, fields).await
    }

    pub(crate) async fn decode_request(
        &self,
        stream_id: StreamId,
        payload: &[u8],
    ) -> Result<http::request::Parts, Error> {
        request_parts(self.decode(stream_id, payload).await?)
    }

    pub(crate) async fn encode_response(
        &self,
        stream_id: StreamId,
        parts: http::response::Parts,
    ) -> Result<Bytes, Error> {
        self.encode(
            stream_id,
            response_fields(parts).map_err(Error::into_invalid_message)?,
        )
        .await
    }

    pub(crate) async fn decode_response(
        &self,
        stream_id: StreamId,
        payload: &[u8],
    ) -> Result<http::response::Parts, Error> {
        response_parts(self.decode(stream_id, payload).await?)
    }

    pub(crate) async fn encode_trailers(
        &self,
        stream_id: StreamId,
        trailers: HeaderMap,
    ) -> Result<Bytes, Error> {
        self.encode(
            stream_id,
            regular_fields(trailers).map_err(Error::into_invalid_message)?,
        )
        .await
    }

    pub(crate) async fn decode_trailers(
        &self,
        stream_id: StreamId,
        payload: &[u8],
    ) -> Result<HeaderMap, Error> {
        trailer_fields(self.decode(stream_id, payload).await?)
    }

    pub(crate) fn cancel_stream(&self, stream_id: StreamId) {
        let should_send = self
            .decoder
            .lock()
            .expect("QPACK decoder lock poisoned")
            .cancel(stream_id);
        if should_send
            && let Err(error) = self.decoder_instructions.enqueue(
                instruction::DecoderInstruction::StreamCancellation(stream_id.as_u64()),
            )
        {
            let _ = self.fail_on_connection::<()>(Err(error));
        }
    }

    pub(crate) async fn handle_encoder_stream(&self, mut reader: ChunkReader) -> Result<(), Error> {
        let result = async {
            let mut buffered = BytesMut::new();
            while let Some(chunk) = reader.read_chunk().await? {
                buffered.extend_from_slice(&chunk);
                while let Some((instruction, consumed)) = instruction::decode_encoder(&buffered)? {
                    buffered.advance(consumed);
                    let inserted = self
                        .decoder
                        .lock()
                        .expect("QPACK decoder lock poisoned")
                        .apply(instruction)?;
                    if inserted {
                        self.decoder_instructions
                            .enqueue(instruction::DecoderInstruction::InsertCountIncrement(1))?;
                        self.insertions.notify_waiters();
                    }
                }
                if buffered.len() > self.max_encoder_instruction_buffer_bytes {
                    return Err(Error::connection_protocol(
                        Code::QPACK_ENCODER_STREAM_ERROR,
                        "peer QPACK encoder instruction exceeds the advertised table capacity",
                    ));
                }
            }
            if !buffered.is_empty() {
                return Err(Error::connection_protocol(
                    Code::QPACK_ENCODER_STREAM_ERROR,
                    "peer QPACK encoder stream ended in the middle of an instruction",
                ));
            }
            Err(Error::connection_protocol(
                Code::H3_CLOSED_CRITICAL_STREAM,
                "peer QPACK encoder stream closed",
            ))
        }
        .await;
        self.fail_on_connection(result)
    }

    pub(crate) async fn handle_decoder_stream(&self, mut reader: ChunkReader) -> Result<(), Error> {
        let result = async {
            let mut buffered = BytesMut::new();
            while let Some(chunk) = reader.read_chunk().await? {
                buffered.extend_from_slice(&chunk);
                while let Some((instruction, consumed)) = instruction::decode_decoder(&buffered)? {
                    buffered.advance(consumed);
                    self.encoder.lock().await.state.apply(instruction)?;
                }
            }
            if !buffered.is_empty() {
                return Err(Error::connection_protocol(
                    Code::QPACK_DECODER_STREAM_ERROR,
                    "peer QPACK decoder stream ended in the middle of an instruction",
                ));
            }
            Err(Error::connection_protocol(
                Code::H3_CLOSED_CRITICAL_STREAM,
                "peer QPACK decoder stream closed",
            ))
        }
        .await;
        self.fail_on_connection(result)
    }

    pub(crate) fn fail(&self, error: Error) {
        let mut failure = self.failure.lock().expect("QPACK failure lock poisoned");
        if failure.is_some() {
            return;
        }
        *failure = Some(error);
        drop(failure);
        self.failed.notify_waiters();
        self.insertions.notify_waiters();
    }

    fn failure(&self) -> Option<Error> {
        self.failure
            .lock()
            .expect("QPACK failure lock poisoned")
            .clone()
    }

    async fn encode(&self, stream_id: StreamId, fields: Vec<Field>) -> Result<Bytes, Error> {
        let result = async {
            let mut encoder = self.encoder.lock().await;
            let encoded = encoder.state.encode(stream_id, fields)?;
            if !encoded.instructions.is_empty() {
                send_critical(&mut encoder.stream, encoded.instructions, "QPACK encoder").await?;
            }
            Ok(encoded.field_section)
        }
        .await;
        self.fail_on_connection(result)
    }

    async fn decode(&self, stream_id: StreamId, payload: &[u8]) -> Result<Vec<Field>, Error> {
        loop {
            let notified = self.insertions.notified();
            let failed = self.failed.notified();
            if let Some(error) = self.failure() {
                return Err(error);
            }
            let decoded = match self
                .decoder
                .lock()
                .expect("QPACK decoder lock poisoned")
                .decode(stream_id, payload)
            {
                Ok(decoded) => decoded,
                Err(error) => return self.fail_on_connection(Err(error)),
            };
            match decoded {
                decoder::Decode::Ready {
                    fields,
                    used_dynamic_table,
                } => {
                    if used_dynamic_table
                        && let Err(error) = self.decoder_instructions.enqueue(
                            instruction::DecoderInstruction::SectionAcknowledgement(
                                stream_id.as_u64(),
                            ),
                        )
                    {
                        return self.fail_on_connection(Err(error));
                    }
                    return Ok(fields);
                }
                decoder::Decode::Blocked => {
                    tokio::select! {
                        _ = notified => {}
                        _ = failed => {}
                    }
                }
            }
        }
    }

    fn fail_on_connection<T>(&self, result: Result<T, Error>) -> Result<T, Error> {
        if let Err(error) = &result
            && error.is_connection()
        {
            self.fail(error.clone());
            self.connection_state.terminate(error.clone());
        }
        result
    }
}

impl DecoderWriter {
    pub(crate) async fn run(mut self) -> Result<(), Error> {
        loop {
            let failed = self.queue.failed.notified();
            if let Some(error) = self.queue.failure() {
                return Err(error);
            }
            tokio::select! {
                biased;
                _ = failed => {}
                command = self.commands.recv() => {
                    let Some(command) = command else {
                        return Ok(());
                    };
                    let len = command.len();
                    send_critical(&mut self.stream, command, "QPACK decoder").await?;
                    self.queue.pending_bytes.fetch_sub(len, Ordering::AcqRel);
                }
            }
        }
    }
}

impl InstructionQueue {
    fn enqueue(&self, instruction: instruction::DecoderInstruction) -> Result<(), Error> {
        let bytes = instruction::encode_decoder(instruction)?;
        let len = bytes.len();
        if self
            .pending_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(len)
                    .filter(|pending| *pending <= MAX_PENDING_DECODER_INSTRUCTION_BYTES)
            })
            .is_err()
        {
            let error = Error::connection_protocol(
                Code::H3_EXCESSIVE_LOAD,
                "pending QPACK decoder instructions exceed the implementation limit",
            );
            self.fail(error.clone());
            return Err(error);
        }
        if self.commands.send(bytes).is_err() {
            self.pending_bytes.fetch_sub(len, Ordering::AcqRel);
            let error = Error::connection_protocol(
                Code::H3_CLOSED_CRITICAL_STREAM,
                "local QPACK decoder instruction writer stopped",
            );
            self.fail(error.clone());
            return Err(error);
        }
        Ok(())
    }

    fn fail(&self, error: Error) {
        let mut failure = self.failure.lock().expect("QPACK queue lock poisoned");
        if failure.is_none() {
            *failure = Some(error);
            drop(failure);
            self.failed.notify_waiters();
        }
    }

    fn failure(&self) -> Option<Error> {
        self.failure
            .lock()
            .expect("QPACK queue lock poisoned")
            .clone()
    }
}

async fn send_critical(
    stream: &mut BoxSendStream,
    bytes: Bytes,
    name: &'static str,
) -> Result<(), Error> {
    stream.send(bytes).await.map_err(|error| {
        if error.is_connection() {
            Error::connection(
                error.code(),
                format!("connection failed while writing the {name} stream"),
                error,
            )
        } else {
            Error::connection(
                Some(Code::H3_CLOSED_CRITICAL_STREAM),
                format!("{name} stream was reset"),
                error,
            )
        }
    })
}

#[cfg(test)]
fn encode_request(parts: http::request::Parts) -> Result<Bytes, Error> {
    encode_fields(request_fields(parts)?)
}

#[cfg(test)]
fn decode_request(payload: &[u8]) -> Result<http::request::Parts, Error> {
    request_parts(decode_fields(payload)?)
}

#[cfg(test)]
fn encode_response(parts: http::response::Parts) -> Result<Bytes, Error> {
    encode_fields(response_fields(parts)?)
}

#[cfg(test)]
fn decode_response(payload: &[u8]) -> Result<http::response::Parts, Error> {
    response_parts(decode_fields(payload)?)
}

#[cfg(test)]
fn encode_trailers(trailers: HeaderMap) -> Result<Bytes, Error> {
    encode_fields(regular_fields(trailers)?)
}

#[cfg(test)]
fn decode_trailers(payload: &[u8]) -> Result<HeaderMap, Error> {
    trailer_fields(decode_fields(payload)?)
}

#[cfg(test)]
fn encode_fields(fields: impl IntoIterator<Item = Field>) -> Result<Bytes, Error> {
    let mut encoded = vec![0, 0];
    for field in fields {
        let (name_index, exact_index) = static_table::find(&field.name, &field.value);
        if let Some(index) = exact_index.filter(|index| name_index == Some(*index)) {
            encode_prefixed_integer(index as u64, 6, 0xc0, &mut encoded)?;
        } else if let Some(index) = name_index {
            let never_dynamic = is_sensitive(&field.name);
            let prefix = 0x50 | if never_dynamic { 0x20 } else { 0 };
            encode_prefixed_integer(index as u64, 4, prefix, &mut encoded)?;
            encode_string(&field.value, 7, 0, &mut encoded)?;
        } else {
            let never_dynamic = is_sensitive(&field.name);
            let prefix = 0x20 | if never_dynamic { 0x10 } else { 0 };
            encode_prefixed_integer(field.name.len() as u64, 3, prefix, &mut encoded)?;
            encoded.extend_from_slice(&field.name);
            encode_string(&field.value, 7, 0, &mut encoded)?;
        }
    }
    Ok(Bytes::from(encoded))
}

#[cfg(any(test, feature = "fuzzing"))]
fn decode_fields(mut encoded: &[u8]) -> Result<Vec<Field>, Error> {
    let (required_insert_count, consumed) = decode_prefixed_integer(encoded, 8)?;
    encoded = &encoded[consumed..];
    let Some(delta_prefix) = encoded.first().copied() else {
        return Err(qpack_error("missing QPACK delta-base prefix"));
    };
    let (delta_base, consumed) = decode_prefixed_integer(encoded, 7)?;
    encoded = &encoded[consumed..];
    if required_insert_count != 0 || delta_base != 0 || delta_prefix & 0x80 != 0 {
        return Err(qpack_error(
            "dynamic QPACK references are not available before encoder state is applied",
        ));
    }

    let mut fields = Vec::new();
    while let Some(first) = encoded.first().copied() {
        if first & 0x80 != 0 {
            let is_static = first & 0x40 != 0;
            let (index, consumed) = decode_prefixed_integer(encoded, 6)?;
            encoded = &encoded[consumed..];
            if !is_static {
                return Err(qpack_error("dynamic QPACK indexed field is unavailable"));
            }
            let (name, value) = static_table::get(index)
                .ok_or_else(|| qpack_error(format!("unknown QPACK static index {index}")))?;
            fields.push(Field {
                name: Bytes::from_static(name.as_bytes()),
                value: Bytes::from_static(value.as_bytes()),
            });
        } else if first & 0xc0 == 0x40 {
            let is_static = first & 0x10 != 0;
            let (name_index, consumed) = decode_prefixed_integer(encoded, 4)?;
            encoded = &encoded[consumed..];
            if !is_static {
                return Err(qpack_error("dynamic QPACK name references are unavailable"));
            }
            let name = static_table::get_name(name_index).ok_or_else(|| {
                qpack_error(format!("unknown QPACK static name index {name_index}"))
            })?;
            let (value, consumed) = decode_string(encoded, 7)?;
            encoded = &encoded[consumed..];
            fields.push(Field {
                name: Bytes::from_static(name.as_bytes()),
                value,
            });
        } else if first & 0xe0 == 0x20 {
            let name_huffman = first & 0x08 != 0;
            let (name_len, consumed) = decode_prefixed_integer(encoded, 3)?;
            encoded = &encoded[consumed..];
            let name_len = usize::try_from(name_len)
                .map_err(|_| qpack_error("QPACK field name is too large"))?;
            if encoded.len() < name_len {
                return Err(qpack_error("incomplete QPACK field name"));
            }
            let name = decode_octets(&encoded[..name_len], name_huffman)?;
            encoded = &encoded[name_len..];
            let (value, consumed) = decode_string(encoded, 7)?;
            encoded = &encoded[consumed..];
            fields.push(Field { name, value });
        } else {
            return Err(qpack_error(
                "post-base or dynamic QPACK field representation is unavailable",
            ));
        }
    }
    Ok(fields)
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_field_section(encoded: &[u8]) {
    let _ = decode_fields(encoded);
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_instruction(encoded: &[u8]) {
    let _ = instruction::decode_encoder(encoded);
    let _ = instruction::decode_decoder(encoded);
}

pub(super) fn encode_prefixed_integer(
    mut value: u64,
    prefix_bits: u8,
    high_bits: u8,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    if value > MAX_VARINT {
        return Err(qpack_error("QPACK integer exceeds 62 bits"));
    }
    let limit = (1u64 << prefix_bits) - 1;
    if value < limit {
        output.push(high_bits | value as u8);
        return Ok(());
    }

    output.push(high_bits | limit as u8);
    value -= limit;
    while value >= 128 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
    Ok(())
}

pub(crate) fn decode_prefixed_integer(
    encoded: &[u8],
    prefix_bits: u8,
) -> Result<(u64, usize), Error> {
    let Some(first) = encoded.first().copied() else {
        return Err(qpack_error("missing QPACK prefixed integer"));
    };
    let limit = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & limit;
    if value < limit {
        return Ok((value, 1));
    }

    let mut shift = 0u32;
    for (offset, byte) in encoded[1..].iter().copied().enumerate() {
        if shift >= 63 {
            return Err(qpack_error("QPACK prefixed integer is too long"));
        }
        let term = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or_else(|| qpack_error("QPACK integer overflow"))?;
        value = value
            .checked_add(term)
            .ok_or_else(|| qpack_error("QPACK integer overflow"))?;
        if value > MAX_VARINT {
            return Err(qpack_error("QPACK integer exceeds 62 bits"));
        }
        if byte & 0x80 == 0 {
            return Ok((value, offset + 2));
        }
        shift = shift
            .checked_add(7)
            .ok_or_else(|| qpack_error("QPACK integer overflow"))?;
    }
    Err(qpack_error("incomplete QPACK prefixed integer"))
}

pub(super) fn encode_string(
    value: &[u8],
    prefix_bits: u8,
    high_bits: u8,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    encode_prefixed_integer(value.len() as u64, prefix_bits, high_bits, output)?;
    output.extend_from_slice(value);
    Ok(())
}

pub(crate) fn decode_string(encoded: &[u8], prefix_bits: u8) -> Result<(Bytes, usize), Error> {
    let Some(first) = encoded.first().copied() else {
        return Err(qpack_error("missing QPACK string"));
    };
    let huffman_mask = 1 << prefix_bits;
    let huffman = first & huffman_mask != 0;
    let (len, prefix_len) = decode_prefixed_integer(encoded, prefix_bits)?;
    let len = usize::try_from(len).map_err(|_| qpack_error("QPACK string is too large"))?;
    let end = prefix_len
        .checked_add(len)
        .ok_or_else(|| qpack_error("QPACK string length overflow"))?;
    if encoded.len() < end {
        return Err(qpack_error("incomplete QPACK string"));
    }
    Ok((decode_octets(&encoded[prefix_len..end], huffman)?, end))
}

pub(super) fn decode_octets(encoded: &[u8], huffman: bool) -> Result<Bytes, Error> {
    if !huffman {
        return Ok(Bytes::copy_from_slice(encoded));
    }
    let mut decoded = Vec::new();
    httlib_huffman::decode(encoded, &mut decoded, DecoderSpeed::FourBits)
        .map_err(|_| qpack_error("invalid QPACK Huffman string"))?;
    Ok(Bytes::from(decoded))
}

pub(super) fn is_sensitive(name: &[u8]) -> bool {
    matches!(
        name,
        b"authorization" | b"proxy-authorization" | b"cookie" | b"set-cookie"
    )
}

pub(super) fn qpack_error(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::connection_protocol(Code::QPACK_DECOMPRESSION_FAILED, message)
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use futures::{Sink, Stream};
    use http::{HeaderValue, Method, StatusCode, Version, header::CONNECTION};

    use super::*;

    struct TestSendStream;

    struct TestRecvStream(Option<Bytes>);

    impl Stream for TestRecvStream {
        type Item = Result<Bytes, transport::StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.take().map(Ok))
        }
    }

    impl transport::RecvStream for TestRecvStream {
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

    impl Sink<Bytes> for TestSendStream {
        type Error = transport::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl transport::SendStream for TestSendStream {
        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), transport::StreamError>> {
            Sink::poll_ready(Pin::new(self), cx)
        }

        fn start_send(&mut self, item: Bytes) -> Result<(), transport::StreamError> {
            Sink::start_send(Pin::new(self), item)
        }

        fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), transport::StreamError>> {
            Sink::poll_close(Pin::new(self), cx)
        }

        fn reset(&mut self, _code: Code) -> Result<(), transport::StreamError> {
            Ok(())
        }
    }

    #[test]
    fn request_round_trip_preserves_pseudo_headers_and_repeated_fields() {
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri("https://example.test/items?q=1")
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        request
            .headers_mut()
            .append("x-tag", HeaderValue::from_static("a"));
        request
            .headers_mut()
            .append("x-tag", HeaderValue::from_static("b"));

        let encoded = encode_request(request.into_parts().0).unwrap();
        let actual = decode_request(&encoded).unwrap();

        assert_eq!(actual.method, Method::POST);
        assert_eq!(actual.uri, "https://example.test/items?q=1");
        assert_eq!(actual.version, Version::HTTP_3);
        assert_eq!(actual.headers.get_all("x-tag").iter().count(), 2);
    }

    #[test]
    fn response_and_trailer_round_trip() {
        let response = http::Response::builder()
            .status(StatusCode::CREATED)
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        let response = decode_response(&encode_response(response.into_parts().0).unwrap()).unwrap();
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.version, Version::HTTP_3);

        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", HeaderValue::from_static("ok"));
        assert_eq!(
            decode_trailers(&encode_trailers(trailers.clone()).unwrap()).unwrap(),
            trailers
        );
    }

    #[test]
    fn static_and_literal_representations_decode() {
        let fields = vec![
            Field {
                name: Bytes::from_static(b":method"),
                value: Bytes::from_static(b"GET"),
            },
            Field {
                name: Bytes::from_static(b"content-type"),
                value: Bytes::from_static(b"application/custom"),
            },
            Field {
                name: Bytes::from_static(b"x-custom"),
                value: Bytes::from_static(b"value"),
            },
        ];
        let encoded = encode_fields(fields.clone()).unwrap();

        assert_eq!(decode_fields(&encoded).unwrap(), fields);
    }

    #[test]
    fn dynamic_references_are_reported_as_qpack_errors() {
        let encoded = [0, 0, 0x80];
        let error = decode_fields(&encoded).unwrap_err();

        assert!(matches!(&error, Error::Connection { .. }));
        assert_eq!(error.code(), Some(Code::QPACK_DECOMPRESSION_FAILED));
    }

    #[test]
    fn prefixed_integer_larger_than_62_bits_is_rejected() {
        let encoded = [0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x40];
        let error = decode_prefixed_integer(&encoded, 8).unwrap_err();

        assert!(matches!(&error, Error::Connection { .. }));
        assert_eq!(error.code(), Some(Code::QPACK_DECOMPRESSION_FAILED));
    }

    #[tokio::test]
    async fn blocked_decode_returns_when_the_connection_fails() {
        let mut settings = Settings::default();
        settings.set_qpack_max_table_capacity(256);
        settings.set_qpack_blocked_streams(1);
        let (qpack, _writer) = Qpack::new(
            &settings,
            Box::new(TestSendStream),
            Box::new(TestSendStream),
            Arc::new(crate::connection::ConnectionState::new()),
        );
        let blocked = {
            let qpack = Arc::clone(&qpack);
            tokio::spawn(async move {
                qpack
                    .decode(crate::stream_id::from_u64_unchecked(0), &[2, 0, 0x80])
                    .await
            })
        };
        tokio::task::yield_now().await;

        qpack.fail(Error::connection_protocol(
            Code::H3_INTERNAL_ERROR,
            "connection closed",
        ));

        let error = tokio::time::timeout(Duration::from_millis(100), blocked)
            .await
            .expect("blocked QPACK decode did not observe connection failure")
            .expect("decode task panicked")
            .expect_err("connection failure must abort blocked decoding");
        assert!(matches!(&error, Error::Connection { .. }));
        assert_eq!(error.code(), Some(Code::H3_INTERNAL_ERROR));
    }

    #[tokio::test]
    async fn incomplete_encoder_instruction_is_bounded_by_table_capacity() {
        let settings = Settings::default();
        let (qpack, _writer) = Qpack::new(
            &settings,
            Box::new(TestSendStream),
            Box::new(TestSendStream),
            Arc::new(crate::connection::ConnectionState::new()),
        );
        let mut instruction = vec![0x5f, 69];
        instruction.extend(std::iter::repeat_n(0, 63));

        let error = qpack
            .handle_encoder_stream(ChunkReader::new(
                crate::stream_id::from_u64_unchecked(6),
                TestRecvStream(Some(Bytes::from(instruction))),
            ))
            .await
            .expect_err("an incomplete instruction cannot grow without a bound");

        assert!(matches!(&error, Error::Connection { .. }));
        assert_eq!(error.code(), Some(Code::QPACK_ENCODER_STREAM_ERROR));
    }

    #[test]
    fn rejects_connection_specific_fields() {
        let request = http::Request::builder()
            .uri("https://example.test/")
            .header(CONNECTION, "close")
            .body(())
            .unwrap();
        let error = encode_request(request.into_parts().0).unwrap_err();

        assert_eq!(error.code(), Some(Code::H3_MESSAGE_ERROR));
    }

    #[test]
    fn connect_requires_authority_form_with_port() {
        let valid = http::Request::builder()
            .method(Method::CONNECT)
            .uri("example.test:443")
            .body(())
            .unwrap();
        let decoded = decode_request(&encode_request(valid.into_parts().0).unwrap()).unwrap();
        assert_eq!(decoded.uri, "example.test:443");

        let invalid = http::Request::builder()
            .method(Method::CONNECT)
            .uri("example.test")
            .body(())
            .unwrap();
        assert!(encode_request(invalid.into_parts().0).is_err());
    }
}
