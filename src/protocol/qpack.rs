use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use bytes::{Buf, Bytes, BytesMut};
use dquic::prelude::StreamWriter;
use futures::SinkExt;
use httlib_huffman::DecoderSpeed;
#[cfg(test)]
use http::HeaderMap;
use qbase::varint::VARINT_MAX;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, watch};

#[cfg(test)]
use super::headers::request_fields;
#[cfg(test)]
use super::headers::{
    regular_fields, request_parts, response_fields, response_parts, trailer_fields,
};
use crate::{Code, Error, Settings, StreamId, wire::ChunkReader};

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

const MAX_PENDING_DECODER_INSTRUCTION_BYTES: usize = 64 * 1024;
const MIN_ENCODER_INSTRUCTION_BUFFER_BYTES: usize = 64;

struct EncoderSide {
    state: encoder::Encoder,
    stream: StreamWriter,
}

/// Connection-scoped QPACK state shared by every request stream.
pub(crate) struct Qpack {
    encoder: AsyncMutex<EncoderSide>,
    decoder: Mutex<decoder::Decoder>,
    insertions: Notify,
    max_encoder_instruction_buffer_bytes: usize,
    terminal: watch::Receiver<Option<Error>>,
    decoder_instructions: Arc<InstructionQueue>,
    fail_connection: Box<dyn Fn(Error) + Send + Sync>,
}

pub(crate) struct DecoderWriter {
    stream: StreamWriter,
    commands: mpsc::UnboundedReceiver<Bytes>,
    queue: Arc<InstructionQueue>,
    terminal: watch::Receiver<Option<Error>>,
}

struct InstructionQueue {
    commands: mpsc::UnboundedSender<Bytes>,
    pending_bytes: AtomicUsize,
}

impl Qpack {
    pub(crate) fn new(
        settings: &Settings,
        encoder_stream: StreamWriter,
        decoder_stream: StreamWriter,
        terminal: watch::Receiver<Option<Error>>,
        fail_connection: Box<dyn Fn(Error) + Send + Sync>,
    ) -> (Arc<Self>, DecoderWriter) {
        let (commands_tx, commands_rx) = mpsc::unbounded_channel();
        let queue = Arc::new(InstructionQueue {
            commands: commands_tx,
            pending_bytes: AtomicUsize::new(0),
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
            terminal: terminal.clone(),
            decoder_instructions: Arc::clone(&queue),
            fail_connection,
        });
        let writer = DecoderWriter {
            stream: decoder_stream,
            commands: commands_rx,
            queue,
            terminal,
        };
        (qpack, writer)
    }

    pub(crate) async fn apply_peer_settings(&self, settings: &Settings) -> Result<(), Error> {
        let work = async {
            let mut encoder = self.encoder.lock().await;
            if let Some(error) = self.failure() {
                return Err(error);
            }
            let result = async {
                futures::future::poll_fn(|cx| encoder.stream.poll_ready(cx))
                    .await
                    .map_err(|error| critical_error(error.into(), "QPACK encoder"))?;
                let instruction = encoder
                    .state
                    .configure(settings.qpack_max_table_capacity())?;
                if !instruction.is_empty() {
                    encoder
                        .stream
                        .write(instruction)
                        .map_err(|error| critical_error(error.into(), "QPACK encoder"))?;
                }
                Ok(())
            }
            .await;
            // Publish failure before another request can acquire the encoder.
            self.terminate_on_connection_error(result)
        };
        tokio::select! {
            biased;
            error = self.stopped() => Err(error),
            result = work => result,
        }
    }

    pub(crate) fn cancel_stream(&self, stream_id: StreamId) {
        let should_send = self
            .decoder
            .lock()
            .expect("QPACK decoder lock poisoned")
            .cancel(stream_id);
        if should_send
            && let Err(error) = self.decoder_instructions.enqueue(
                instruction::DecoderInstruction::StreamCancellation(u64::from(stream_id)),
            )
        {
            let _ = self.terminate_on_connection_error::<()>(Err(error));
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
        self.terminate_on_connection_error(result)
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
        self.terminate_on_connection_error(result)
    }

    pub(crate) fn failure(&self) -> Option<Error> {
        self.terminal.borrow().clone()
    }

    pub(crate) async fn stopped(&self) -> Error {
        self.terminal
            .clone()
            .wait_for(Option::is_some)
            .await
            .expect("connection owns terminal sender")
            .clone()
            .unwrap()
    }

    pub(crate) async fn encode_fields(
        &self,
        stream_id: StreamId,
        fields: Vec<Field>,
    ) -> Result<Bytes, Error> {
        let work = async {
            let mut encoder = self.encoder.lock().await;
            if let Some(error) = self.failure() {
                return Err(error);
            }
            let result = async {
                futures::future::poll_fn(|cx| encoder.stream.poll_ready(cx))
                    .await
                    .map_err(|error| critical_error(error.into(), "QPACK encoder"))?;
                // No suspension between changing shared state and transport ownership.
                let encoded = encoder.state.encode(stream_id, fields)?;
                if !encoded.instructions.is_empty() {
                    encoder
                        .stream
                        .write(encoded.instructions)
                        .map_err(|error| critical_error(error.into(), "QPACK encoder"))?;
                }
                Ok(encoded.field_section)
            }
            .await;
            // Publish failure before another request can acquire the encoder.
            self.terminate_on_connection_error(result)
        };
        tokio::select! {
            biased;
            error = self.stopped() => Err(error),
            result = work => result,
        }
    }

    pub(crate) async fn decode_fields(
        &self,
        stream_id: StreamId,
        payload: &[u8],
    ) -> Result<Vec<Field>, Error> {
        loop {
            let notified = self.insertions.notified();
            if let Some(error) = self.failure() {
                return Err(error);
            }
            let decoded = self
                .decoder
                .lock()
                .expect("QPACK decoder lock poisoned")
                .decode(stream_id, payload);
            let decoded = match decoded {
                Ok(decoded) => decoded,
                Err(error) => return self.terminate_on_connection_error(Err(error)),
            };
            match decoded {
                decoder::Decode::Ready {
                    fields,
                    used_dynamic_table,
                } => {
                    if used_dynamic_table
                        && let Err(error) = self.decoder_instructions.enqueue(
                            instruction::DecoderInstruction::SectionAcknowledgement(u64::from(
                                stream_id,
                            )),
                        )
                    {
                        return self.terminate_on_connection_error(Err(error));
                    }
                    return Ok(fields);
                }
                decoder::Decode::Blocked => {
                    tokio::select! {
                        _ = notified => {}
                        error = self.stopped() => return Err(error),
                    }
                }
            }
        }
    }

    pub(super) fn terminate_on_connection_error<T>(
        &self,
        result: Result<T, Error>,
    ) -> Result<T, Error> {
        if let Err(error) = &result
            && error.is_connection()
        {
            (self.fail_connection)(error.clone());
        }
        result
    }
}

impl DecoderWriter {
    pub(crate) async fn run(mut self) -> Result<(), Error> {
        let work = async {
            while let Some(command) = self.commands.recv().await {
                let len = command.len();
                send_critical(&mut self.stream, command, "QPACK decoder").await?;
                self.queue.pending_bytes.fetch_sub(len, Ordering::AcqRel);
            }
            Ok(())
        };
        tokio::select! {
            biased;
            error = self.terminal.wait_for(Option::is_some) => Err(error.expect("connection owns terminal sender").clone().unwrap()),
            result = work => result,
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
            return Err(error);
        }
        if self.commands.send(bytes).is_err() {
            self.pending_bytes.fetch_sub(len, Ordering::AcqRel);
            let error = Error::connection_protocol(
                Code::H3_CLOSED_CRITICAL_STREAM,
                "local QPACK decoder instruction writer stopped",
            );
            return Err(error);
        }
        Ok(())
    }
}

async fn send_critical(
    stream: &mut StreamWriter,
    bytes: Bytes,
    name: &'static str,
) -> Result<(), Error> {
    stream
        .feed(bytes)
        .await
        .map_err(|error| critical_error(error.into(), name))
}

fn critical_error(error: crate::transport::StreamError, name: &'static str) -> Error {
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
    if value > VARINT_MAX {
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
        if value > VARINT_MAX {
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
    use std::time::Duration;

    use http::{HeaderValue, Method, StatusCode, Version, header::CONNECTION};

    use super::*;

    #[tokio::test]
    async fn cancelled_encoder_backpressure_preserves_peer_table() {
        use crate::protocol::test_streams::Streams;
        let streams = Streams::with_uni_credit(3);
        let (encoder_id, encoder_stream) = streams.writer();
        let (_, decoder_stream) = streams.writer();
        let (terminal, receiver) = watch::channel(None);
        let owner = Arc::new(std::sync::OnceLock::<std::sync::Weak<Qpack>>::new());
        let on_failure = owner.clone();
        let mut settings = Settings::default();
        settings.set_qpack_max_table_capacity(4096);
        let (qpack, _writer) = Qpack::new(
            &settings,
            encoder_stream,
            decoder_stream,
            receiver,
            Box::new(move |error| {
                let qpack = on_failure.get().unwrap().upgrade().unwrap();
                assert!(
                    qpack.encoder.try_lock().is_err(),
                    "failure must be published before unlocking shared state"
                );
                terminal.send_replace(Some(error));
            }),
        );
        owner.set(Arc::downgrade(&qpack)).unwrap();
        // Valid instructions fill the native send buffer without changing table contents.
        let capacity =
            instruction::encode_encoder(&instruction::EncoderInstruction::SetCapacity(4096))
                .unwrap();
        qpack
            .encoder
            .lock()
            .await
            .stream
            .write(capacity.clone())
            .unwrap();
        let mut configure = Box::pin(qpack.apply_peer_settings(&settings));
        assert!(futures::poll!(configure.as_mut()).is_pending());
        drop(configure);
        let credit = |value| {
            streams
                .data
                .recv_stream_control(
                    qbase::frame::MaxStreamDataFrame::new(
                        encoder_id,
                        qbase::varint::VarInt::from_u32(value),
                    )
                    .into(),
                )
                .unwrap()
        };
        credit(6);
        tokio::time::timeout(
            Duration::from_secs(2),
            streams.drive(qpack.apply_peer_settings(&settings)),
        )
        .await
        .unwrap()
        .unwrap();
        let field = |value| {
            vec![Field {
                name: Bytes::from_static(b"x-review"),
                value: Bytes::from_static(value),
            }]
        };
        let id = |value| StreamId::from(qbase::varint::VarInt::from_u32(value));
        let mut cancelled = Box::pin(qpack.encode_fields(id(0), field(b"one")));
        assert!(futures::poll!(cancelled.as_mut()).is_pending());
        drop(cancelled);
        credit(1024);
        let encoded = tokio::time::timeout(
            Duration::from_secs(2),
            streams.drive(qpack.encode_fields(id(4), field(b"two"))),
        )
        .await
        .unwrap()
        .unwrap();
        while !streams.drain().0.is_empty() {}
        let mut peer = decoder::Decoder::new(4096, 0, None);
        let mut bytes = BytesMut::new();
        for (frame, data) in streams.sent.lock().unwrap().iter() {
            if frame.stream_id() == encoder_id {
                bytes.extend_from_slice(data);
            }
        }
        while !bytes.is_empty() {
            let (command, consumed) = instruction::decode_encoder(&bytes).unwrap().unwrap();
            peer.apply(command).unwrap();
            bytes.advance(consumed);
        }
        assert!(
            matches!(peer.decode(id(4), &encoded).unwrap(), decoder::Decode::Ready { fields, .. } if fields == field(b"two"))
        );
        qpack
            .encoder
            .lock()
            .await
            .state
            .apply(instruction::DecoderInstruction::InsertCountIncrement(1))
            .unwrap();
        let encoded = qpack.encode_fields(id(8), field(b"two")).await.unwrap();
        assert!(
            matches!(peer.decode(id(8), &encoded).unwrap(), decoder::Decode::Ready { fields, used_dynamic_table: true } if fields == field(b"two"))
        );
        dquic::prelude::CancelStream::cancel(
            &mut qpack.encoder.lock().await.stream,
            Code::H3_REQUEST_CANCELLED.as_u64(),
        );
        let error = qpack
            .encode_fields(id(12), field(b"three"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(Code::H3_CLOSED_CRITICAL_STREAM));
        assert_eq!(qpack.failure().unwrap().code(), error.code());
        assert_eq!(
            qpack
                .encode_fields(id(16), Vec::new())
                .await
                .unwrap_err()
                .code(),
            error.code()
        );
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
        let (terminal, subscription) = watch::channel(None);
        let (qpack, writer) = Qpack::new(
            &settings,
            crate::protocol::test_streams::writer(),
            crate::protocol::test_streams::writer(),
            subscription,
            Box::new(|_| {}),
        );
        let writing = tokio::spawn(writer.run());
        let blocked = {
            let qpack = Arc::clone(&qpack);
            tokio::spawn(async move {
                qpack
                    .decode_fields(
                        crate::StreamId::from(qbase::varint::VarInt::from_u32(0)),
                        &[2, 0, 0x80],
                    )
                    .await
            })
        };
        tokio::task::yield_now().await;

        terminal.send_replace(Some(Error::connection_protocol(
            Code::H3_INTERNAL_ERROR,
            "connection closed",
        )));

        let error = tokio::time::timeout(Duration::from_millis(100), blocked)
            .await
            .expect("blocked QPACK decode did not observe connection failure")
            .expect("decode task panicked")
            .expect_err("connection failure must abort blocked decoding");
        assert!(matches!(&error, Error::Connection { .. }));
        assert_eq!(error.code(), Some(Code::H3_INTERNAL_ERROR));
        assert_eq!(writing.await.unwrap().unwrap_err().code(), error.code());
    }

    #[tokio::test]
    async fn decoder_queue_overflow_notifies_the_same_terminal_subscription() {
        let mut settings = Settings::default();
        settings.set_qpack_max_table_capacity(256);
        settings.set_qpack_blocked_streams(1);
        let (terminal, subscription) = watch::channel(None);
        let reported = terminal.clone();
        let (qpack, writer) = Qpack::new(
            &settings,
            crate::protocol::test_streams::writer(),
            crate::protocol::test_streams::writer(),
            subscription,
            Box::new(move |error| {
                reported.send_replace(Some(error));
            }),
        );
        let id = StreamId::from(qbase::varint::VarInt::from_u32(0));
        let mut blocked = Box::pin(qpack.decode_fields(id, &[2, 0, 0x80]));
        assert!(futures::poll!(blocked.as_mut()).is_pending());
        for _ in 0..MAX_PENDING_DECODER_INSTRUCTION_BYTES {
            qpack
                .decoder_instructions
                .enqueue(instruction::DecoderInstruction::InsertCountIncrement(1))
                .unwrap();
        }
        qpack.cancel_stream(id);
        assert_eq!(
            terminal.borrow().as_ref().and_then(Error::code),
            Some(Code::H3_EXCESSIVE_LOAD)
        );
        assert_eq!(
            blocked.await.unwrap_err().code(),
            Some(Code::H3_EXCESSIVE_LOAD)
        );
        assert_eq!(
            writer.run().await.unwrap_err().code(),
            Some(Code::H3_EXCESSIVE_LOAD)
        );
    }

    #[tokio::test]
    async fn incomplete_encoder_instruction_is_bounded_by_table_capacity() {
        let settings = Settings::default();
        let (failure, subscription) = watch::channel(None);
        let reported = failure.clone();
        let (qpack, _writer) = Qpack::new(
            &settings,
            crate::protocol::test_streams::writer(),
            crate::protocol::test_streams::writer(),
            subscription,
            Box::new(move |error| {
                reported.send_replace(Some(error));
            }),
        );
        let mut instruction = vec![0x5f, 69];
        instruction.extend(std::iter::repeat_n(0, 63));

        let error = qpack
            .handle_encoder_stream(ChunkReader::new(
                crate::StreamId::from(qbase::varint::VarInt::from_u32(6)),
                crate::protocol::test_streams::reader([Ok(Bytes::from(instruction))]),
            ))
            .await
            .expect_err("an incomplete instruction cannot grow without a bound");

        assert!(matches!(&error, Error::Connection { .. }));
        assert_eq!(error.code(), Some(Code::QPACK_ENCODER_STREAM_ERROR));
        assert_eq!(
            failure.borrow().as_ref().and_then(Error::code),
            error.code()
        );
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
