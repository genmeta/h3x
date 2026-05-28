pub mod algorithm;
pub mod decoder;
pub mod dynamic;
pub mod encoder;
pub mod field;
pub mod instruction;
pub mod integer;
pub mod protocol;
pub mod settings;
pub mod r#static;
pub mod string;

#[cfg(all(test, feature = "hyper"))]
mod tests {
    use std::{pin::pin, sync::Arc};

    use bytes::Bytes;
    use futures::SinkExt;
    use http::{HeaderMap, HeaderValue, Request, Response};
    use tokio::{io::AsyncReadExt, sync::Notify, time};

    use crate::{
        codec::{DecodeExt, EncodeExt, SinkWriter, StreamReader},
        dhttp::{
            frame::{Frame, stream::FrameStream},
            settings::Settings,
            stream::UnidirectionalStream,
        },
        qpack::{
            algorithm::{Algorithm, DynamicCompressAlgo, HuffmanAlways, StaticCompressAlgo},
            decoder::{Decoder, MessageStreamReader},
            encoder::Encoder,
            field::FieldSection,
        },
        quic::{
            ConnectionError,
            test::{mock_stream_pair, mock_stream_pair_with_capacity},
        },
        util::deferred::Deferred,
        varint::VarInt,
    };

    #[tokio::test]
    async fn r#static() {
        _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
        let encode_strategy = StaticCompressAlgo::new(HuffmanAlways);

        // stream id is unused in this test
        let (encoder_stream_reader, encoder_stream_writer) = mock_stream_pair(VarInt::from_u32(1));
        let (decoder_stream_reader, decoder_stream_writer) = mock_stream_pair(VarInt::from_u32(2));

        let init_encoder = tokio::spawn(async move {
            let encoder_stream = UnidirectionalStream::initial(
                UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE,
                SinkWriter::new(encoder_stream_writer),
            )
            .await
            .unwrap();
            tracing::trace!("sent encoder stream type");

            let decoder_stream = Box::pin(Deferred::from(async move {
                let decoder_stream = StreamReader::new(decoder_stream_reader)
                    .decode::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    decoder_stream.r#type(),
                    UnidirectionalStream::QPACK_DECODER_STREAM_TYPE
                );
                tracing::trace!("received decoder stream type");
                Ok::<_, ConnectionError>(decoder_stream)
            }));

            Arc::new(Encoder::new(
                Arc::<Settings>::default(),
                Box::pin((encoder_stream).into_encode_sink()),
                Box::pin((decoder_stream).into_decode_stream()),
            ))
        });

        let init_decoder = tokio::spawn(async move {
            let decoder_stream = UnidirectionalStream::initial(
                UnidirectionalStream::QPACK_DECODER_STREAM_TYPE,
                SinkWriter::new(decoder_stream_writer),
            )
            .await
            .unwrap();
            tracing::trace!("sent decoder stream type");

            let encoder_stream = Box::pin(Deferred::from(async move {
                let encoder_stream = StreamReader::new(encoder_stream_reader)
                    .decode::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    encoder_stream.r#type(),
                    UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE
                );
                tracing::trace!("received encoder stream type");
                Ok::<_, ConnectionError>(encoder_stream)
            }));

            Arc::new(Decoder::new(
                Arc::new(Settings::default()),
                Box::pin((decoder_stream).into_encode_sink()),
                Box::pin((encoder_stream).into_decode_stream()),
            ))
        });

        let (encoder, decoder) = time::timeout(time::Duration::from_secs(1), async move {
            tokio::try_join!(init_encoder, init_decoder).unwrap()
        })
        .await
        .expect("test timedout");

        let request = Request::builder()
            .method("POST")
            .uri("https://h3x.demo.lab.genmeta.net/api/v1/upload")
            .header("user-agent", "genemta-curl/0.3.0")
            .header("accept", "*/*")
            .body("Hello, World!")
            .unwrap();

        let (parts, body) = request.into_parts();
        let field_section = FieldSection::from(parts);

        let expected_field_section = field_section.clone();

        let received = Arc::new(Notify::new());
        let received_rx = received.clone();

        let (response_stream, request_stream) = mock_stream_pair(VarInt::from_u32(0));
        let request = tokio::spawn(async move {
            let mut request_stream = SinkWriter::new(request_stream);

            let header_frame = Encoder::encode(
                &*encoder,
                field_section.iter(),
                &encode_strategy,
                &mut request_stream,
            )
            .await
            .unwrap();
            request_stream.encode_one(header_frame).await.unwrap();

            tracing::trace!("header frame sent");

            let frame_payload = Bytes::from_static(body.as_bytes());
            let data_frame = Frame::new(Frame::DATA_FRAME_TYPE, frame_payload).unwrap();
            request_stream.encode_one(data_frame).await.unwrap();
            request_stream.flush().await.unwrap();
            tracing::trace!("data frame sent");

            received_rx.notified().await;
        });

        let response = tokio::spawn(async move {
            let response_stream = MessageStreamReader::new(response_stream, decoder.clone());

            let mut frame_stream = pin!(FrameStream::new(StreamReader::new(response_stream)));
            let frame = frame_stream.as_mut().next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::HEADERS_FRAME_TYPE);
            let field_section = Decoder::decode(&*decoder, frame).await.unwrap();
            assert_eq!(field_section, expected_field_section);
            tracing::trace!(?field_section, "decoded field section",);

            let mut frame = frame_stream.next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::DATA_FRAME_TYPE);
            tracing::trace!("got data frame, reading");

            let mut data = Vec::new();
            frame.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, body.as_bytes());
            tracing::trace!("read data frame");

            received.notify_one();
        });

        time::timeout(time::Duration::from_secs(1), async move {
            tokio::try_join!(request, response).unwrap()
        })
        .await
        .expect("test timedout");
    }

    #[tokio::test]
    async fn static_response_trailer_and_empty_field_sections_roundtrip() {
        let encode_strategy = StaticCompressAlgo::new(HuffmanAlways);

        let (encoder_stream_reader, encoder_stream_writer) =
            mock_stream_pair_with_capacity(VarInt::from_u32(1), 64);
        let (decoder_stream_reader, decoder_stream_writer) =
            mock_stream_pair_with_capacity(VarInt::from_u32(2), 64);

        let init_encoder = tokio::spawn(async move {
            let encoder_stream = UnidirectionalStream::initial(
                UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE,
                SinkWriter::new(encoder_stream_writer),
            )
            .await
            .unwrap();

            let decoder_stream = Box::pin(Deferred::from(async move {
                let decoder_stream = StreamReader::new(decoder_stream_reader)
                    .decode::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    decoder_stream.r#type(),
                    UnidirectionalStream::QPACK_DECODER_STREAM_TYPE
                );
                Ok::<_, ConnectionError>(decoder_stream)
            }));

            Arc::new(Encoder::new(
                Arc::<Settings>::default(),
                Box::pin((encoder_stream).into_encode_sink()),
                Box::pin((decoder_stream).into_decode_stream()),
            ))
        });

        let init_decoder = tokio::spawn(async move {
            let decoder_stream = UnidirectionalStream::initial(
                UnidirectionalStream::QPACK_DECODER_STREAM_TYPE,
                SinkWriter::new(decoder_stream_writer),
            )
            .await
            .unwrap();

            let encoder_stream = Box::pin(Deferred::from(async move {
                let encoder_stream = StreamReader::new(encoder_stream_reader)
                    .decode::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    encoder_stream.r#type(),
                    UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE
                );
                Ok::<_, ConnectionError>(encoder_stream)
            }));

            Arc::new(Decoder::new(
                Arc::new(Settings::default()),
                Box::pin((decoder_stream).into_encode_sink()),
                Box::pin((encoder_stream).into_decode_stream()),
            ))
        });

        let (encoder, decoder) = time::timeout(time::Duration::from_secs(1), async move {
            tokio::try_join!(init_encoder, init_decoder).unwrap()
        })
        .await
        .expect("setup timed out");

        let response = Response::builder()
            .status(204)
            .header("server", "h3x-test")
            .header("cache-control", "no-store")
            .body(())
            .unwrap();
        let (response_parts, ()) = response.into_parts();

        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", HeaderValue::from_static("sha256:abc123"));
        trailers.insert("x-empty", HeaderValue::from_static(""));

        let cases = [
            (VarInt::from_u32(4), FieldSection::from(response_parts)),
            (VarInt::from_u32(8), FieldSection::trailer(trailers)),
            (
                VarInt::from_u32(12),
                FieldSection::trailer(HeaderMap::new()),
            ),
        ];

        for (stream_id, field_section) in cases {
            let expected = field_section.clone();
            let (read_stream, write_stream) = mock_stream_pair_with_capacity(stream_id, 64);
            let mut write_stream = SinkWriter::new(write_stream);

            let header_frame = Encoder::encode(
                &*encoder,
                field_section.iter(),
                &encode_strategy,
                &mut write_stream,
            )
            .await
            .unwrap();
            write_stream.encode_one(header_frame).await.unwrap();
            write_stream.flush().await.unwrap();

            let read_stream = MessageStreamReader::new(read_stream, decoder.clone());
            let mut frame_stream = pin!(FrameStream::new(StreamReader::new(read_stream)));
            let frame = frame_stream.as_mut().next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::HEADERS_FRAME_TYPE);

            let decoded = Decoder::decode(&*decoder, frame).await.unwrap();
            assert_eq!(decoded, expected);
        }
    }

    fn settings_with_dynamic_table() -> Arc<Settings> {
        let mut settings = Settings::default();
        settings.set(crate::qpack::settings::QpackMaxTableCapacity::setting(
            VarInt::from_u32(4096),
        ));
        settings.set(crate::qpack::settings::QpackBlockedStreams::setting(
            VarInt::from_u32(100),
        ));
        Arc::new(settings)
    }

    #[tokio::test]
    async fn settings_with_dynamic_table_enables_qpack_limits() {
        let settings = settings_with_dynamic_table();

        assert_eq!(settings.qpack_max_table_capacity(), VarInt::from_u32(4096));
        assert_eq!(settings.qpack_blocked_streams(), VarInt::from_u32(100));
    }

    #[test]
    fn qpack_error_displays_and_connection_codes_are_stable() {
        use crate::{
            error::{Code, H3ConnectionError},
            qpack::{
                decoder::{InvalidDynamicTableReference, QPackEncoderStreamError},
                encoder::{QPackDecoderStreamError, QPackEncoderError},
                protocol::{QPackProtocolDisabled, QPackProtocolFactory},
            },
        };

        let decoder_stream_error =
            QPackDecoderStreamError::AcknowledgeNonExistSection { stream_id: 99 };
        assert_eq!(
            decoder_stream_error.to_string(),
            "acknowledging non-existent or non-blocking stream"
        );
        assert_eq!(
            decoder_stream_error.code(),
            Code::QPACK_DECODER_STREAM_ERROR
        );
        assert_eq!(
            QPackDecoderStreamError::IncrementKnownReceivedCountOverflow.to_string(),
            "known received count increment overflow (known_received_count + increment > inserted_count)"
        );
        assert_eq!(
            QPackDecoderStreamError::IncrementZero.to_string(),
            "insert count increment of zero is not allowed"
        );

        assert_eq!(
            QPackEncoderError::CapacityExceedsMax {
                capacity: 2,
                max: 1,
            }
            .to_string(),
            "dynamic table capacity 2 exceeds SETTINGS_QPACK_MAX_TABLE_CAPACITY 1"
        );
        assert_eq!(
            QPackEncoderError::CannotEvict.to_string(),
            "cannot evict entries: no evictable entries in dynamic table"
        );

        let encoder_stream_error =
            QPackEncoderStreamError::ReferencedStaticEntryNotExisted { index: 100 };
        assert_eq!(
            encoder_stream_error.to_string(),
            "referenced static table entry 100 does not exist"
        );
        assert_eq!(
            encoder_stream_error.code(),
            Code::QPACK_ENCODER_STREAM_ERROR
        );
        assert_eq!(
            QPackEncoderStreamError::SetDynamicTableCapacityExceeded.to_string(),
            "setting dynamic table capacity exceeded maximum allowed"
        );
        assert_eq!(
            QPackEncoderStreamError::NoEvictableEntryForInsertion.to_string(),
            "no evictable entry for insertion, cannot insert new entry"
        );
        assert_eq!(
            QPackEncoderStreamError::ReferencedDynamicEntryNotExisted { index: 7 }.to_string(),
            "referenced dynamic table entry 7 does not exist"
        );

        let invalid_reference = InvalidDynamicTableReference::IndexOverflow;
        assert_eq!(invalid_reference.to_string(), "reference index overflow");
        assert_eq!(invalid_reference.code(), Code::QPACK_DECOMPRESSION_FAILED);
        assert_eq!(
            InvalidDynamicTableReference::ReferencedStaticEntryNotExisted { index: 99 }.to_string(),
            "referenced static table entry 99 does not exist"
        );
        assert_eq!(
            InvalidDynamicTableReference::ReferencedDynamicEntryNotExisted { index: 8 }.to_string(),
            "referenced dynamic table entry 8 does not exist"
        );

        assert_eq!(QPackProtocolFactory::new().to_string(), "QPACK");
        assert_eq!(
            QPackProtocolDisabled.to_string(),
            "qpack protocol is disabled"
        );
    }

    #[test]
    fn encoder_state_rejects_invalid_capacity_ack_and_increment_paths() {
        use crate::qpack::encoder::{EncoderState, QPackDecoderStreamError, QPackEncoderError};

        let settings = settings_with_dynamic_table();
        let mut encoder_state = EncoderState::new(settings);

        let capacity_error = encoder_state
            .set_max_table_capacity(4097)
            .expect_err("capacity above peer setting must be rejected");
        assert!(matches!(
            capacity_error,
            QPackEncoderError::CapacityExceedsMax {
                capacity: 4097,
                max: 4096
            }
        ));

        encoder_state
            .set_max_table_capacity(64)
            .expect("capacity within peer setting");
        encoder_state
            .insert_with_literal_name(
                false,
                Bytes::from_static(b"x-unacked"),
                false,
                Bytes::from_static(b"value"),
            )
            .expect("insert should fit the dynamic table");

        let shrink_error = encoder_state
            .set_max_table_capacity(0)
            .expect_err("unacknowledged entry is not evictable");
        assert!(matches!(shrink_error, QPackEncoderError::CannotEvict));
        assert_eq!(encoder_state.table_inserted_count(), 1);
        assert_eq!(encoder_state.table_dropped_count(), 0);

        let ack_error = encoder_state
            .on_section_acknowledgment(VarInt::from_u32(4).into_inner())
            .expect_err("unknown stream id must not be acknowledged");
        assert!(matches!(
            ack_error,
            QPackDecoderStreamError::AcknowledgeNonExistSection { stream_id: 4 }
        ));

        let zero_increment = encoder_state
            .on_insert_count_increment(0)
            .expect_err("zero insert count increment is a decoder stream error");
        assert!(matches!(
            zero_increment,
            QPackDecoderStreamError::IncrementZero
        ));

        let overflow_increment = encoder_state
            .on_insert_count_increment(2)
            .expect_err("increment beyond inserted-known count must fail");
        assert!(matches!(
            overflow_increment,
            QPackDecoderStreamError::IncrementKnownReceivedCountOverflow
        ));
    }

    #[test]
    fn decoder_state_rejects_invalid_encoder_stream_operations() {
        use crate::qpack::decoder::{DecoderState, QPackEncoderStreamError};

        let settings = settings_with_dynamic_table();
        let mut decoder_state = DecoderState::new(settings);

        let capacity_error = decoder_state
            .set_dynamic_table_capacity(4097)
            .expect_err("capacity above local setting must be rejected");
        assert!(matches!(
            capacity_error,
            QPackEncoderStreamError::SetDynamicTableCapacityExceeded
        ));

        let missing_static = decoder_state
            .insert_with_name_reference(true, 99, Bytes::from_static(b"value"))
            .expect_err("invalid static table name reference must fail");
        assert!(matches!(
            missing_static,
            QPackEncoderStreamError::ReferencedStaticEntryNotExisted { index: 99 }
        ));

        let missing_dynamic = decoder_state
            .insert_with_name_reference(false, 0, Bytes::from_static(b"value"))
            .expect_err("invalid dynamic table name reference must fail");
        assert!(matches!(
            missing_dynamic,
            QPackEncoderStreamError::ReferencedDynamicEntryNotExisted { index: 0 }
        ));

        decoder_state
            .set_dynamic_table_capacity(0)
            .expect("zero capacity is within settings");
        let no_space = decoder_state
            .insert_with_literal_name(Bytes::from_static(b"x-too-large"), Bytes::new())
            .expect_err("entry cannot fit in a zero-capacity dynamic table");
        assert!(matches!(
            no_space,
            QPackEncoderStreamError::NoEvictableEntryForInsertion
        ));

        let missing_duplicate = decoder_state
            .duplicate(0)
            .expect_err("invalid duplicate reference must fail");
        assert!(matches!(
            missing_duplicate,
            QPackEncoderStreamError::ReferencedDynamicEntryNotExisted { index: 0 }
        ));
    }

    #[test]
    fn encoded_field_section_prefix_handles_boundary_values() {
        use crate::{codec::DecodeError, qpack::field::EncodedFieldSectionPrefix};

        assert_eq!(EncodedFieldSectionPrefix::encode_ric(0, 4096), 0);
        assert_eq!(
            EncodedFieldSectionPrefix::encode_ric(1, 0),
            1,
            "non-zero RIC with disabled dynamic table is preserved as an invalid wire value"
        );
        assert_eq!(
            EncodedFieldSectionPrefix::decode_ric(1, 0, 0),
            Err(DecodeError::DecompressionFailed)
        );
        assert_eq!(
            EncodedFieldSectionPrefix::decode_ric(3, 32, 0),
            Err(DecodeError::DecompressionFailed)
        );
        assert_eq!(
            EncodedFieldSectionPrefix::resolve_base(u64::MAX, false, 1),
            Err(DecodeError::ArithmeticOverflow)
        );
        assert_eq!(
            EncodedFieldSectionPrefix::resolve_base(0, true, 0),
            Err(DecodeError::ArithmeticOverflow)
        );
    }

    fn apply_pending_encoder_instructions(
        encoder_state: &mut crate::qpack::encoder::EncoderState,
        decoder_state: &mut crate::qpack::decoder::DecoderState,
    ) {
        use crate::qpack::encoder::EncoderInstruction;

        while let Some(instruction) = encoder_state.pending_instructions.pop_front() {
            match instruction {
                EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                    decoder_state.set_dynamic_table_capacity(capacity).unwrap();
                }
                EncoderInstruction::InsertWithNameReference {
                    is_static,
                    name_index,
                    value,
                    ..
                } => {
                    let abs_index = if is_static {
                        name_index
                    } else {
                        decoder_state.table_inserted_count() - name_index - 1
                    };
                    decoder_state
                        .insert_with_name_reference(is_static, abs_index, value)
                        .unwrap();
                }
                EncoderInstruction::InsertWithLiteralName { name, value, .. } => {
                    decoder_state.insert_with_literal_name(name, value).unwrap();
                }
                EncoderInstruction::Duplicate { index } => {
                    let abs_index = decoder_state.table_inserted_count() - index - 1;
                    decoder_state.duplicate(abs_index).unwrap();
                }
            }
        }
    }

    #[test]
    fn apply_pending_encoder_instructions_replays_duplicate_entries() {
        use crate::qpack::{decoder::DecoderState, encoder::EncoderState};

        let settings = settings_with_dynamic_table();
        let mut encoder_state = EncoderState::new(settings.clone());
        encoder_state
            .set_max_table_capacity(4096)
            .expect("set encoder capacity");
        let original_index = encoder_state
            .insert_with_literal_name(
                false,
                Bytes::from_static(b"x-duplicate"),
                false,
                Bytes::from_static(b"value"),
            )
            .expect("insert original entry");
        let duplicated_index = encoder_state
            .duplicate(original_index)
            .expect("duplicate original entry");
        let mut decoder_state = DecoderState::new(settings);

        apply_pending_encoder_instructions(&mut encoder_state, &mut decoder_state);

        assert_eq!(decoder_state.table_inserted_count(), duplicated_index + 1);
        assert_eq!(
            decoder_state.dynamic_table.get(duplicated_index),
            Some(&crate::qpack::field::FieldLine {
                name: Bytes::from_static(b"x-duplicate"),
                value: Bytes::from_static(b"value"),
            })
        );
    }

    #[tokio::test]
    async fn dynamic_response_trailer_and_empty_field_sections_roundtrip() {
        use crate::qpack::{
            decoder::DecoderState,
            encoder::EncoderState,
            field::{EncodedFieldSectionPrefix, FieldLine},
        };

        let settings = settings_with_dynamic_table();
        let mut encoder_state = EncoderState::new(settings.clone());
        encoder_state
            .set_max_table_capacity(4096)
            .expect("set encoder capacity");

        let mut decoder_state = DecoderState::new(settings.clone());
        apply_pending_encoder_instructions(&mut encoder_state, &mut decoder_state);

        let encode_strategy = DynamicCompressAlgo::new(HuffmanAlways);

        let response = Response::builder()
            .status(201)
            .header("server", "h3x-dynamic-test")
            .header("x-dynamic-name", "first")
            .header("cache-control", "no-store")
            .body(())
            .unwrap();
        let (response_parts, ()) = response.into_parts();

        let mut trailers = HeaderMap::new();
        trailers.insert("x-dynamic-name", HeaderValue::from_static("second"));
        trailers.insert("x-trailer-only", HeaderValue::from_static("present"));

        let cases = [
            FieldSection::from(response_parts),
            FieldSection::trailer(trailers),
            FieldSection::trailer(HeaderMap::new()),
        ];

        for field_section in cases {
            let expected: Vec<FieldLine> = field_section.iter().collect();
            let output = encode_strategy
                .compress(&mut encoder_state, field_section.iter(), true)
                .await;
            apply_pending_encoder_instructions(&mut encoder_state, &mut decoder_state);

            let required_insert_count = EncodedFieldSectionPrefix::decode_ric(
                output.prefix.encoded_insert_count,
                settings.qpack_max_table_capacity().into_inner(),
                decoder_state.table_inserted_count(),
            )
            .expect("decode required insert count");
            let base = EncodedFieldSectionPrefix::resolve_base(
                required_insert_count,
                output.prefix.sign,
                output.prefix.delta_base,
            )
            .expect("resolve base");

            let decoded: Vec<FieldLine> = output
                .representations
                .iter()
                .map(|repr| decoder_state.decompress(repr, base).expect("decompress"))
                .collect();
            assert_eq!(decoded, expected);
        }

        assert_eq!(encoder_state.table_capacity(), 4096);
        assert!(
            encoder_state.table_inserted_count() >= 3,
            "dynamic response/trailer roundtrip should insert reusable table entries"
        );
        assert_eq!(
            decoder_state.table_inserted_count(),
            encoder_state.table_inserted_count()
        );
    }

    /// Direct roundtrip test: encode with DynamicCompressAlgo, then decode using
    /// the decoder state. Bypasses mock streams to test the algorithm itself.
    #[tokio::test]
    async fn dynamic_roundtrip() {
        use crate::qpack::{
            algorithm::{Algorithm, DynamicCompressAlgo, HuffmanAlways},
            decoder::DecoderState,
            encoder::EncoderState,
            field::{EncodedFieldSectionPrefix, FieldLine},
        };

        let settings = settings_with_dynamic_table();
        let mut encoder_state = EncoderState::new(settings.clone());
        encoder_state
            .set_max_table_capacity(4096)
            .expect("set capacity");

        let mut decoder_state = DecoderState::new(settings.clone());
        decoder_state.set_dynamic_table_capacity(4096).unwrap();

        let algo = DynamicCompressAlgo::new(HuffmanAlways);

        // Encode a set of field lines
        let field_lines = vec![
            FieldLine {
                name: Bytes::from_static(b":method"),
                value: Bytes::from_static(b"GET"),
            },
            FieldLine {
                name: Bytes::from_static(b":path"),
                value: Bytes::from_static(b"/api/v1/resource"),
            },
            FieldLine {
                name: Bytes::from_static(b":authority"),
                value: Bytes::from_static(b"example.com"),
            },
            FieldLine {
                name: Bytes::from_static(b"x-custom-header"),
                value: Bytes::from_static(b"custom-value"),
            },
            FieldLine {
                name: Bytes::from_static(b"authorization"),
                value: Bytes::from_static(b"Bearer token123"),
            },
        ];

        let output = algo
            .compress(&mut encoder_state, field_lines.clone(), true)
            .await;

        // Apply encoder instructions to decoder state
        // (simulates instructions arriving via encoder stream)
        apply_pending_encoder_instructions(&mut encoder_state, &mut decoder_state);

        // Decode the RIC to get required_insert_count
        let max_table_capacity = settings.qpack_max_table_capacity().into_inner();
        let total_inserts = decoder_state.table_inserted_count();
        let required_insert_count = EncodedFieldSectionPrefix::decode_ric(
            output.prefix.encoded_insert_count,
            max_table_capacity,
            total_inserts,
        )
        .expect("decode_ric");

        // Resolve base
        let base = EncodedFieldSectionPrefix::resolve_base(
            required_insert_count,
            output.prefix.sign,
            output.prefix.delta_base,
        )
        .expect("resolve_base");

        // Decompress each field line representation
        let decoded: Vec<FieldLine> = output
            .representations
            .iter()
            .map(|repr| decoder_state.decompress(repr, base).expect("decompress"))
            .collect();

        assert_eq!(decoded.len(), field_lines.len());
        for (original, decoded) in field_lines.iter().zip(decoded.iter()) {
            assert_eq!(original.name, decoded.name, "name mismatch");
            assert_eq!(original.value, decoded.value, "value mismatch");
        }

        // Verify dynamic table was used (entries were inserted)
        assert!(
            encoder_state.table_inserted_count() > 0,
            "expected dynamic table insertions"
        );

        // Verify sensitive header was NOT inserted
        // :method GET and accept */* are static matches, authorization is sensitive
        // :path, :authority, x-custom-header should be inserted
        assert_eq!(
            encoder_state.table_inserted_count(),
            3,
            "expected 3 insertions (:path, :authority, x-custom-header)"
        );
    }

    /// Full E2E roundtrip test with dynamic compression using real streams.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dynamic_e2e_roundtrip() {
        _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        let settings = settings_with_dynamic_table();
        let encode_strategy = DynamicCompressAlgo::new(HuffmanAlways);

        // Use larger buffer (256) for dynamic encoder instructions
        let (encoder_stream_reader, encoder_stream_writer) =
            mock_stream_pair_with_capacity(VarInt::from_u32(1), 256);
        let (decoder_stream_reader, decoder_stream_writer) =
            mock_stream_pair_with_capacity(VarInt::from_u32(2), 256);

        let enc_settings = settings.clone();
        let dec_settings = settings;

        let init_encoder = tokio::spawn(async move {
            let encoder_stream = UnidirectionalStream::initial(
                UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE,
                SinkWriter::new(encoder_stream_writer),
            )
            .await
            .unwrap();

            let decoder_stream = Box::pin(Deferred::from(async move {
                let decoder_stream = StreamReader::new(decoder_stream_reader)
                    .decode::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    decoder_stream.r#type(),
                    UnidirectionalStream::QPACK_DECODER_STREAM_TYPE
                );
                Ok::<_, ConnectionError>(decoder_stream)
            }));

            Arc::new(Encoder::new(
                enc_settings,
                Box::pin((encoder_stream).into_encode_sink()),
                Box::pin((decoder_stream).into_decode_stream()),
            ))
        });

        let init_decoder = tokio::spawn(async move {
            let decoder_stream = UnidirectionalStream::initial(
                UnidirectionalStream::QPACK_DECODER_STREAM_TYPE,
                SinkWriter::new(decoder_stream_writer),
            )
            .await
            .unwrap();

            let encoder_stream = Box::pin(Deferred::from(async move {
                let encoder_stream = StreamReader::new(encoder_stream_reader)
                    .decode::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    encoder_stream.r#type(),
                    UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE
                );
                Ok::<_, ConnectionError>(encoder_stream)
            }));

            Arc::new(Decoder::new(
                dec_settings,
                Box::pin((decoder_stream).into_encode_sink()),
                Box::pin((encoder_stream).into_decode_stream()),
            ))
        });

        let (encoder, decoder) = time::timeout(time::Duration::from_secs(1), async move {
            tokio::try_join!(init_encoder, init_decoder).unwrap()
        })
        .await
        .expect("setup timed out");

        let request = Request::builder()
            .method("POST")
            .uri("https://h3x.demo.lab.genmeta.net/api/v1/upload")
            .header("user-agent", "genmeta-curl/0.3.0")
            .header("accept", "*/*")
            .header("x-custom-header", "custom-value")
            .body("Hello, World!")
            .unwrap();

        let (parts, body) = request.into_parts();
        let field_section = FieldSection::from(parts);
        let expected_field_section = field_section.clone();

        let received = Arc::new(Notify::new());
        let received_rx = received.clone();

        let (response_stream, request_stream) = mock_stream_pair(VarInt::from_u32(0));

        let encoder_clone = encoder.clone();
        let request_task = tokio::spawn(async move {
            let mut request_stream = SinkWriter::new(request_stream);

            let header_frame = Encoder::encode(
                &*encoder_clone,
                field_section.iter(),
                &encode_strategy,
                &mut request_stream,
            )
            .await
            .unwrap();
            request_stream.encode_one(header_frame).await.unwrap();
            tracing::trace!("header frame sent (dynamic)");

            // Flush encoder instructions through the real encoder stream
            encoder_clone.flush_instructions().await.unwrap();
            tracing::trace!("encoder instructions flushed");

            let frame_payload = Bytes::from_static(body.as_bytes());
            let data_frame = Frame::new(Frame::DATA_FRAME_TYPE, frame_payload).unwrap();
            request_stream.encode_one(data_frame).await.unwrap();
            request_stream.flush().await.unwrap();
            tracing::trace!("data frame sent");

            received_rx.notified().await;
        });

        let response_task = tokio::spawn(async move {
            let response_stream = MessageStreamReader::new(response_stream, decoder.clone());

            let mut frame_stream = pin!(FrameStream::new(StreamReader::new(response_stream)));
            let frame = frame_stream.as_mut().next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::HEADERS_FRAME_TYPE);
            let field_section = Decoder::decode(&*decoder, frame).await.unwrap();
            assert_eq!(field_section, expected_field_section);
            tracing::trace!(?field_section, "decoded field section (dynamic)");

            let mut frame = frame_stream.next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::DATA_FRAME_TYPE);

            let mut data = Vec::new();
            frame.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, body.as_bytes());
            tracing::trace!("read data frame");

            received.notify_one();
        });

        time::timeout(time::Duration::from_secs(5), async move {
            tokio::try_join!(request_task, response_task).unwrap()
        })
        .await
        .expect("dynamic_e2e_roundtrip timed out");
    }
}
