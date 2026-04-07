pub mod algorithm;
pub mod decoder;
pub mod dynamic;
pub mod encoder;
pub mod field;
pub mod instruction;
pub mod integer;
pub mod protocol;
pub mod r#static;
pub mod string;

#[cfg(all(test, feature = "hyper"))]
mod tests {
    use std::{pin::pin, sync::Arc};

    use bytes::Bytes;
    use futures::SinkExt;
    use http::Request;
    use tokio::{io::AsyncReadExt, sync::Notify, time};

    use crate::{
        codec::{DecodeExt, EncodeExt, SinkWriter, StreamReader},
        dhttp::{
            frame::{Frame, stream::FrameStream},
            settings::{QpackBlockedStreams, QpackMaxTableCapacity, Settings},
            stream::UnidirectionalStream,
        },
        qpack::{
            algorithm::{DynamicCompressAlgo, HuffmanAlways, StaticCompressAlgo},
            decoder::{Decoder, MessageStreamReader},
            encoder::Encoder,
            field::FieldSection,
        },
        quic::{
            ConnectionError,
            test::{mock_stream_pair, mock_stream_pair_with_capacity},
        },
        util::try_future::TryFuture,
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
            tracing::info!("sent encoder stream type");

            let decoder_stream = Box::pin(TryFuture::from(async move {
                let decoder_stream = StreamReader::new(decoder_stream_reader)
                    .decode::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    decoder_stream.r#type(),
                    UnidirectionalStream::QPACK_DECODER_STREAM_TYPE
                );
                tracing::info!("received decoder stream type");
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
            tracing::info!("sent decoder stream type");

            let encoder_stream = Box::pin(TryFuture::from(async move {
                let encoder_stream = StreamReader::new(encoder_stream_reader)
                    .decode::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    encoder_stream.r#type(),
                    UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE
                );
                tracing::info!("received encoder stream type");
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

            tracing::info!("header frame sent");

            let frame_payload = Bytes::from_static(body.as_bytes());
            let data_frame = Frame::new(Frame::DATA_FRAME_TYPE, frame_payload).unwrap();
            request_stream.encode_one(data_frame).await.unwrap();
            request_stream.flush().await.unwrap();
            tracing::info!("data frame sent");

            received_rx.notified().await;
        });

        let response = tokio::spawn(async move {
            let response_stream = MessageStreamReader::new(response_stream, decoder.clone());

            let mut frame_stream = pin!(FrameStream::new(StreamReader::new(response_stream)));
            let frame = frame_stream.as_mut().next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::HEADERS_FRAME_TYPE);
            let field_section = Decoder::decode(&*decoder, frame).await.unwrap();
            assert_eq!(field_section, expected_field_section);
            tracing::info!(?field_section, "decoded field section",);

            let mut frame = frame_stream.next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::DATA_FRAME_TYPE);
            tracing::info!("got data frame, reading");

            let mut data = Vec::new();
            frame.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, body.as_bytes());
            tracing::info!("read data frame");

            received.notify_one();
        });

        time::timeout(time::Duration::from_secs(1), async move {
            tokio::try_join!(request, response).unwrap()
        })
        .await
        .expect("test timedout");
    }

    fn settings_with_dynamic_table() -> Arc<Settings> {
        let mut settings = Settings::default();
        settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(4096)));
        settings.set(QpackBlockedStreams::setting(VarInt::from_u32(100)));
        Arc::new(settings)
    }

    /// Direct roundtrip test: encode with DynamicCompressAlgo, then decode using
    /// the decoder state. Bypasses mock streams to test the algorithm itself.
    #[tokio::test]
    async fn dynamic_roundtrip() {
        use crate::qpack::{
            algorithm::{Algorithm, DynamicCompressAlgo, HuffmanAlways},
            decoder::DecoderState,
            encoder::{EncoderInstruction, EncoderState},
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
        for instruction in encoder_state.pending_instructions() {
            match instruction {
                EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                    decoder_state.set_dynamic_table_capacity(*capacity).unwrap();
                }
                EncoderInstruction::InsertWithNameReference {
                    is_static,
                    name_index,
                    value,
                    ..
                } => {
                    // Wire-format name_index: relative for dynamic, absolute for static
                    let abs_index = if *is_static {
                        *name_index
                    } else {
                        decoder_state.table_inserted_count() - name_index - 1
                    };
                    decoder_state
                        .insert_with_name_reference(*is_static, abs_index, value.clone())
                        .unwrap();
                }
                EncoderInstruction::InsertWithLiteralName { name, value, .. } => {
                    decoder_state
                        .insert_with_literal_name(name.clone(), value.clone())
                        .unwrap();
                }
                EncoderInstruction::Duplicate { index } => {
                    let abs_index = decoder_state.table_inserted_count() - index - 1;
                    decoder_state.duplicate(abs_index).unwrap();
                }
            }
        }

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

            let decoder_stream = Box::pin(TryFuture::from(async move {
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

            let encoder_stream = Box::pin(TryFuture::from(async move {
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
            tracing::info!("header frame sent (dynamic)");

            // Flush encoder instructions through the real encoder stream
            encoder_clone.flush_instructions().await.unwrap();
            tracing::info!("encoder instructions flushed");

            let frame_payload = Bytes::from_static(body.as_bytes());
            let data_frame = Frame::new(Frame::DATA_FRAME_TYPE, frame_payload).unwrap();
            request_stream.encode_one(data_frame).await.unwrap();
            request_stream.flush().await.unwrap();
            tracing::info!("data frame sent");

            received_rx.notified().await;
        });

        let response_task = tokio::spawn(async move {
            let response_stream = MessageStreamReader::new(response_stream, decoder.clone());

            let mut frame_stream = pin!(FrameStream::new(StreamReader::new(response_stream)));
            let frame = frame_stream.as_mut().next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::HEADERS_FRAME_TYPE);
            let field_section = Decoder::decode(&*decoder, frame).await.unwrap();
            assert_eq!(field_section, expected_field_section);
            tracing::info!(?field_section, "decoded field section (dynamic)");

            let mut frame = frame_stream.next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::DATA_FRAME_TYPE);

            let mut data = Vec::new();
            frame.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, body.as_bytes());
            tracing::info!("read data frame");

            received.notify_one();
        });

        time::timeout(time::Duration::from_secs(5), async move {
            tokio::try_join!(request_task, response_task).unwrap()
        })
        .await
        .expect("dynamic_e2e_roundtrip timed out");
    }
}
