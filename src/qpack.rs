pub mod decoder;
pub mod dynamic;
pub mod encoder;
pub mod field_section;
pub mod header_block;
pub mod instruction;
pub mod integer;
pub mod settings;
pub mod r#static;
pub mod strategy;
pub mod string;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use futures::SinkExt;
    use http::Request;
    use tokio::{io::AsyncReadExt, sync::Notify, time};

    use crate::{
        codec::{
            BufSinkWriter, BufStreamReader,
            util::{DecodeFrom, EncodeInto, decoder, encoder},
        },
        frame::Frame,
        qpack::{
            decoder::{Decoder, MessageStreamReader},
            encoder::Encoder,
            field_section::FieldSection,
            settings::Settings,
            strategy::{HuffmanAlways, StaticEncoder},
        },
        quic::test::mock_stream_pair,
        stream::{FutureStream, UnidirectionalStream},
    };

    #[tokio::test]
    async fn r#static() {
        let encode_strategy = StaticEncoder::new(HuffmanAlways);

        // stream id is unused in this test
        let (encoder_stream_reader, encoder_stream_writer) = mock_stream_pair(1);
        let (decoder_stream_reader, decoder_stream_writer) = mock_stream_pair(2);

        let init_encoder = tokio::spawn(async move {
            let encoder_stream = UnidirectionalStream::new(
                UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE,
                BufSinkWriter::new(encoder_stream_writer),
            )
            .await
            .unwrap();
            println!("Sent encoder stream type");

            let decoder_stream = Box::pin(FutureStream::from(async move {
                let decoder_stream =
                    UnidirectionalStream::decode_from(BufStreamReader::new(decoder_stream_reader))
                        .await
                        .unwrap();
                assert_eq!(
                    decoder_stream.r#type(),
                    UnidirectionalStream::QPACK_DECODER_STREAM_TYPE
                );
                println!("Received decoder stream type");
                decoder_stream
            }));

            Arc::new(Encoder::new(
                Settings::default(),
                Box::pin(encoder(encoder_stream)),
                Box::pin(decoder(decoder_stream)),
            ))
        });

        let init_decoder = tokio::spawn(async move {
            let decoder_stream = UnidirectionalStream::new(
                UnidirectionalStream::QPACK_DECODER_STREAM_TYPE,
                BufSinkWriter::new(decoder_stream_writer),
            )
            .await
            .unwrap();
            println!("Sent decoder stream type");

            let encoder_stream = Box::pin(FutureStream::from(async move {
                let encoder_stream =
                    UnidirectionalStream::decode_from(BufStreamReader::new(encoder_stream_reader))
                        .await
                        .unwrap();
                assert_eq!(
                    encoder_stream.r#type(),
                    UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE
                );
                println!("Received encoder stream type");
                encoder_stream
            }));

            Arc::new(Decoder::new(
                Settings::default(),
                Box::pin(encoder(decoder_stream)),
                Box::pin(decoder(encoder_stream)),
            ))
        });

        let (encoder, decoder) = time::timeout(time::Duration::from_secs(1), async move {
            tokio::try_join!(init_encoder, init_decoder).unwrap()
        })
        .await
        .expect("Test timedout");

        let request = Request::builder()
            .method("POST")
            .uri("https://h3x.demo.lab.genmeta.net/api/v1/upload")
            .header("user-agent", "genemta-curl/0.3.0")
            .header("accept", "*/*")
            .body("Hello, World!")
            .unwrap();

        let (parts, body) = request.into_parts();
        let field_section = FieldSection::try_from(parts).unwrap();

        let expected_field_section = field_section.clone();

        let received = Arc::new(Notify::new());
        let received_rx = received.clone();

        let (response_stream, request_stream) = mock_stream_pair(0);
        let request = tokio::spawn(async move {
            let mut request_stream = BufSinkWriter::new(request_stream);

            encoder
                .encode(field_section, &encode_strategy, &mut request_stream)
                .await
                .unwrap();
            println!("Header frame sent");

            let frame_payload = [Bytes::from_static(body.as_bytes())];
            let frame = Frame::new(Frame::DATA_FRAME_TYPE, frame_payload).unwrap();
            frame.encode_into(&mut request_stream).await.unwrap();
            request_stream.flush().await.unwrap();
            println!("Data frame sent");

            received_rx.notified().await;
        });

        let response = tokio::spawn(async move {
            let response_stream = MessageStreamReader::new(response_stream, decoder.clone());
            let response_stream = BufStreamReader::new(response_stream);

            let mut frame = Frame::decode_from(response_stream).await.unwrap();
            assert_eq!(frame.r#type(), Frame::HEADERS_FRAME_TYPE);
            let field_section = decoder.decode(&mut frame).await.unwrap();
            assert_eq!(field_section, expected_field_section);
            println!("Decoded field section: {:?}", field_section);

            frame = frame.into_next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::DATA_FRAME_TYPE);
            println!("Got data frame, reading");

            let mut data = Vec::new();
            frame.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, body.as_bytes());
            println!("Read data frame");

            received.notify_one();
        });

        time::timeout(time::Duration::from_secs(1), async move {
            tokio::try_join!(request, response).unwrap()
        })
        .await
        .expect("Test timedout");
    }
}
