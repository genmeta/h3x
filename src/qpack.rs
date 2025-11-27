pub mod algorithm;
pub mod decoder;
pub mod dynamic;
pub mod encoder;
pub mod field_section;
pub mod header_block;
pub mod instruction;
pub mod integer;
pub mod r#static;
pub mod string;

use std::pin::Pin;

use futures::{Sink, stream::BoxStream};

use crate::connection::StreamError;

pub type BoxInstructionStream<'a, Instruction> = BoxStream<'a, Result<Instruction, StreamError>>;
pub type BoxSink<'a, Item, Err> = Pin<Box<dyn Sink<Item, Error = Err> + Send + 'a>>;
pub type BoxInstructionSink<'a, Instruction> = BoxSink<'a, Instruction, StreamError>;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use futures::SinkExt;
    use http::Request;
    use tokio::{io::AsyncReadExt, sync::Notify, time};

    use crate::{
        codec::{DecodeExt, EncodeExt, SinkWriter, StreamReader},
        connection::{settings::Settings, stream::UnidirectionalStream},
        frame::{Frame, stream::FrameStream},
        qpack::{
            algorithm::{HuffmanAlways, StaticCompressAlgo},
            decoder::{Decoder, MessageStreamReader},
            encoder::Encoder,
            field_section::FieldSection,
        },
        quic::{ConnectionError, test::mock_stream_pair},
        util::try_future_stream::TryFutureStream,
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
            let encoder_stream = UnidirectionalStream::new(
                UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE,
                SinkWriter::new(encoder_stream_writer),
            )
            .await
            .unwrap();
            tracing::info!("Sent encoder stream type");

            let decoder_stream = Box::pin(TryFutureStream::from(async move {
                let decoder_stream = StreamReader::new(decoder_stream_reader)
                    .into_decoded::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    decoder_stream.r#type(),
                    UnidirectionalStream::QPACK_DECODER_STREAM_TYPE
                );
                tracing::info!("Received decoder stream type");
                Ok::<_, ConnectionError>(decoder_stream)
            }));

            Arc::new(Encoder::new(
                Settings::default(),
                Box::pin((encoder_stream).into_encode_sink()),
                Box::pin((decoder_stream).into_decode_stream()),
            ))
        });

        let init_decoder = tokio::spawn(async move {
            let decoder_stream = UnidirectionalStream::new(
                UnidirectionalStream::QPACK_DECODER_STREAM_TYPE,
                SinkWriter::new(decoder_stream_writer),
            )
            .await
            .unwrap();
            tracing::info!("Sent decoder stream type");

            let encoder_stream = Box::pin(TryFutureStream::from(async move {
                let encoder_stream = StreamReader::new(encoder_stream_reader)
                    .into_decoded::<UnidirectionalStream<_>>()
                    .await
                    .unwrap();
                assert_eq!(
                    encoder_stream.r#type(),
                    UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE
                );
                tracing::info!("Received encoder stream type");
                Ok::<_, ConnectionError>(encoder_stream)
            }));

            Arc::new(Decoder::new(
                Settings::default(),
                Box::pin((decoder_stream).into_encode_sink()),
                Box::pin((encoder_stream).into_decode_stream()),
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
        let field_section = FieldSection::from(parts);

        let expected_field_section = field_section.clone();

        let received = Arc::new(Notify::new());
        let received_rx = received.clone();

        let (response_stream, request_stream) = mock_stream_pair(VarInt::from_u32(0));
        let request = tokio::spawn(async move {
            let mut request_stream = SinkWriter::new(request_stream);

            let header_frame = encoder
                .encode(field_section.iter(), &encode_strategy, &mut request_stream)
                .await
                .unwrap();
            request_stream.encode_one(header_frame).await.unwrap();

            tracing::info!("Header frame sent");

            let frame_payload = Bytes::from_static(body.as_bytes());
            let data_frame = Frame::new(Frame::DATA_FRAME_TYPE, frame_payload).unwrap();
            request_stream.encode_one(data_frame).await.unwrap();
            request_stream.flush().await.unwrap();
            tracing::info!("Data frame sent");

            received_rx.notified().await;
        });

        let response = tokio::spawn(async move {
            let response_stream = MessageStreamReader::new(response_stream, decoder.clone());

            let mut frame_stream = FrameStream::new(StreamReader::new(response_stream));
            let frame = frame_stream.next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::HEADERS_FRAME_TYPE);
            let field_section = decoder.decode(frame).await.unwrap();
            assert_eq!(field_section, expected_field_section);
            tracing::info!(?field_section, "Decoded field section",);

            let mut frame = frame_stream.next_frame().await.unwrap().unwrap();
            assert_eq!(frame.r#type(), Frame::DATA_FRAME_TYPE);
            tracing::info!("Got data frame, reading");

            let mut data = Vec::new();
            frame.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, body.as_bytes());
            tracing::info!("Read data frame");

            received.notify_one();
        });

        time::timeout(time::Duration::from_secs(1), async move {
            tokio::try_join!(request, response).unwrap()
        })
        .await
        .expect("Test timedout");
    }
}
