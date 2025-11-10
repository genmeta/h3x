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
    use futures::{Sink, SinkExt, Stream, StreamExt};
    use http::Request;
    use tokio::{io::AsyncReadExt, sync::Notify, time};

    use crate::{
        codec::{
            BufSinkWriter, BufStreamReader,
            error::{DecodeStreamError, EncodeStreamError},
            util::{DecodeFrom, EncodeInto},
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
    };

    fn channel<T>() -> (
        impl Sink<T, Error = EncodeStreamError>,
        impl Stream<Item = Result<T, DecodeStreamError>>,
    ) {
        let (sink, stream) = futures::channel::mpsc::channel(8);
        (sink.sink_map_err(|_e| unreachable!()), stream.map(Ok))
    }

    #[tokio::test]
    async fn r#static() {
        let encode_strategy = StaticEncoder::new(HuffmanAlways);
        let (encoder_stream_tx, encoder_stream_rx) = channel();
        let (decoder_stream_tx, decoder_stream_rx) = channel();
        let (response_stream, request_stream) = mock_stream_pair(0);

        let settings = Settings::default();
        let encoder = Arc::new(Encoder::new(settings, encoder_stream_tx, decoder_stream_rx));
        let decoder = Arc::new(Decoder::new(settings, decoder_stream_tx, encoder_stream_rx));

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
            tokio::pin!(response_stream);

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
