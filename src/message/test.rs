//! Test helpers for creating [`MessageReader`](super::stream::MessageReader) and
//! [`MessageWriter`](super::stream::MessageWriter) instances with mock QUIC connections,
//! suitable for unit testing.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream};

use super::stream::{MessageReader, MessageWriter, guard};
use crate::{
    codec::{SinkWriter, StreamReader},
    qpack::protocol::{QPackDecoder, QPackEncoder},
    quic,
    varint::VarInt,
};

/// Create a [`MessageReader`] for testing with a mock QUIC connection.
///
/// The returned `MessageReader` uses a no-op reader that immediately returns `None`,
/// and QPack codec streams that never produce data. The underlying mock connection
/// has no open streams and will never become ready.
pub fn read_stream_for_test(stream_id: VarInt) -> MessageReader {
    struct TestReader {
        stream_id: VarInt,
    }
    impl quic::GetStreamId for TestReader {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.get_mut().stream_id))
        }
    }
    impl quic::StopStream for TestReader {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }
    impl Stream for TestReader {
        type Item = Result<Bytes, quic::StreamError>;
        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(None)
        }
    }

    fn dec_sink() -> Pin<
        Box<
            dyn Sink<
                    crate::qpack::decoder::DecoderInstruction,
                    Error = crate::connection::StreamError,
                > + Send,
        >,
    > {
        Box::pin(
            futures::sink::drain::<crate::qpack::decoder::DecoderInstruction>()
                .sink_map_err(|never| match never {}),
        )
    }
    fn dec_stream() -> Pin<
        Box<
            dyn Stream<
                    Item = Result<
                        crate::qpack::encoder::EncoderInstruction,
                        crate::connection::StreamError,
                    >,
                > + Send,
        >,
    > {
        Box::pin(futures::stream::empty::<
            Result<crate::qpack::encoder::EncoderInstruction, crate::connection::StreamError>,
        >())
    }

    let mock = Arc::new(crate::connection::tests::MockConnection::new());
    let erased: Arc<dyn quic::DynConnection> = mock;

    let mut protocols = crate::protocol::Protocols::new();
    protocols.insert(crate::dhttp::protocol::DHttpProtocol::new_for_test(
        erased.clone(),
    ));
    let state = crate::connection::ConnectionState::new_for_test(erased, Arc::new(protocols));

    let reader = StreamReader::new(guard::GuardedQuicReader::new(
        Box::pin(TestReader { stream_id }) as crate::quic::BoxQuicStreamReader,
    ));

    MessageReader::new(
        stream_id,
        reader,
        Arc::new(QPackDecoder::new(
            Arc::new(crate::dhttp::settings::Settings::default()),
            dec_sink(),
            dec_stream(),
        )),
        state,
    )
}

/// Create a [`MessageWriter`] for testing with a mock QUIC connection.
///
/// The returned `MessageWriter` uses a no-op writer that discards all written data,
/// and QPack codec streams that never produce data. The underlying mock connection
/// has no open streams and will never become ready.
pub fn write_stream_for_test(stream_id: VarInt) -> MessageWriter {
    struct TestWriter {
        stream_id: VarInt,
    }
    impl quic::GetStreamId for TestWriter {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.get_mut().stream_id))
        }
    }
    impl quic::ResetStream for TestWriter {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }
    impl Sink<Bytes> for TestWriter {
        type Error = quic::StreamError;
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

    fn enc_sink() -> Pin<
        Box<
            dyn Sink<
                    crate::qpack::encoder::EncoderInstruction,
                    Error = crate::connection::StreamError,
                > + Send,
        >,
    > {
        Box::pin(
            futures::sink::drain::<crate::qpack::encoder::EncoderInstruction>()
                .sink_map_err(|never| match never {}),
        )
    }
    fn enc_stream() -> Pin<
        Box<
            dyn Stream<
                    Item = Result<
                        crate::qpack::decoder::DecoderInstruction,
                        crate::connection::StreamError,
                    >,
                > + Send,
        >,
    > {
        Box::pin(futures::stream::empty::<
            Result<crate::qpack::decoder::DecoderInstruction, crate::connection::StreamError>,
        >())
    }

    let mock = Arc::new(crate::connection::tests::MockConnection::new());
    let erased: Arc<dyn quic::DynConnection> = mock;

    let mut protocols = crate::protocol::Protocols::new();
    protocols.insert(crate::dhttp::protocol::DHttpProtocol::new_for_test(
        erased.clone(),
    ));
    let state = crate::connection::ConnectionState::new_for_test(erased, Arc::new(protocols));

    let writer = SinkWriter::new(guard::GuardedQuicWriter::new(
        Box::pin(TestWriter { stream_id }) as crate::quic::BoxQuicStreamWriter,
    ));

    MessageWriter::new(
        writer,
        Arc::new(QPackEncoder::new(
            Arc::new(crate::dhttp::settings::Settings::default()),
            enc_sink(),
            enc_stream(),
        )),
        state,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::Code,
        quic::{self, GetStreamIdExt},
        varint::VarInt,
    };

    #[tokio::test]
    async fn test_write_stream_new() {
        let stream_id = VarInt::from_u32(4);
        let _write_stream = write_stream_for_test(stream_id);
    }

    #[tokio::test]
    async fn test_write_stream_connection() {
        let stream_id = VarInt::from_u32(4);
        let write_stream = write_stream_for_test(stream_id);
        let conn: &Arc<dyn quic::DynConnection> = write_stream.state.quic();
        let _ = Arc::clone(conn);
    }

    #[tokio::test]
    async fn test_write_stream_reset() {
        let stream_id = VarInt::from_u32(4);
        let mut write_stream = write_stream_for_test(stream_id);
        let result = write_stream.reset(Code::H3_NO_ERROR).await;
        assert!(result.is_ok(), "reset should succeed on mock writer");
    }

    #[tokio::test]
    async fn test_write_stream_get_stream_id() {
        let stream_id = VarInt::from_u32(4);
        let mut write_stream = write_stream_for_test(stream_id);
        let id = GetStreamIdExt::stream_id(&mut write_stream).await;
        assert!(id.is_ok(), "stream_id should succeed");
        assert_eq!(
            id.unwrap(),
            stream_id,
            "stream_id should match the value passed to write_stream_for_test"
        );
    }
}
