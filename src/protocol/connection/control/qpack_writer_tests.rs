use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use qrecovery::send::CancelStream;
use tokio::io::AsyncWrite;

use super::*;
use crate::{
    Role,
    test_support::{Reader, TestTransport},
};

struct FailingWriter(u8, Option<crate::Error>);
impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = &self.1 {
            return Poll::Ready(Err(error.clone().into()));
        }
        if self.0 == 254 {
            return Poll::Pending;
        }
        if bytes.first() == Some(&self.0) {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Ready(Ok(bytes.len()))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl CancelStream for FailingWriter {
    fn cancel(&mut self, code: u64) {
        assert_eq!(code, ErrorCode::H3_CLOSED_CRITICAL_STREAM.as_u64());
        self.1 =
            Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM.reason("test transport cancelled writer"));
    }
}

struct FailingTransport {
    base: TestTransport,
    stream_type: u8,
}
impl Transport for FailingTransport {
    type StreamReader = Reader;
    type StreamWriter = FailingWriter;
    fn role(&self) -> Role {
        Role::Client
    }
    async fn open_bi(&self) -> Result<Option<(u64, (Reader, FailingWriter))>> {
        Err(self.terminated().await)
    }
    async fn accept_bi(&self) -> Result<(u64, (Reader, FailingWriter))> {
        Err(self.terminated().await)
    }
    async fn open_uni(&self) -> Result<Option<(u64, FailingWriter)>> {
        if self.stream_type == 253 {
            return std::future::pending().await;
        }
        Ok(Some((2, FailingWriter(self.stream_type, None))))
    }
    async fn accept_uni(&self) -> Result<(u64, Reader)> {
        Err(self.terminated().await)
    }
    fn close(&self, reason: String, code: u64) -> Result<()> {
        self.base.close(reason, code)
    }
    async fn terminated(&self) -> h3x::Error {
        self.base.terminated().await
    }
}

#[tokio::test]
async fn settings_failure_closes_admission_and_active_streams() {
    assert_writer_failure(StreamType::Control).await;
}

#[tokio::test]
async fn qpack_encoder_failure_closes_admission_and_active_streams() {
    assert_writer_failure(StreamType::QpackEncoder).await;
}

#[tokio::test]
async fn qpack_decoder_failure_closes_admission_and_active_streams() {
    assert_writer_failure(StreamType::QpackDecoder).await;
}

async fn assert_writer_failure(stream_type: StreamType) {
    let connection = H3Connection::new(
        FailingTransport {
            base: TestTransport::default(),
            stream_type: stream_type as u8,
        },
        Default::default(),
    )
    .await
    .unwrap();
    let (mut send, _recv) = connection
        .bi_streams
        .insert(0, Reader, FailingWriter(255, None))
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), connection.transport.terminated())
        .await
        .unwrap();
    assert_eq!(error.code, ErrorCode::H3_CLOSED_CRITICAL_STREAM);
    tokio::time::timeout(Duration::from_secs(1), async {
        while connection.qpack.error().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(connection.qpack.error(), Some(error.clone()));
    assert_eq!(
        error.reason,
        io::Error::from(io::ErrorKind::BrokenPipe).to_string()
    );
    assert_eq!(connection.open_bi().await.err(), Some(error.clone()));
    assert_eq!(
        ErrorCode::from(send.write_all(b"x").await.unwrap_err()),
        error.code
    );
    // The connection-owned writer tasks release their connection handles.
    tokio::task::yield_now().await;
    assert_eq!(Arc::strong_count(&connection.transport), 1);
}

#[tokio::test]
async fn qpack_failure_interrupts_pending_open_and_write_in_both_directions() {
    // 253 blocks stream creation; 254 blocks stream writes.
    for (encoder, stream_type) in [(true, 253), (false, 253), (true, 254), (false, 254)] {
        let transport = Arc::new(FailingTransport {
            base: TestTransport::default(),
            stream_type,
        });
        let qpack = crate::protocol::qpack::ArcQpack::new(&Default::default()).unwrap();
        let (encoder_tx, encoder_rx) = tokio::sync::mpsc::channel(1);
        let (decoder_tx, decoder_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn({
            let qpack = qpack.clone();
            let transport = transport.clone();
            async move {
                if encoder {
                    crate::protocol::connection::sync_encoder(&qpack, transport, encoder_rx).await
                } else {
                    crate::protocol::connection::sync_decoder(&qpack, transport, decoder_rx).await
                }
            }
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        let error = ErrorCode::QPACK_DECOMPRESSION_FAILED.reason("invalid field section");
        qpack.on_error(error.clone());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap(),
            Err(error.clone())
        );
        assert_eq!(transport.terminated().await, error);
        drop((encoder_tx, decoder_tx));
    }
}
