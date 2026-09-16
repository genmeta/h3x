//! A silent transport for message codec tests that supply their own stream halves.
use std::{
    io,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

use h3x::{ErrorCode, H3Connection, Result, Role, Transport};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
};

#[derive(Default)]
pub struct TestTransport {
    error: Mutex<Option<h3x::Error>>,
    ended: Notify,
}

pub struct Reader;
pub struct Writer;

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl StopSending for Reader {
    fn stop(&mut self, _: u64) {}
}
impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl CancelStream for Writer {
    fn cancel(&mut self, _: u64) {}
}

impl Transport for TestTransport {
    type StreamReader = Reader;
    type StreamWriter = Writer;
    fn role(&self) -> Role {
        Role::Client
    }
    async fn open_bi(&self) -> Result<Option<(u64, (Reader, Writer))>> {
        Err(self.terminated().await)
    }
    async fn accept_bi(&self) -> Result<(u64, (Reader, Writer))> {
        Err(self.terminated().await)
    }
    async fn open_uni(&self) -> Result<Option<(u64, Writer)>> {
        if let Some(error) = self.error.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(Some((2, Writer)))
    }
    async fn accept_uni(&self) -> Result<(u64, Reader)> {
        Err(self.terminated().await)
    }
    fn close(&self, reason: String, code: u64) -> Result<()> {
        let error = [
            ErrorCode::H3_NO_ERROR,
            ErrorCode::H3_INTERNAL_ERROR,
            ErrorCode::H3_CLOSED_CRITICAL_STREAM,
            ErrorCode::H3_EXCESSIVE_LOAD,
            ErrorCode::H3_FRAME_UNEXPECTED,
            ErrorCode::QPACK_DECOMPRESSION_FAILED,
            ErrorCode::QPACK_ENCODER_STREAM_ERROR,
            ErrorCode::QPACK_DECODER_STREAM_ERROR,
        ]
        .into_iter()
        .find(|error| error.as_u64() == code)
        .unwrap_or(ErrorCode::H3_INTERNAL_ERROR);
        self.error
            .lock()
            .unwrap()
            .get_or_insert(error.with_reason(reason));
        self.ended.notify_waiters();
        Ok(())
    }
    async fn terminated(&self) -> h3x::Error {
        loop {
            let ended = self.ended.notified();
            tokio::pin!(ended);
            ended.as_mut().enable();
            if let Some(error) = self.error.lock().unwrap().clone() {
                return error;
            }
            ended.await;
        }
    }
}

#[allow(dead_code)] // This fixture is also included by the crate's codec unit tests.
pub async fn connection() -> H3Connection<TestTransport> {
    H3Connection::new(TestTransport::default(), Default::default())
        .await
        .unwrap()
}
