//! A silent transport for message codec tests that supply their own stream halves.
use std::{
    io,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

use h3x::{Error, H3Connection, Result, Role, Transport};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
};

#[derive(Default)]
pub struct TestTransport {
    error: Mutex<Option<Error>>,
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
        if let Some(error) = *self.error.lock().unwrap() {
            return Err(error);
        }
        Ok(Some((2, Writer)))
    }
    async fn accept_uni(&self) -> Result<(u64, Reader)> {
        Err(self.terminated().await)
    }
    fn close(&self, _: String, code: u64) -> Result<()> {
        let error = [
            Error::H3_NO_ERROR,
            Error::H3_INTERNAL_ERROR,
            Error::H3_EXCESSIVE_LOAD,
            Error::H3_FRAME_UNEXPECTED,
            Error::QPACK_DECOMPRESSION_FAILED,
            Error::QPACK_ENCODER_STREAM_ERROR,
            Error::QPACK_DECODER_STREAM_ERROR,
        ]
        .into_iter()
        .find(|error| error.as_u64() == code)
        .unwrap_or(Error::H3_INTERNAL_ERROR);
        self.error.lock().unwrap().get_or_insert(error);
        self.ended.notify_waiters();
        Ok(())
    }
    async fn terminated(&self) -> Error {
        loop {
            let ended = self.ended.notified();
            tokio::pin!(ended);
            ended.as_mut().enable();
            if let Some(error) = *self.error.lock().unwrap() {
                return error;
            }
            ended.await;
        }
    }
}

#[allow(dead_code)] // This fixture is also included by the crate's codec unit tests.
pub fn connection() -> H3Connection<TestTransport> {
    H3Connection::new(TestTransport::default(), Default::default()).unwrap()
}
