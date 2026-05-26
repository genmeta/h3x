use bytes::Bytes;
use futures::{SinkExt, StreamExt, future::Either};
use tokio_util::sync::CancellationToken;

use super::super::bridge;
use crate::{
    codec::BoxReadStream,
    message::stream::guard,
    quic::{self, CancelStreamExt, GetStreamIdExt, StopStreamExt},
    util::deferred::Deferred,
    varint::VarInt,
};

/// Remote trait for reading from a QUIC stream over remoc RTC.
#[remoc::rtc::remote]
pub trait ReadStream: Send {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn read(&mut self) -> Result<Option<Bytes>, quic::StreamError>;
    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
}

impl ReadStreamClient {
    pub async fn into_quic(mut self) -> Result<impl quic::ReadStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(bridge::ReadBridge::<_, quic::StreamError, _, _, _, _>::new(
            stream_id,
            self,
            |mut client: ReadStreamClient, token: CancellationToken| async move {
                tokio::select! {
                    res = client.read() => Either::Left((client, res.transpose())),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: ReadStreamClient, code| async move {
                let res = client.stop(code).await;
                (client, res)
            },
        ))
    }

    pub fn into_boxed_quic(self) -> guard::GuardedQuicReader {
        let raw: BoxReadStream = Box::pin(Deferred::from(self.into_quic()));
        guard::GuardedQuicReader::new(raw)
    }
}

/// Remote trait for writing to a QUIC stream over remoc RTC.
#[remoc::rtc::remote]
pub trait WriteStream: Send {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn write(&mut self, data: Bytes) -> Result<(), quic::StreamError>;
    async fn flush(&mut self) -> Result<(), quic::StreamError>;
    async fn shutdown(&mut self) -> Result<(), quic::StreamError>;
    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
}

impl WriteStreamClient {
    pub async fn into_quic(mut self) -> Result<impl quic::WriteStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(bridge::WriteBridge::<
            _,
            quic::StreamError,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
        >::new(
            stream_id,
            self,
            |mut client: WriteStreamClient, token: CancellationToken, bytes| async move {
                tokio::select! {
                    res = client.write(bytes) => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: WriteStreamClient, token: CancellationToken| async move {
                tokio::select! {
                    res = client.flush() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: WriteStreamClient, token: CancellationToken| async move {
                tokio::select! {
                    res = client.shutdown() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: WriteStreamClient, code| async move {
                let res = client.cancel(code).await;
                (client, res)
            },
        ))
    }

    pub fn into_boxed_quic(self) -> guard::GuardedQuicWriter {
        let raw: crate::codec::BoxWriteStream = Box::pin(Deferred::from(self.into_quic()));
        guard::GuardedQuicWriter::new(raw)
    }
}

impl<S> ReadStream for S
where
    S: quic::ReadStream + Unpin + Send,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        GetStreamIdExt::stream_id(self).await
    }

    async fn read(&mut self) -> Result<Option<Bytes>, quic::StreamError> {
        StreamExt::next(self).await.transpose()
    }

    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        StopStreamExt::stop(self, code).await
    }
}

impl<S> WriteStream for S
where
    S: quic::WriteStream + Unpin + Send,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        GetStreamIdExt::stream_id(self).await
    }

    async fn write(&mut self, data: Bytes) -> Result<(), quic::StreamError> {
        SinkExt::send(self, data).await
    }

    async fn flush(&mut self) -> Result<(), quic::StreamError> {
        SinkExt::flush(self).await
    }

    async fn shutdown(&mut self) -> Result<(), quic::StreamError> {
        SinkExt::close(self).await
    }

    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        CancelStreamExt::cancel(self, code).await
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::StreamExt;

    use super::*;

    #[tokio::test]
    async fn blanket_read_stream_delegates_to_quic_reader() {
        let stream_id = VarInt::from_u32(7);
        let (mut reader, mut writer) = quic::test::mock_stream_pair(stream_id);

        futures::SinkExt::send(&mut writer, Bytes::from_static(b"hello"))
            .await
            .expect("write succeeds");
        drop(writer);

        let id = ReadStream::stream_id(&mut reader)
            .await
            .expect("stream id resolves");
        assert_eq!(id, stream_id);

        let chunk = ReadStream::read(&mut reader).await.expect("read succeeds");
        assert_eq!(chunk, Some(Bytes::from_static(b"hello")));

        let eof = ReadStream::read(&mut reader).await.expect("eof succeeds");
        assert!(eof.is_none());
    }

    #[tokio::test]
    async fn blanket_read_stream_stop_delegates_to_quic_reader() {
        let stream_id = VarInt::from_u32(9);
        let (mut reader, _writer) = quic::test::mock_stream_pair(stream_id);

        ReadStream::stop(&mut reader, VarInt::from_u32(42))
            .await
            .expect("stop succeeds");
    }

    #[tokio::test]
    async fn blanket_write_stream_delegates_to_quic_writer() {
        let stream_id = VarInt::from_u32(11);
        let (mut reader, mut writer) = quic::test::mock_stream_pair(stream_id);

        let id = WriteStream::stream_id(&mut writer)
            .await
            .expect("stream id resolves");
        assert_eq!(id, stream_id);

        WriteStream::write(&mut writer, Bytes::from_static(b"payload"))
            .await
            .expect("write succeeds");
        WriteStream::flush(&mut writer)
            .await
            .expect("flush succeeds");

        let chunk = reader
            .next()
            .await
            .expect("chunk present")
            .expect("read ok");
        assert_eq!(chunk, Bytes::from_static(b"payload"));

        WriteStream::shutdown(&mut writer)
            .await
            .expect("shutdown succeeds");
        assert!(reader.next().await.is_none());
    }

    #[tokio::test]
    async fn blanket_write_stream_cancel_delegates_to_quic_writer() {
        let stream_id = VarInt::from_u32(13);
        let (mut reader, mut writer) = quic::test::mock_stream_pair(stream_id);
        let code = VarInt::from_u32(99);

        WriteStream::cancel(&mut writer, code)
            .await
            .expect("cancel succeeds");

        let error = reader
            .next()
            .await
            .expect("reset is delivered")
            .expect_err("reader observes reset");
        assert!(matches!(error, quic::StreamError::Reset { code: c } if c == code));
    }
}
