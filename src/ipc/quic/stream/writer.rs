//! IPC write-side typed frame IO.
//!
//! Worker-side handles are constructed directly as
//! [`BridgeStreamWriter`](crate::rpc::stream::writer::BridgeStreamWriter)
//! over a direction-aware socketpair frame IO. Hypervisor-side adapters use the
//! sibling IO type to execute write commands against a real QUIC write stream.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{Sink, Stream};
use tokio::net::{
    UnixStream,
    unix::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio_util::codec::{FramedRead, FramedWrite};

use super::codec::{CodecError, WriteCommandCodec, WriteEventCodec};
use crate::{
    quic,
    rpc::{
        lifecycle::LifecycleExt,
        stream::{
            frame::{WriteCommand, WriteEvent},
            writer::BridgeStreamWriter,
        },
    },
    varint::VarInt,
};

pin_project_lite::pin_project! {
    /// Worker-side IPC frame IO for a QUIC write stream.
    pub(crate) struct IpcWriterIo {
        #[pin]
        read: FramedRead<OwnedReadHalf, WriteEventCodec>,
        #[pin]
        write: FramedWrite<OwnedWriteHalf, WriteCommandCodec>,
    }
}

impl IpcWriterIo {
    fn new(socket: UnixStream) -> Self {
        let (read, write) = socket.into_split();
        Self {
            read: FramedRead::new(read, WriteEventCodec::new()),
            write: FramedWrite::new(write, WriteCommandCodec::new()),
        }
    }
}

impl Sink<WriteCommand> for IpcWriterIo {
    type Error = CodecError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: WriteCommand) -> Result<(), Self::Error> {
        self.project().write.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_close(cx)
    }
}

impl Stream for IpcWriterIo {
    type Item = Result<WriteEvent, CodecError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().read.poll_next(cx)
    }
}

pub(crate) fn writer<L>(
    stream_id: VarInt,
    socket: UnixStream,
    lifecycle: Arc<L>,
) -> BridgeStreamWriter<IpcWriterIo, L, CodecError>
where
    L: LifecycleExt + 'static,
    quic::ConnectionError: From<CodecError>,
{
    BridgeStreamWriter::new(stream_id, IpcWriterIo::new(socket), lifecycle)
}

pin_project_lite::pin_project! {
    /// Hypervisor-side IPC frame IO for a QUIC write stream.
    pub(crate) struct IpcWriteHypervisorIo {
        #[pin]
        read: FramedRead<OwnedReadHalf, WriteCommandCodec>,
        #[pin]
        write: FramedWrite<OwnedWriteHalf, WriteEventCodec>,
    }
}

impl IpcWriteHypervisorIo {
    pub(crate) fn new(socket: UnixStream) -> Self {
        let (read, write) = socket.into_split();
        Self {
            read: FramedRead::new(read, WriteCommandCodec::new()),
            write: FramedWrite::new(write, WriteEventCodec::new()),
        }
    }
}

impl Sink<WriteEvent> for IpcWriteHypervisorIo {
    type Error = CodecError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: WriteEvent) -> Result<(), Self::Error> {
        self.project().write.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_close(cx)
    }
}

impl Stream for IpcWriteHypervisorIo {
    type Item = Result<WriteCommand, CodecError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().read.poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use futures::{SinkExt as _, StreamExt as _};
    use tokio::net::UnixStream;
    use tokio_util::codec::{FramedRead, FramedWrite};

    use super::*;
    use crate::{
        quic,
        rpc::stream::{
            frame::{WriteCommand, WriteEvent},
            test_io::TestLifecycle,
        },
    };

    #[tokio::test]
    async fn writer_constructs_bridge_over_ipc_codecs() {
        let stream_id = VarInt::from_u32(31);
        let (worker_socket, peer_socket) = UnixStream::pair().unwrap();
        let lifecycle = Arc::new(TestLifecycle::new());
        let mut writer = writer(stream_id, worker_socket, lifecycle);
        let (peer_read, peer_write) = peer_socket.into_split();
        let mut peer_read = FramedRead::new(peer_read, WriteCommandCodec::new());
        let mut peer_write = FramedWrite::new(peer_write, WriteEventCodec::new());
        let data = Bytes::from_static(b"ipc write");
        let sent = data.clone();

        let task = tokio::spawn(async move {
            writer.send(sent).await?;
            Ok::<_, quic::StreamError>(())
        });

        peer_write.send(WriteEvent::Pull).await.unwrap();
        assert_eq!(
            peer_read.next().await.unwrap().unwrap(),
            WriteCommand::Push { data }
        );
        assert_eq!(
            peer_read.next().await.unwrap().unwrap(),
            WriteCommand::Flush
        );
        peer_write.send(WriteEvent::FlushAck).await.unwrap();

        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn writer_bridge_io_eof_latches_connection_error() {
        let stream_id = VarInt::from_u32(32);
        let (worker_socket, peer_socket) = UnixStream::pair().unwrap();
        let lifecycle = Arc::new(TestLifecycle::new());
        let mut writer = writer(stream_id, worker_socket, lifecycle.clone());
        drop(peer_socket);

        let error = writer.send(Bytes::from_static(b"lost")).await.unwrap_err();
        assert!(matches!(error, quic::StreamError::Connection { .. }));
        assert!(quic::Lifecycle::check(lifecycle.as_ref()).is_err());
    }
}
