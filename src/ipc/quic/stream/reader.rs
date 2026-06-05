//! IPC read-side typed frame IO.
//!
//! Worker-side handles are constructed directly as
//! [`BridgeStreamReader`](crate::rpc::stream::reader::BridgeStreamReader)
//! over a direction-aware socketpair frame IO. Hypervisor-side adapters use the
//! sibling IO type to execute read commands against a real QUIC read stream.

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

use super::codec::{CodecError, ReadCommandCodec, ReadEventCodec};
use crate::{
    quic,
    rpc::{
        lifecycle::LifecycleExt,
        stream::{
            frame::{ReadCommand, ReadEvent},
            reader::BridgeStreamReader,
        },
    },
    varint::VarInt,
};

pin_project_lite::pin_project! {
    /// Worker-side IPC frame IO for a QUIC read stream.
    pub(crate) struct IpcReaderIo {
        #[pin]
        read: FramedRead<OwnedReadHalf, ReadEventCodec>,
        #[pin]
        write: FramedWrite<OwnedWriteHalf, ReadCommandCodec>,
    }
}

impl IpcReaderIo {
    fn new(socket: UnixStream) -> Self {
        let (read, write) = socket.into_split();
        Self {
            read: FramedRead::new(read, ReadEventCodec::new()),
            write: FramedWrite::new(write, ReadCommandCodec::new()),
        }
    }
}

impl Sink<ReadCommand> for IpcReaderIo {
    type Error = CodecError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: ReadCommand) -> Result<(), Self::Error> {
        self.project().write.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_close(cx)
    }
}

impl Stream for IpcReaderIo {
    type Item = Result<ReadEvent, CodecError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().read.poll_next(cx)
    }
}

pub(crate) fn reader<L>(
    stream_id: VarInt,
    socket: UnixStream,
    lifecycle: Arc<L>,
) -> BridgeStreamReader<IpcReaderIo, L, CodecError>
where
    L: LifecycleExt + 'static,
    quic::ConnectionError: From<CodecError>,
{
    BridgeStreamReader::new(stream_id, IpcReaderIo::new(socket), lifecycle)
}

pin_project_lite::pin_project! {
    /// Hypervisor-side IPC frame IO for a QUIC read stream.
    pub(crate) struct IpcReadHypervisorIo {
        #[pin]
        read: FramedRead<OwnedReadHalf, ReadCommandCodec>,
        #[pin]
        write: FramedWrite<OwnedWriteHalf, ReadEventCodec>,
    }
}

impl IpcReadHypervisorIo {
    pub(crate) fn new(socket: UnixStream) -> Self {
        let (read, write) = socket.into_split();
        Self {
            read: FramedRead::new(read, ReadCommandCodec::new()),
            write: FramedWrite::new(write, ReadEventCodec::new()),
        }
    }
}

impl Sink<ReadEvent> for IpcReadHypervisorIo {
    type Error = CodecError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: ReadEvent) -> Result<(), Self::Error> {
        self.project().write.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().write.poll_close(cx)
    }
}

impl Stream for IpcReadHypervisorIo {
    type Item = Result<ReadCommand, CodecError>;

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
    use crate::rpc::stream::{
        frame::{ReadCommand, ReadEvent},
        test_io::TestLifecycle,
    };

    #[tokio::test]
    async fn reader_constructs_bridge_over_ipc_codecs() {
        let stream_id = VarInt::from_u32(21);
        let (worker_socket, peer_socket) = UnixStream::pair().unwrap();
        let lifecycle = Arc::new(TestLifecycle::new());
        let mut reader = reader(stream_id, worker_socket, lifecycle);
        let (peer_read, peer_write) = peer_socket.into_split();
        let mut peer_read = FramedRead::new(peer_read, ReadCommandCodec::new());
        let mut peer_write = FramedWrite::new(peer_write, ReadEventCodec::new());

        let task = tokio::spawn(async move { reader.next().await });
        assert_eq!(peer_read.next().await.unwrap().unwrap(), ReadCommand::Pull);
        peer_write
            .send(ReadEvent::Push {
                data: Bytes::from_static(b"ipc read"),
            })
            .await
            .unwrap();

        assert_eq!(
            task.await.unwrap().unwrap().unwrap(),
            Bytes::from_static(b"ipc read")
        );
    }

    #[tokio::test]
    async fn reader_bridge_io_eof_latches_connection_error() {
        let stream_id = VarInt::from_u32(22);
        let (worker_socket, peer_socket) = UnixStream::pair().unwrap();
        let lifecycle = Arc::new(TestLifecycle::new());
        let mut reader = reader(stream_id, worker_socket, lifecycle.clone());
        drop(peer_socket);

        let error = reader.next().await.unwrap().unwrap_err();
        assert!(matches!(error, quic::StreamError::Connection { .. }));
        assert!(quic::Lifecycle::check(lifecycle.as_ref()).is_err());
    }
}
