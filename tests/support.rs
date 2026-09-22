use std::{
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

use h3x::{Error, ErrorCode, H3Connection, Result, Role, Settings, Transport, TransportError};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    sync::{Mutex, mpsc},
};

const STREAM_CAPACITY: usize = 64 * 1024;

type BiStream = (u64, (Stream, Stream));
type UniStream = (u64, Stream);

/// Minimal in-memory QUIC connection used by the request/response examples.
pub struct Connection {
    role: Role,
    next_bi: AtomicU64,
    next_uni: AtomicU64,
    outgoing_bi: mpsc::UnboundedSender<BiStream>,
    incoming_bi: Mutex<mpsc::UnboundedReceiver<BiStream>>,
    outgoing_uni: mpsc::UnboundedSender<UniStream>,
    incoming_uni: Mutex<mpsc::UnboundedReceiver<UniStream>>,
}

pub struct Stream(DuplexStream);

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl StopSending for Stream {
    fn stop(&mut self, _: u64) {}
}

impl CancelStream for Stream {
    fn cancel(&mut self, _: u64) {}
}

impl TransportError for Stream {
    fn map_error(error: std::io::Error) -> Error {
        Error::from_stream_io(error)
    }
}

impl Transport for Connection {
    type StreamReader = Stream;
    type StreamWriter = Stream;

    fn role(&self) -> Role {
        self.role
    }

    async fn open_bi(&self) -> Result<Option<BiStream>> {
        let id = self.next_bi.fetch_add(4, Ordering::Relaxed);
        let (local, peer) = bi_stream();
        self.outgoing_bi.send((id, peer)).map_err(|_| {
            ErrorCode::InternalError.connection("peer stopped accepting bidirectional streams")
        })?;
        Ok(Some((id, local)))
    }

    async fn accept_bi(&self) -> Result<BiStream> {
        self.incoming_bi.lock().await.recv().await.ok_or_else(|| {
            ErrorCode::InternalError.connection("peer closed the bidirectional stream queue")
        })
    }

    async fn open_uni(&self) -> Result<Option<UniStream>> {
        let id = self.next_uni.fetch_add(4, Ordering::Relaxed);
        let (writer, reader) = duplex(STREAM_CAPACITY);
        self.outgoing_uni.send((id, Stream(reader))).map_err(|_| {
            ErrorCode::InternalError.connection("peer stopped accepting unidirectional streams")
        })?;
        Ok(Some((id, Stream(writer))))
    }

    async fn accept_uni(&self) -> Result<UniStream> {
        self.incoming_uni.lock().await.recv().await.ok_or_else(|| {
            ErrorCode::InternalError.connection("peer closed the unidirectional stream queue")
        })
    }

    fn close(&self, _: String, _: u64) -> Result<()> {
        Ok(())
    }
}

/// Build the client and server halves of one in-memory HTTP/3 connection.
pub fn connection_pair() -> (H3Connection<Connection>, H3Connection<Connection>) {
    let (client_bi, server_bi) = mpsc::unbounded_channel();
    let (server_bi_reply, client_bi_reply) = mpsc::unbounded_channel();
    let (client_uni, server_uni) = mpsc::unbounded_channel();
    let (server_uni_reply, client_uni_reply) = mpsc::unbounded_channel();

    let client = Connection {
        role: Role::Client,
        next_bi: AtomicU64::new(0),
        next_uni: AtomicU64::new(2),
        outgoing_bi: client_bi,
        incoming_bi: Mutex::new(client_bi_reply),
        outgoing_uni: client_uni,
        incoming_uni: Mutex::new(client_uni_reply),
    };
    let server = Connection {
        role: Role::Server,
        next_bi: AtomicU64::new(1),
        next_uni: AtomicU64::new(3),
        outgoing_bi: server_bi_reply,
        incoming_bi: Mutex::new(server_bi),
        outgoing_uni: server_uni_reply,
        incoming_uni: Mutex::new(server_uni),
    };

    (
        H3Connection::new(client, Settings::default()).unwrap(),
        H3Connection::new(server, Settings::default()).unwrap(),
    )
}

fn bi_stream() -> ((Stream, Stream), (Stream, Stream)) {
    let (local_writer, peer_reader) = duplex(STREAM_CAPACITY);
    let (peer_writer, local_reader) = duplex(STREAM_CAPACITY);
    (
        (Stream(local_reader), Stream(local_writer)),
        (Stream(peer_reader), Stream(peer_writer)),
    )
}
