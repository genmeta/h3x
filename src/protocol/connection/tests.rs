use std::{
    collections::VecDeque,
    future::poll_fn,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use qbase::varint::VarInt;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::{Notify, oneshot},
};

use super::{
    H3Connection,
    goaway::{StreamCursor, StreamView},
};
use crate::{
    Error, ReadRequest, ReadResponse, ReadStream, Result, Role, Transport, WriteBody, WriteRequest,
    WriteResponse, WriteStream, client,
    common::{self, Write},
    protocol::{
        frame::{self, Frame, H3Frame},
        qpack::{self, Qpack},
    },
    server,
};

mod close;
mod control;
mod goaway;
mod messages;
mod streams;
mod uni;

impl<T: Transport> H3Connection<T> {
    pub(crate) fn peer_settings_received(&self) -> bool {
        self.settings.peer.lock().unwrap().is_some()
    }

    pub(crate) fn received_goaway(&self) -> Option<u64> {
        self.cursor.lock().unwrap().peer()
    }

    fn transport(&self) -> &Arc<T> {
        self.transport.as_ref().unwrap()
    }
}

struct Cell<T>(Mutex<T>);

impl<T: Copy> Cell<T> {
    fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }

    fn get(&self) -> T {
        *self.0.lock().unwrap()
    }

    fn set(&self, value: T) {
        *self.0.lock().unwrap() = value;
    }
}

struct Queue<S> {
    values: Mutex<VecDeque<S>>,
    changed: Notify,
}

impl<S> Default for Queue<S> {
    fn default() -> Self {
        Self {
            values: Mutex::new(VecDeque::new()),
            changed: Notify::new(),
        }
    }
}

impl<S> Queue<S> {
    fn push(&self, value: S) {
        self.values.lock().unwrap().push_back(value);
        self.changed.notify_one();
    }

    async fn pop(&self) -> S {
        loop {
            let changed = self.changed.notified();
            if let Some(value) = self.values.lock().unwrap().pop_front() {
                return value;
            }
            changed.await;
        }
    }
}
struct Recv(Box<dyn AsyncRead + Unpin + Send>);

impl AsyncRead for Recv {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl StopSending for Recv {
    fn stop(&mut self, _: u64) {
        self.0 = Box::new(duplex(1).0);
    }
}

struct MemorySend(DuplexStream);

impl AsyncWrite for MemorySend {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl CancelStream for MemorySend {
    fn cancel(&mut self, _: u64) {
        self.0 = duplex(1).0;
    }
}

type Bi = (u64, (Recv, MemorySend));
struct Memory {
    incoming_uni: Arc<Queue<(u64, Recv)>>,
    outgoing_uni: Arc<Queue<(u64, Recv)>>,
    incoming_bi: Arc<Queue<Bi>>,
    outgoing_bi: Arc<Queue<Bi>>,
    next_uni: Cell<u64>,
    next_bi: Cell<u64>,
    blocked_open: Cell<bool>,
    close_calls: Cell<usize>,
    accept_bi_calls: Cell<usize>,
    ended: Arc<(Cell<Option<Error>>, Notify)>,
}

fn pair() -> (Memory, Memory) {
    let uni_a = Arc::new(Queue::default());
    let uni_b = Arc::new(Queue::default());
    let bi_a = Arc::new(Queue::default());
    let bi_b = Arc::new(Queue::default());
    let ended = Arc::new((Cell::new(None), Notify::new()));
    (
        Memory {
            incoming_uni: uni_a.clone(),
            outgoing_uni: uni_b.clone(),
            incoming_bi: bi_a.clone(),
            outgoing_bi: bi_b.clone(),
            next_uni: Cell::new(2),
            next_bi: Cell::new(0),
            blocked_open: Cell::new(false),
            close_calls: Cell::new(0),
            accept_bi_calls: Cell::new(0),
            ended: ended.clone(),
        },
        Memory {
            incoming_uni: uni_b,
            outgoing_uni: uni_a,
            incoming_bi: bi_b,
            outgoing_bi: bi_a,
            next_uni: Cell::new(3),
            next_bi: Cell::new(1),
            blocked_open: Cell::new(false),
            close_calls: Cell::new(0),
            accept_bi_calls: Cell::new(0),
            ended,
        },
    )
}

impl Transport for Memory {
    fn role(&self) -> Role {
        if self.next_uni.get() % 4 == 2 {
            Role::Client
        } else {
            Role::Server
        }
    }
    type Recv = Recv;
    type Send = MemorySend;

    async fn open_bi_stream(&self) -> Result<Option<Bi>> {
        if let Some(error) = self.ended.0.get() {
            return Err(error);
        }
        if self.blocked_open.get() {
            return Err(self.terminated().await);
        }
        let id = self.next_bi.get();
        self.next_bi.set(id + 4);
        let (send, peer_recv) = duplex(3);
        let (peer_send, recv) = duplex(3);
        self.outgoing_bi
            .push((id, (Recv(Box::new(peer_recv)), MemorySend(peer_send))));
        Ok(Some((id, (Recv(Box::new(recv)), MemorySend(send)))))
    }

    async fn accept_bi_stream(&self) -> Result<Bi> {
        self.accept_bi_calls.set(self.accept_bi_calls.get() + 1);
        tokio::select! {
            biased;
            error = self.terminated() => Err(error),
            stream = self.incoming_bi.pop() => Ok(stream),
        }
    }

    async fn open_uni_stream(&self) -> Result<Option<(u64, MemorySend)>> {
        let id = self.next_uni.get();
        self.next_uni.set(id + 4);
        let (send, recv) = duplex(3);
        self.outgoing_uni.push((id, Recv(Box::new(recv))));
        Ok(Some((id, MemorySend(send))))
    }

    async fn accept_uni_stream(&self) -> Result<(u64, Recv)> {
        tokio::select! {
            biased;
            error = self.terminated() => Err(error),
            stream = self.incoming_uni.pop() => Ok(stream),
        }
    }

    fn close(&self, _: String, code: u64) -> Result<()> {
        self.close_calls.set(self.close_calls.get() + 1);
        if self.ended.0.get().is_none() {
            let error = [
                Error::H3_NO_ERROR,
                Error::H3_GENERAL_PROTOCOL_ERROR,
                Error::H3_INTERNAL_ERROR,
                Error::H3_STREAM_CREATION_ERROR,
                Error::H3_CLOSED_CRITICAL_STREAM,
                Error::H3_FRAME_UNEXPECTED,
                Error::H3_FRAME_ERROR,
                Error::H3_EXCESSIVE_LOAD,
                Error::H3_ID_ERROR,
                Error::H3_SETTINGS_ERROR,
                Error::H3_MISSING_SETTINGS,
                Error::H3_REQUEST_REJECTED,
                Error::H3_REQUEST_CANCELLED,
                Error::H3_REQUEST_INCOMPLETE,
                Error::H3_MESSAGE_ERROR,
                Error::H3_CONNECT_ERROR,
                Error::H3_VERSION_FALLBACK,
                Error::QPACK_DECOMPRESSION_FAILED,
                Error::QPACK_ENCODER_STREAM_ERROR,
                Error::QPACK_DECODER_STREAM_ERROR,
            ]
            .into_iter()
            .find(|error| error.as_u64() == code)
            .unwrap_or(Error::H3_INTERNAL_ERROR);
            self.ended.0.set(Some(error));
        }
        self.ended.1.notify_waiters();
        Ok(())
    }

    async fn terminated(&self) -> Error {
        loop {
            let changed = self.ended.1.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(error) = self.ended.0.get() {
                return error;
            }
            changed.await;
        }
    }
}

impl Memory {
    /// Model a transport-owned idle timeout without sending CONNECTION_CLOSE.
    fn expire(&self) {
        self.ended.0.set(Some(Error::H3_NO_ERROR));
        self.ended.1.notify_waiters();
    }
}

async fn assert_closed(connection: &H3Connection<Memory>) {
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        wait_for_transport(connection.transport(), &connection.qpack, &connection.bi),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(connection.error(), Some(Error::H3_NO_ERROR));
    assert_eq!(connection.bi.len(), 0);
}

// Test-only adapters keep the existing protocol scenarios readable; public APIs return messages.
async fn request_on<R, F, Fut, O>(
    connection: &H3Connection<Memory>,
    request: R,
    callback: F,
) -> Result<O>
where
    R: Into<common::Request<Write>>,
    F: FnOnce(client::Response) -> Fut,
    Fut: Future<Output = Result<O>>,
{
    let (send, recv) = connection.open_bi().await?;
    let response = client::request(request, recv, send, connection.qpack().clone()).await?;
    callback(response).await
}

async fn accept_on<F, Fut, R>(connection: &H3Connection<Memory>, handler: F) -> Result<()>
where
    F: FnOnce(server::Request) -> Fut,
    Fut: Future<Output = Result<R>>,
    R: Into<common::Response<Write>>,
{
    let (send, recv) = connection.accept_bi().await?;
    let request = server::accept(recv, connection.qpack().clone()).await?;
    let method = request.method();
    let response = handler(request).await?.into();
    server::respond(response, send, connection.qpack().clone(), &method).await
}

// Keep the returned critical stream alive for the duration of the test.
async fn acknowledge_goaway(peer: &Memory, id: u64) -> MemorySend {
    let (_, mut send) = peer.open_uni_stream().await.unwrap().unwrap();
    send.write_all(&[0]).await.unwrap();
    crate::protocol::stream::control::write(
        &mut send,
        &H3Frame::Settings(Frame::new(frame::Settings::default()).unwrap()),
    )
    .await
    .unwrap();
    crate::protocol::stream::control::write(
        &mut send,
        &H3Frame::Goaway(
            Frame::new(frame::Goaway {
                id: VarInt::try_from(id).unwrap(),
            })
            .unwrap(),
        ),
    )
    .await
    .unwrap();
    send
}

struct ConnectionState {
    transport: Arc<Memory>,
    qpack: Arc<Qpack<Memory>>,
    cursor: Arc<Mutex<StreamCursor>>,
    bi: Arc<crate::protocol::stream::bi::BiStreams<Recv, MemorySend>>,
}

fn observe(connection: &H3Connection<Memory>) -> ConnectionState {
    ConnectionState {
        transport: connection.transport().clone(),
        qpack: connection.qpack.clone(),
        cursor: connection.cursor.clone(),
        bi: connection.bi.clone(),
    }
}

impl ConnectionState {
    fn transport(&self) -> &Arc<Memory> {
        &self.transport
    }
    fn error(&self) -> Option<Error> {
        self.qpack.error()
    }
    fn qpack(&self) -> &Arc<Qpack<Memory>> {
        &self.qpack
    }
    async fn assert_closed(&self) {
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_transport(&self.transport, &self.qpack, &self.bi),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(self.error(), Some(Error::H3_NO_ERROR));
        assert_eq!(self.bi.len(), 0);
    }
}

async fn wait_for_drain(connection: H3Connection<Memory>) -> Result<()> {
    let observed = observe(&connection);
    connection.goaway().await?;
    wait_for_transport(&observed.transport, &observed.qpack, &observed.bi).await
}

// Observe cleanup performed by the real tasks, without closing resources in the fixture.
async fn wait_for_transport(
    transport: &Memory,
    qpack: &Qpack<Memory>,
    bi: &crate::protocol::stream::bi::BiStreams<Recv, MemorySend>,
) -> Result<()> {
    let error = transport.terminated().await;
    while qpack.error().is_none() || bi.len() != 0 {
        tokio::task::yield_now().await;
    }
    if error == Error::H3_NO_ERROR {
        Ok(())
    } else {
        Err(error)
    }
}

async fn receive_control_stream(peer: &Memory) -> (Recv, Vec<Recv>) {
    use tokio::io::AsyncReadExt;
    let mut qpack = Vec::new();
    loop {
        let (_, mut recv) = peer.accept_uni_stream().await.unwrap();
        match recv.read_u8().await.unwrap() {
            0 => return (recv, qpack),
            2 | 3 => qpack.push(recv),
            ty => panic!("unexpected stream type {ty}"),
        }
    }
}

impl StreamCursor {
    fn sent(&self) -> Option<u64> {
        match self.local {
            StreamView::Gone(id) => Some(id),
            _ => None,
        }
    }
}
