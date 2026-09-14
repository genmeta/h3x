use std::{
    collections::VecDeque,
    future::poll_fn,
    sync::{Arc, Mutex},
    task::Poll,
};

use bytes::Bytes;
use qbase::varint::VarInt;
use tokio::{
    io::{AsyncWriteExt, DuplexStream, duplex},
    sync::{Notify, oneshot},
};

use super::{H3Connection, goaway::GoawayState};
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
        self.uni.settings.peer.lock().unwrap().is_some()
    }

    pub(crate) fn received_goaway(&self) -> Option<u64> {
        self.uni.goaway.state.lock().unwrap().peer()
    }

    pub fn qpack(&self) -> &Arc<Qpack> {
        &self.uni.qpack
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
type Recv = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
type Bi = (u64, (Recv, DuplexStream));
struct Memory {
    incoming_uni: Arc<Queue<(u64, Recv)>>,
    outgoing_uni: Arc<Queue<(u64, Recv)>>,
    incoming_bi: Arc<Queue<Bi>>,
    outgoing_bi: Arc<Queue<Bi>>,
    next_uni: Cell<u64>,
    next_bi: Cell<u64>,
    blocked_open: Cell<bool>,
    close_calls: Cell<usize>,
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
    type Send = DuplexStream;
    fn stop(recv: &mut Recv, _: u64) {
        *recv = Box::new(duplex(1).0);
    }

    fn cancel(send: &mut DuplexStream, _: u64) {
        *send = duplex(1).0;
    }

    fn is_stream_reset(error: &std::io::Error) -> bool {
        error
            .get_ref()
            .is_some_and(|source| source.is::<qbase::frame::ResetStreamError>())
    }

    async fn open_bi_stream(&self) -> Result<Option<Bi>> {
        if self.blocked_open.get() {
            std::future::pending::<()>().await;
        }
        let id = self.next_bi.get();
        self.next_bi.set(id + 4);
        let (send, peer_recv) = duplex(3);
        let (peer_send, recv) = duplex(3);
        self.outgoing_bi
            .push((id, (Box::new(peer_recv), peer_send)));
        Ok(Some((id, (Box::new(recv), send))))
    }

    async fn accept_bi_stream(&self) -> Result<Bi> {
        Ok(self.incoming_bi.pop().await)
    }

    async fn open_uni_stream(&self) -> Result<Option<(u64, DuplexStream)>> {
        let id = self.next_uni.get();
        self.next_uni.set(id + 4);
        let (send, recv) = duplex(3);
        self.outgoing_uni.push((id, Box::new(recv)));
        Ok(Some((id, send)))
    }

    async fn accept_uni_stream(&self) -> Result<(u64, Recv)> {
        Ok(self.incoming_uni.pop().await)
    }

    fn close(&self, _: String, _: u64) -> Result<()> {
        self.close_calls.set(self.close_calls.get() + 1);
        if self.ended.0.get().is_none() {
            self.ended.0.set(Some(Error::H3_NO_ERROR));
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

async fn assert_waiting_for_idle(connection: &H3Connection<Memory>) {
    connection.bi.drained().await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), connection.closed())
            .await
            .is_err()
    );
    assert_eq!(connection.transport.close_calls.get(), 0);
    assert_eq!(connection.transport.ended.0.get(), None);
    assert_eq!(connection.error(), None);
    assert_eq!(connection.bi.len(), 0);
    assert!(!connection.task.is_finished());
}

async fn expire_transport(connection: &H3Connection<Memory>) {
    connection.transport.expire();
    connection.closed().await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(connection.transport.close_calls.get(), 0);
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
