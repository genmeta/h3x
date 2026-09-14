use std::{collections::VecDeque, future::poll_fn, task::Poll};

use bytes::Bytes;
use tokio::{
    io::{AsyncWriteExt, DuplexStream, duplex},
    sync::Notify,
};

use super::*;
use crate::{
    ReadRequest, ReadResponse, ReadStream, Role, WriteBody, WriteRequest, WriteResponse,
    WriteStream, client,
    common::{self, Write},
    server,
};

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
type Bi = (u64, (DuplexStream, DuplexStream));
struct Memory {
    incoming_uni: Arc<Queue<(u64, DuplexStream)>>,
    outgoing_uni: Arc<Queue<(u64, DuplexStream)>>,
    incoming_bi: Arc<Queue<Bi>>,
    outgoing_bi: Arc<Queue<Bi>>,
    next_uni: Cell<u64>,
    next_bi: Cell<u64>,
    blocked_open: Cell<bool>,
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
    type Recv = DuplexStream;
    type Send = DuplexStream;
    fn stop(recv: &mut DuplexStream, _: u64) {
        *recv = duplex(1).0;
    }

    fn cancel(send: &mut DuplexStream, _: u64) {
        *send = duplex(1).0;
    }

    async fn open_bi_stream(&self) -> Result<Option<Bi>> {
        if self.blocked_open.get() {
            std::future::pending::<()>().await;
        }
        let id = self.next_bi.get();
        self.next_bi.set(id + 4);
        let (send, peer_recv) = duplex(3);
        let (peer_send, recv) = duplex(3);
        self.outgoing_bi.push((id, (peer_recv, peer_send)));
        Ok(Some((id, (recv, send))))
    }

    async fn accept_bi_stream(&self) -> Result<Bi> {
        Ok(self.incoming_bi.pop().await)
    }

    async fn open_uni_stream(&self) -> Result<Option<(u64, DuplexStream)>> {
        let id = self.next_uni.get();
        self.next_uni.set(id + 4);
        let (send, recv) = duplex(3);
        self.outgoing_uni.push((id, recv));
        Ok(Some((id, send)))
    }

    async fn accept_uni_stream(&self) -> Result<(u64, DuplexStream)> {
        Ok(self.incoming_uni.pop().await)
    }

    fn close(&self, _: String, _: u64) -> Result<()> {
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
        self.uni.goaway.state.lock().unwrap().peer
    }

    pub fn qpack(&self) -> &Arc<Qpack> {
        &self.uni.qpack
    }
}

#[test]
fn settings_accept_limits_and_reject_unrepresentable_values() {
    let max = frame::MAX_BUFFERED_FRAME_PAYLOAD as u64;
    for (fields, capacity, blocked) in [(0, 0, 0), (max, max, VARINT_MAX)] {
        let settings = Settings::new(fields, capacity, blocked).unwrap();
        assert_eq!(
            settings
                .local
                .get(frame::SETTINGS_MAX_FIELD_SECTION_SIZE, 1),
            fields
        );
        assert_eq!(
            settings
                .local
                .get(frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, 1),
            capacity
        );
        assert_eq!(
            settings.local.get(frame::SETTINGS_QPACK_BLOCKED_STREAMS, 1),
            blocked
        );
        assert!(settings.peer.lock().unwrap().is_none());
    }
    for (fields, capacity, blocked) in [(max + 1, 0, 0), (0, max + 1, 0), (0, 0, VARINT_MAX + 1)] {
        assert!(matches!(
            Settings::new(fields, capacity, blocked),
            Err(Error::H3_SETTINGS_ERROR)
        ));
    }
}
