use std::sync::{Arc, Mutex};

use qbase::varint::{VARINT_MAX, VarInt};
use tokio::{
    sync::{Notify, oneshot},
    task::JoinHandle,
};

use super::{
    frame::{self, Frame, H3Frame},
    qpack::{self, Qpack},
    stream::{H3ReadStream, H3WriteStream, UniStreams, bi::BiStreams},
};
use crate::{Error, Result, Transport};

/// Local advertised settings and the independently received peer settings.
pub struct Settings {
    pub(crate) local: frame::Settings,
    pub(crate) peer: Mutex<Option<frame::Settings>>,
}

impl Settings {
    pub fn new(
        max_field_section_size: u64,
        max_table_capacity: u64,
        blocked_streams: u64,
    ) -> Result<Self> {
        if max_field_section_size > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64
            || max_table_capacity > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64
        {
            return Err(Error::H3_SETTINGS_ERROR);
        }
        let values = [
            (frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, max_table_capacity),
            (
                frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                max_field_section_size,
            ),
            (frame::SETTINGS_QPACK_BLOCKED_STREAMS, blocked_streams),
        ]
        .into_iter()
        .map(|(id, value)| {
            Ok((
                VarInt::from_u32(id),
                VarInt::try_from(value).map_err(|_| Error::H3_SETTINGS_ERROR)?,
            ))
        })
        .collect::<Result<_>>()?;
        Ok(Self {
            local: frame::Settings { values },
            peer: Mutex::new(None),
        })
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new(65536, 4096, 16).unwrap()
    }
}

#[derive(Default)]
pub(crate) struct GoawayState {
    local: Option<u64>,
    pub(crate) peer: Option<u64>,
    accepted_boundary: u64,
}

#[derive(Default)]
pub(crate) struct Goaway {
    pub(crate) state: Mutex<GoawayState>,
    pub(crate) changed: Notify,
}

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Dropping the connection closes it and stops its driver.
pub struct H3Connection<T: Transport> {
    transport: Arc<T>,
    uni: Arc<UniStreams>,
    bi: Arc<BiStreams<T::Recv, T::Send>>,
    task: JoinHandle<()>,
}

impl<T: Transport> H3Connection<T> {
    /// Start HTTP/3 using default settings and the transport's endpoint role.
    /// Panics if called outside a Tokio runtime.
    pub fn new(transport: T) -> Self {
        Self::with_settings(transport, Settings::default()).expect("valid default HTTP/3 settings")
    }

    pub fn with_settings(transport: T, settings: Settings) -> Result<Self> {
        let (local, max_fields) = qpack::limits(&settings.local);
        let qpack = Arc::new(Qpack::new(
            local,
            qpack::Settings::default(),
            frame::MAX_BUFFERED_FRAME_PAYLOAD,
        )?);
        qpack.local_limit(max_fields);
        let transport = Arc::new(transport);
        let uni = Arc::new(UniStreams::new(settings, qpack));
        let bi = Arc::new(BiStreams::default());
        let task = tokio::spawn({
            let bi = Arc::clone(&bi);
            let transport = Arc::clone(&transport);
            let uni = Arc::clone(&uni);
            async move {
                let _ = process_connection(transport.as_ref(), &uni, &bi).await;
            }
        });
        Ok(Self {
            transport,
            uni,
            bi,
            task,
        })
    }

    /// Open a bidirectional stream, returning (send, receive).
    pub async fn open_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::Send, T::Recv>,
        H3ReadStream<T::Recv, T::Send>,
    )> {
        self.error().map_or(Ok(()), Err)?;
        let changed = self.uni.goaway.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let draining = {
            let state = self.uni.goaway.state.lock().unwrap();
            state.local.or(state.peer).is_some()
        };
        if draining {
            return Err(Error::H3_REQUEST_REJECTED);
        }
        let stream = tokio::select! {
            biased;
            error = self.uni.qpack.terminated() => return Err(error),
            _ = &mut changed => return Err(Error::H3_REQUEST_REJECTED),
            stream = self.transport.open_bi_stream() => stream?,
        }
        .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
        let draining = {
            let state = self.uni.goaway.state.lock().unwrap();
            state.local.or(state.peer).is_some()
        };
        if draining {
            return Err(Error::H3_REQUEST_REJECTED);
        }
        self.insert(stream)
    }

    /// Accept a bidirectional stream, returning (send, receive), before parsing HTTP.
    pub async fn accept_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::Send, T::Recv>,
        H3ReadStream<T::Recv, T::Send>,
    )> {
        self.error().map_or(Ok(()), Err)?;
        let changed = self.uni.goaway.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let accept = self.transport.accept_bi_stream();
        tokio::pin!(accept);
        let stream = loop {
            self.error().map_or(Ok(()), Err)?;
            if self.uni.goaway.state.lock().unwrap().local.is_some() {
                return Err(Error::H3_REQUEST_REJECTED);
            }
            tokio::select! {
                biased;
                error = self.uni.qpack.terminated() => return Err(error),
                _ = &mut changed => {
                    changed.set(self.uni.goaway.changed.notified());
                    changed.as_mut().enable();
                }
                stream = &mut accept => break stream?,
            }
        };
        if stream.0 > VARINT_MAX || !stream.0.is_multiple_of(4) {
            return Err(Error::H3_ID_ERROR);
        }
        {
            let mut state = self.uni.goaway.state.lock().unwrap();
            if state.local.is_some() {
                return Err(Error::H3_REQUEST_REJECTED);
            }
            state.accepted_boundary = state.accepted_boundary.max(stream.0 + 4);
        }
        self.insert(stream)
    }

    #[expect(
        clippy::type_complexity,
        reason = "Transport tuple keeps both halves and their ID together"
    )]
    fn insert(
        &self,
        (id, (recv, send)): (u64, (T::Recv, T::Send)),
    ) -> Result<(
        H3WriteStream<T::Send, T::Recv>,
        H3ReadStream<T::Recv, T::Send>,
    )> {
        if id > VARINT_MAX || !id.is_multiple_of(4) {
            return Err(Error::H3_ID_ERROR);
        }
        self.bi.insert(id, recv, send)
    }

    pub fn error(&self) -> Option<Error> {
        self.uni.qpack.error()
    }

    pub fn close(&self, error: Error) {
        close_connection(self.transport.as_ref(), &self.uni.qpack, error);
        self.bi.close(self.uni.qpack.error().unwrap_or(error));
    }

    pub async fn closed(&self) -> Result<()> {
        let error = tokio::select! {
            error = self.uni.qpack.terminated() => error,
            error = self.transport.terminated() => {
                self.close(error); self.error().unwrap_or(error)
        } };
        if error == Error::H3_NO_ERROR {
            Ok(())
        } else {
            Err(error)
        }
    }

    /// Queue GOAWAY and wait for the driver to finish writing it.
    /// Cancelling this wait does not cancel a frame already queued for sending.
    pub async fn goaway(&self) -> Result<()> {
        let permit = tokio::select! {
            biased;
            error = self.uni.qpack.terminated() => return Err(error),
            permit = self.uni.control.sender.reserve() => {
                permit.map_err(|_| self.error().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM))?
            }
        };
        let (completed, completion) = oneshot::channel();
        {
            let mut state = self.uni.goaway.state.lock().unwrap();
            self.error().map_or(Ok(()), Err)?;
            let id = state.accepted_boundary;
            if id > VARINT_MAX || state.local.is_some_and(|previous| id > previous) {
                return Err(Error::H3_ID_ERROR);
            }
            let frame = H3Frame::Goaway(Frame::new(frame::Goaway {
                id: VarInt::try_from(id).unwrap(),
            })?);
            state.local = Some(id);
            permit.send((frame, completed));
        }
        self.uni.goaway.changed.notify_waiters();
        tokio::select! {
            biased;
            error = self.uni.qpack.terminated() => Err(error),
            result = completion => {
                result.unwrap_or_else(|_| Err(self.error().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM)))
            }
        }
    }
}

async fn process_connection<T: Transport>(
    transport: &T,
    uni: &UniStreams,
    bi: &BiStreams<T::Recv, T::Send>,
) -> Result<()> {
    uni.qpack.error().map_or(Ok(()), Err)?;
    let result = tokio::select! {
        biased;
        error = uni.qpack.terminated() => Err(error),
        error = transport.terminated() => Err(error),
        result = uni.send(transport) => result,
        result = uni.receive(transport, bi) => result,
    };
    close_connection(
        transport,
        &uni.qpack,
        result.err().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM),
    );
    bi.close(uni.qpack.error().unwrap_or(Error::H3_INTERNAL_ERROR));
    if result == Err(Error::H3_NO_ERROR) {
        Ok(())
    } else {
        result
    }
}

fn close_connection<T: Transport>(transport: &T, qpack: &Qpack, error: Error) {
    let error = qpack.error().unwrap_or(error);
    qpack.close(error);
    let _ = transport.close(error.to_string(), error.as_u64());
}

impl<T: Transport> Drop for H3Connection<T> {
    fn drop(&mut self) {
        self.close(Error::H3_NO_ERROR);
        self.task.abort();
    }
}

#[cfg(test)]
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

#[cfg(test)]
mod tests {
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
        let response = handler(request).await?.into();
        server::respond(response, send, connection.qpack().clone()).await
    }

    #[tokio::test]
    async fn raw_connections_support_explicit_message_io() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let requests = async {
            for _ in 0..2 {
                let request = client::Request::post("https://example.com/echo")
                    .unwrap()
                    .body(Bytes::from_static(b"hello"));
                let (received, served) = tokio::join!(
                    request_on(&client, request, |response| async {
                        assert_eq!(response.status(), http::StatusCode::OK);
                        let client::Response::Streaming(mut response) = response else {
                            panic!()
                        };
                        let mut bytes = [0; 5];
                        response.read_all(&mut bytes).await?;
                        assert_eq!(&bytes, b"hello");
                        Ok(())
                    }),
                    accept_on(&server, |request| async {
                        assert_eq!(request.method(), http::Method::POST);
                        let server::Request::Streaming(mut request) = request else {
                            panic!()
                        };
                        let mut bytes = [0; 5];
                        request.read_all(&mut bytes).await?;
                        let mut response = server::Response::<Bytes>::default();
                        response
                            .set_status(http::StatusCode::OK)
                            .set_body(Bytes::copy_from_slice(&bytes));
                        Ok(response)
                    })
                );
                received.unwrap();
                served.unwrap();
            }
            server.goaway().await.unwrap();
            while client.received_goaway().is_none() {
                tokio::task::yield_now().await;
            }
            assert_eq!(client.received_goaway(), Some(8));
            assert_eq!(
                client.open_bi().await.err(),
                Some(Error::H3_REQUEST_REJECTED)
            );
            client.close(Error::H3_NO_ERROR);
        };
        let (a, b, ()) = tokio::join!(client.closed(), server.closed(), requests);
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn streaming_request_remains_writable_and_goaway_preserves_admitted_post() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let response_sent = Notify::new();
        let work = async {
            let mut request =
                client::Request::streaming_post("https://example.com/upload").unwrap();
            let (send, recv) = client.open_bi().await.unwrap();
            assert_eq!(recv.stream_id(), 0);
            assert_eq!(send.stream_id(), 0);
            let response = client::request(request.clone(), recv, send, client.qpack().clone());
            assert_eq!(client.transport.next_bi.get(), 4);
            let (response, produced, served) = tokio::join!(
                response,
                async {
                    response_sent.notified().await;
                    assert_eq!(request.write(b"hello").await?, 5);
                    request.finish().await
                },
                async {
                    let (send, recv) = server.accept_bi().await?;
                    let incoming = server::accept(recv, server.qpack().clone()).await?;
                    let mut response = server::Response::<Bytes>::default();
                    let server::Request::Streaming(mut incoming) = incoming else {
                        panic!()
                    };
                    response.set_status(http::StatusCode::OK);
                    server.goaway().await?;
                    assert_eq!(server.uni.goaway.state.lock().unwrap().accepted_boundary, 4);
                    server::respond(response, send, server.qpack().clone()).await?;
                    response_sent.notify_one();
                    let mut bytes = [0; 5];
                    incoming.read_all(&mut bytes).await?;
                    assert_eq!(&bytes, b"hello");
                    Ok::<_, Error>(())
                }
            );
            assert_eq!(response.unwrap().status(), http::StatusCode::OK);
            produced.unwrap();
            served.unwrap();
            client.close(Error::H3_NO_ERROR);
        };
        let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn invalid_control_frames_close_with_the_exact_protocol_error() {
        for (wire, expected) in [
            (vec![0, 7, 1, 0], Error::H3_MISSING_SETTINGS),
            (vec![0, 4, 2, 2, 0], Error::H3_SETTINGS_ERROR),
            (vec![0, 4, 0, 4, 0], Error::H3_FRAME_UNEXPECTED),
        ] {
            let (a, b) = pair();
            let connection = H3Connection::new(a);
            let (_, mut send) = b.open_uni_stream().await.unwrap().unwrap();
            let peer = async {
                // The autonomous driver may reject the frame before the peer finishes writing it.
                let _ = send.write_all(&wire).await;
                std::future::pending::<()>().await
            };
            tokio::pin!(peer);
            let error = tokio::select! { result=connection.closed()=>result.unwrap_err(), _=&mut peer=>unreachable!() };
            assert_eq!(error, expected, "control bytes: {wire:?}");
            assert_eq!(connection.error(), Some(expected));
            assert_eq!(connection.qpack().error(), Some(expected));
        }
    }

    #[tokio::test]
    async fn duplicate_control_stream_closes_connection() {
        let (a, b) = pair();
        let connection = H3Connection::new(a);
        let peer = async {
            let (_, mut one) = b.open_uni_stream().await.unwrap().unwrap();
            one.write_all(&[0, 4, 0]).await.unwrap();
            let (_, mut two) = b.open_uni_stream().await.unwrap().unwrap();
            two.write_all(&[0]).await.unwrap();
            std::future::pending::<()>().await
        };
        tokio::pin!(peer);
        assert_eq!(
            tokio::select! { result=connection.closed()=>result, _=&mut peer=>unreachable!() },
            Err(Error::H3_STREAM_CREATION_ERROR)
        );
    }

    #[tokio::test]
    async fn dropping_connection_stops_partial_critical_io() {
        let (a, b) = pair();
        let connection = H3Connection::new(a);
        let qpack = connection.qpack().clone();
        let transport = Arc::downgrade(&connection.transport);
        let uni = Arc::downgrade(&connection.uni);
        tokio::task::yield_now().await;
        drop(connection);
        assert_eq!(qpack.error(), Some(Error::H3_NO_ERROR));
        assert_eq!(b.terminated().await, Error::H3_NO_ERROR);
        tokio::task::yield_now().await;
        assert!(
            transport.upgrade().is_none() && uni.upgrade().is_none(),
            "driver must release the transport and unidirectional stream state"
        );
    }

    #[tokio::test]
    async fn goaway_stops_new_opens_and_preserves_admitted_streams() {
        use tokio::io::AsyncReadExt;
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let work = async {
            let (mut send, recv) = client.open_bi().await.unwrap();
            let id = recv.stream_id();
            let (peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
            let peer_id = peer_recv.stream_id();
            assert_eq!(id, peer_id);
            while !server.peer_settings_received() {
                tokio::task::yield_now().await;
            }
            server.goaway().await.unwrap();
            while client.received_goaway().is_none() {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                client.open_bi().await.err(),
                Some(Error::H3_REQUEST_REJECTED)
            );
            let mut byte = [0];
            let (written, read) =
                tokio::join!(send.write_all(b"x"), peer_recv.read_exact(&mut byte));
            written.unwrap();
            read.unwrap();
            assert_eq!(&byte, b"x");
            drop((recv, send, peer_recv, peer_send));
            client.close(Error::H3_NO_ERROR);
        };
        let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn peer_goaway_rejects_delivered_streams_and_wakes_both_halves() {
        use std::{
            sync::atomic::{AtomicUsize, Ordering},
            task::{Wake, Waker},
        };

        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        #[derive(Default)]
        struct Wakes(AtomicUsize);

        impl Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        assert_eq!(client.bi.len(), 1);
        send.write_all(b"abc").await.unwrap(); // Fill the transport's three-byte window.
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = std::task::Context::from_waker(&waker);
        let mut bytes = [0];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(
            std::pin::Pin::new(&mut recv)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
        assert!(
            std::pin::Pin::new(&mut send)
                .poll_write(&mut cx, b"d")
                .is_pending()
        );

        // The server has not accepted stream 0, so GOAWAY excludes it.
        server.goaway().await.unwrap();
        while client.received_goaway().is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(client.received_goaway(), Some(0));
        assert!(wakes.0.load(Ordering::SeqCst) >= 2);
        let Poll::Ready(Err(error)) = std::pin::Pin::new(&mut recv).poll_read(&mut cx, &mut buf)
        else {
            panic!("GOAWAY must reject the pending read");
        };
        assert_eq!(Error::from(error), Error::H3_REQUEST_REJECTED);
        assert_eq!(
            Error::from(send.write_all(b"d").await.unwrap_err()),
            Error::H3_REQUEST_REJECTED
        );
        assert_eq!(
            Error::from(send.flush().await.unwrap_err()),
            Error::H3_REQUEST_REJECTED
        );
        assert_eq!(
            Error::from(send.shutdown().await.unwrap_err()),
            Error::H3_REQUEST_REJECTED
        );
        // GOAWAY ends both directions even while their handles are retained.
        tokio::task::yield_now().await;
        assert_eq!(client.bi.len(), 0);
        drop(recv);
        drop(send);
        tokio::task::yield_now().await;
        assert_eq!(client.bi.len(), 0);
    }

    #[tokio::test]
    async fn lowering_peer_goaway_rejects_only_streams_at_or_above_the_boundary() {
        use tokio::io::AsyncReadExt;
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (mut send0, recv0) = client.open_bi().await.unwrap();
        let (mut send4, recv4) = client.open_bi().await.unwrap();
        let (_peer_send0, mut peer_recv0) = server.accept_bi().await.unwrap();
        let (_peer_send4, mut peer_recv4) = server.accept_bi().await.unwrap();
        server.goaway().await.unwrap();
        while client.received_goaway() != Some(8) {
            tokio::task::yield_now().await;
        }
        send4.write_all(b"a").await.unwrap();
        let mut byte = [0];
        peer_recv4.read_exact(&mut byte).await.unwrap();
        // A peer may lower its boundary in a subsequent GOAWAY.
        let (completed, completion) = oneshot::channel();
        server
            .uni
            .control
            .sender
            .send((
                H3Frame::Goaway(
                    Frame::new(frame::Goaway {
                        id: VarInt::from_u32(4),
                    })
                    .unwrap(),
                ),
                completed,
            ))
            .await
            .unwrap();
        completion.await.unwrap().unwrap();
        while client.received_goaway() != Some(4) {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            Error::from(send4.write_all(b"b").await.unwrap_err()),
            Error::H3_REQUEST_REJECTED
        );
        send0.write_all(b"c").await.unwrap();
        peer_recv0.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'c']);
        drop((send0, recv0, send4, recv4));
        assert_eq!(client.bi.len(), 1);
        client.bi.cleanup();
        assert_eq!(client.bi.len(), 0);
    }

    #[tokio::test]
    async fn client_goaway_does_not_reject_server_request_streams() {
        use tokio::io::AsyncReadExt;
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (_send, mut recv) = client.open_bi().await.unwrap();
        let (mut peer_send, _peer_recv) = server.accept_bi().await.unwrap();
        client.goaway().await.unwrap();
        while server.received_goaway().is_none() {
            tokio::task::yield_now().await;
        }
        peer_send.write_all(b"ok").await.unwrap();
        let mut bytes = [0; 2];
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
    }

    #[tokio::test]
    async fn next_stream_reaps_completed_streams_while_handles_remain_alive() {
        use tokio::io::AsyncReadExt;
        for receive_first in [false, true] {
            let (a, b) = pair();
            let client = H3Connection::new(a);
            let server = H3Connection::new(b);
            let (mut send, mut recv) = client.open_bi().await.unwrap();
            let (mut peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
            if !receive_first {
                send.shutdown().await.unwrap();
                // AsyncRead permits empty reads without having reached EOF.
                assert_eq!(recv.read(&mut []).await.unwrap(), 0);
                tokio::task::yield_now().await;
                assert_eq!(client.bi.len(), 1);
            }
            peer_send.write_all(b"ok").await.unwrap();
            peer_send.shutdown().await.unwrap();
            let mut response = Vec::new();
            recv.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"ok");
            if receive_first {
                tokio::task::yield_now().await;
                assert_eq!(client.bi.len(), 1);
                send.shutdown().await.unwrap();
            }
            let mut request = Vec::new();
            peer_recv.read_to_end(&mut request).await.unwrap();
            assert_eq!(client.bi.len(), 1);
            assert_eq!(server.bi.len(), 1);
            let next = client.open_bi().await.unwrap();
            let peer_next = server.accept_bi().await.unwrap();
            assert_eq!(client.bi.len(), 1);
            assert_eq!(server.bi.len(), 1);

            // Retained handles keep their terminal results; completion is idempotent.
            assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
            assert_eq!(peer_recv.read(&mut [0]).await.unwrap(), 0);
            send.shutdown().await.unwrap();
            peer_send.shutdown().await.unwrap();
            send.flush().await.unwrap();
            assert_eq!(
                send.write_all(b"x").await.unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe
            );
            drop((send, recv, peer_send, peer_recv, next, peer_next));
            client.bi.cleanup();
            server.bi.cleanup();
            tokio::task::yield_now().await;
            assert_eq!(client.bi.len(), 0);
            assert_eq!(server.bi.len(), 0);
        }
    }

    #[tokio::test]
    async fn releasing_one_handle_preserves_the_other_half() {
        use tokio::io::AsyncReadExt;
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (send, mut recv) = client.open_bi().await.unwrap();
        let (mut peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
        drop(send);
        assert_eq!(client.bi.len(), 1);
        let mut bytes = [0; 2];
        assert_eq!(peer_recv.read(&mut bytes).await.unwrap(), 0);
        peer_send.write_all(b"ok").await.unwrap();
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        drop(recv);
        assert_eq!(client.bi.len(), 1);
        client.bi.cleanup();
        assert_eq!(client.bi.len(), 0);
        assert!(peer_send.write_all(b"x").await.is_err());
        drop((peer_recv, peer_send));
        server.bi.cleanup();
        assert_eq!(server.bi.len(), 0);
    }

    #[tokio::test]
    async fn closing_connection_releases_owned_streams_and_wakes_pending_io() {
        use tokio::io::{AsyncRead, ReadBuf};
        let (a, _b) = pair();
        let connection = H3Connection::new(a);
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let mut bytes = [0];
        let mut buf = ReadBuf::new(&mut bytes);
        poll_fn(|cx| {
            assert!(
                std::pin::Pin::new(&mut recv)
                    .poll_read(cx, &mut buf)
                    .is_pending()
            );
            Poll::Ready(())
        })
        .await;
        connection.close(Error::H3_INTERNAL_ERROR);
        assert_eq!(connection.bi.len(), 0);
        let result = poll_fn(|cx| std::pin::Pin::new(&mut recv).poll_read(cx, &mut buf)).await;
        assert_eq!(Error::from(result.unwrap_err()), Error::H3_INTERNAL_ERROR);
        assert_eq!(
            Error::from(send.write_all(b"x").await.unwrap_err()),
            Error::H3_INTERNAL_ERROR
        );
        drop(connection);
        assert_eq!(
            Error::from(send.flush().await.unwrap_err()),
            Error::H3_INTERNAL_ERROR
        );
    }

    #[tokio::test]
    async fn slow_unclassified_stream_does_not_block_control_and_wrong_goaway_is_rejected() {
        let (a, b) = pair();
        let connection = H3Connection::new(a);
        let peer = async {
            let (_, mut slow) = b.open_uni_stream().await.unwrap().unwrap();
            slow.write_all(&[0x40]).await.unwrap();
            let (_, mut control) = b.open_uni_stream().await.unwrap().unwrap();
            control.write_all(&[0, 4, 0, 7, 1, 1]).await.unwrap();
            std::future::pending::<()>().await
        };
        tokio::pin!(peer);
        assert_eq!(
            tokio::select! { result=connection.closed()=>result, _=&mut peer=>unreachable!() },
            Err(Error::H3_ID_ERROR)
        );
        assert!(connection.peer_settings_received());
    }

    #[tokio::test]
    async fn client_accepts_head_response_with_representation_content_length() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let work = async {
            let (received, served) = tokio::join!(
                request_on(
                    &client,
                    client::Request::<Bytes>::head("https://example.com/").unwrap(),
                    |response| async {
                        let client::Response::Bytes(response) = response else {
                            panic!()
                        };
                        assert!(crate::ReadBody::body(&response).is_empty());
                        Ok(())
                    }
                ),
                async {
                    use crate::protocol::frame::Write as _;

                    let (mut send, recv) = server.accept_bi().await?;
                    let request = server::accept(recv, server.qpack().clone()).await?;
                    assert_eq!(request.method(), http::Method::HEAD);
                    let mut response = server::Response::<Bytes>::default();
                    response.set_status(http::StatusCode::OK);
                    let fields = {
                        let mut message = response.message.0.lock().unwrap();
                        message.set_header(http::header::CONTENT_LENGTH, "5".parse().unwrap());
                        message.fields()
                    };
                    // Supply a HEAD response on the wire without storing its request method.
                    let mut frame = Vec::new();
                    frame.put_frame(&Frame::<frame::Headers>::encode(
                        fields,
                        server.qpack(),
                        send.stream_id(),
                    )?);
                    send.write_all(&frame).await?;
                    send.shutdown().await?;
                    Ok::<_, Error>(())
                }
            );
            received.unwrap();
            served.unwrap();
            client.close(Error::H3_NO_ERROR);
        };
        let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn local_goaway_wakes_pending_accept_without_message_parsing() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let work = async {
            let accept = server.accept_bi();
            tokio::pin!(accept);
            poll_fn(|cx| {
                assert!(accept.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            server.goaway().await.unwrap();
            assert_eq!(accept.await.err(), Some(Error::H3_REQUEST_REJECTED));
            client.close(Error::H3_NO_ERROR);
        };
        let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn accept_returns_halves_before_any_http_bytes_arrive() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let halves = client.open_bi().await.unwrap();
        let id = halves.0.stream_id();
        let accept = server.accept_bi();
        tokio::pin!(accept);
        let peer_halves = poll_fn(|cx| match accept.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => panic!("accept must not parse a Request"),
        })
        .await
        .unwrap();
        assert_eq!(id, peer_halves.0.stream_id());
        assert_eq!(
            server.uni.goaway.state.lock().unwrap().accepted_boundary,
            id + 4
        );
        drop((halves, peer_halves));
    }

    #[tokio::test]
    async fn dropping_request_releases_transport_halves_and_upload() {
        use tokio::io::AsyncReadExt;
        let (transport, peer) = pair();
        let connection = H3Connection::new(transport);
        let request = client::Request::streaming_post("https://example.com/upload").unwrap();
        let mut upload = request.clone();
        {
            let request = request_on(&connection, request, |_| async { Ok(()) });
            tokio::pin!(request);
            poll_fn(|cx| {
                assert!(request.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        let (_, (mut recv, mut send)) = peer.accept_bi_stream().await.unwrap();
        let mut partial = Vec::new();
        recv.read_to_end(&mut partial).await.unwrap(); // Drop closed the unfinished sending half.
        assert!(!partial.is_empty());
        assert!(send.write_all(b"response").await.is_err());
        assert_eq!(
            upload.write(b"body").await,
            Err(Error::H3_REQUEST_CANCELLED)
        );
        assert_eq!(connection.error(), None);
    }

    #[tokio::test]
    async fn messages_use_explicit_qpack_and_stream_owned_ids() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let work = async {
            let request = client::Request::post("https://example.com/")
                .unwrap()
                .header(http::header::CONTENT_LENGTH, "3".parse().unwrap())
                .body(Bytes::from_static(b"abc"));
            let (send, recv) = client.open_bi().await.unwrap();
            assert_eq!(recv.stream_id(), send.stream_id());
            let (response, served) = tokio::join!(
                client::request(request, recv, send, client.qpack().clone()),
                async {
                    let (send, recv) = server.accept_bi().await?;
                    assert_eq!(recv.stream_id(), send.stream_id());
                    let request = server::accept(recv, server.qpack().clone()).await?;
                    assert!(matches!(&request, server::Request::Bytes(_)));
                    let mut response = server::Response::<Bytes>::default();
                    response.set_status(http::StatusCode::OK);
                    let response = response.streaming(2);
                    let mut producer = response.clone();
                    let ((), ()) = tokio::try_join!(
                        server::respond(response, send, server.qpack().clone()),
                        async {
                            assert_eq!(producer.write(b"ok").await?, 2);
                            producer.finish().await
                        }
                    )?;
                    Ok::<_, Error>(())
                }
            );
            served.unwrap();
            let response = response.unwrap();
            let client::Response::Streaming(mut response) = response else {
                panic!()
            };
            let mut body = [0; 2];
            response.read_all(&mut body).await.unwrap();
            assert_eq!(&body, b"ok");
            assert_eq!(response.read(&mut [0; 1]).await.unwrap(), 0);
            client.close(Error::H3_NO_ERROR);
        };
        let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn peer_goaway_interrupts_a_pending_transport_open() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let work = async {
            client.transport.blocked_open.set(true);
            let open = client.open_bi();
            tokio::pin!(open);
            poll_fn(|cx| {
                assert!(open.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            server.goaway().await.unwrap();
            assert_eq!(open.await.err(), Some(Error::H3_REQUEST_REJECTED));
            assert_eq!(client.transport.next_bi.get(), 0);
            client.close(Error::H3_NO_ERROR);
        };
        let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn construction_drives_settings_without_any_connection_future() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        for _ in 0..1000 {
            if client.peer_settings_received() && server.peer_settings_received() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(client.peer_settings_received());
        assert!(server.peer_settings_received());
        // Exercise the public handle from a Send task, without polling closed/run.
        tokio::spawn(async move {
            let (send, recv) = client.open_bi().await.unwrap();
            let (peer_send, peer_recv) = server.accept_bi().await.unwrap();
            assert_eq!(send.stream_id(), peer_recv.stream_id());
            assert_eq!(recv.stream_id(), peer_send.stream_id());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn immediate_goaway_waits_for_initial_settings() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        server.goaway().await.unwrap();
        for _ in 0..1000 {
            if client.received_goaway().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(client.peer_settings_received());
        assert_eq!(client.received_goaway(), Some(0));
        assert_eq!(
            client.open_bi().await.err(),
            Some(Error::H3_REQUEST_REJECTED)
        );
    }

    #[tokio::test]
    async fn cancelling_goaway_wait_keeps_partial_frame_owned_by_driver() {
        use tokio::io::AsyncReadExt;

        use crate::protocol::stream::control;

        let (peer, transport) = pair();
        let connection = H3Connection::new(transport);
        let (_, mut recv) = peer.accept_uni_stream().await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), 0);
        assert!(matches!(
            control::read(&mut recv, true).await.unwrap(),
            H3Frame::Settings(_)
        ));
        connection
            .uni
            .goaway
            .state
            .lock()
            .unwrap()
            .accepted_boundary = 64;

        let mut sending = Box::pin(connection.goaway());
        poll_fn(|cx| {
            assert!(sending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // This four-byte frame cannot fit in the three-byte transport buffer.
        assert_eq!(recv.read_u8().await.unwrap(), 7);
        drop(sending);
        let mut remainder = [0; 3];
        recv.read_exact(&mut remainder).await.unwrap();
        assert_eq!(remainder, [2, 0x40, 0x40]);
        assert_eq!(connection.error(), None);

        let (sent, received) = tokio::join!(connection.goaway(), control::read(&mut recv, false));
        sent.unwrap();
        let H3Frame::Goaway(frame) = received.unwrap() else {
            panic!()
        };
        assert_eq!(frame.payload.id.into_u64(), 64);
        assert_eq!(connection.error(), None);
    }

    #[tokio::test]
    async fn goaway_write_failure_closes_connection() {
        use tokio::io::AsyncReadExt;

        use crate::protocol::stream::control;

        let (peer, transport) = pair();
        let connection = H3Connection::new(transport);
        let (_, mut recv) = peer.accept_uni_stream().await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), 0);
        control::read(&mut recv, true).await.unwrap();
        drop(recv);
        assert_eq!(
            connection.goaway().await,
            Err(Error::H3_CLOSED_CRITICAL_STREAM)
        );
        assert_eq!(
            connection.closed().await,
            Err(Error::H3_CLOSED_CRITICAL_STREAM)
        );
    }

    #[tokio::test]
    async fn concurrent_goaways_follow_settings() {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (first, second, third) =
            tokio::join!(server.goaway(), server.goaway(), server.goaway());
        first.unwrap();
        second.unwrap();
        third.unwrap();
        for _ in 0..1000 {
            if client.received_goaway().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(client.peer_settings_received());
        assert_eq!(client.received_goaway(), Some(0));
        assert_eq!(client.error(), None);
        assert_eq!(server.error(), None);
    }

    #[tokio::test]
    async fn close_before_driver_is_polled_preserves_error() {
        let (a, _b) = pair();
        let connection = H3Connection::new(a);
        connection.close(Error::H3_INTERNAL_ERROR);
        assert_eq!(connection.closed().await, Err(Error::H3_INTERNAL_ERROR));
        tokio::task::yield_now().await;
        assert!(connection.task.is_finished());
        assert_eq!(
            connection.open_bi().await.err(),
            Some(Error::H3_INTERNAL_ERROR)
        );
    }

    #[tokio::test]
    async fn dropping_connection_during_initialization_closes_before_aborting_driver() {
        let (a, _b) = pair();
        let connection = H3Connection::new(a);
        let qpack = connection.qpack().clone();
        // The tiny transport buffer leaves SETTINGS partially written.
        tokio::task::yield_now().await;
        drop(connection);
        assert_eq!(qpack.error(), Some(Error::H3_NO_ERROR));
    }

    #[tokio::test]
    async fn transport_role_selects_control_frame_rules() {
        for (role, frames, expected) in [
            (Role::Client, vec![7, 1, 3], Error::H3_ID_ERROR),
            // A client GOAWAY carries a push ID, so 3 is valid. A subsequent DATA is not.
            (
                Role::Server,
                vec![7, 1, 3, 0, 0],
                Error::H3_FRAME_UNEXPECTED,
            ),
            (Role::Server, vec![13, 1, 5, 13, 1, 4], Error::H3_ID_ERROR),
            (Role::Client, vec![13, 1, 5], Error::H3_FRAME_UNEXPECTED),
        ] {
            let (a, b) = pair();
            a.next_uni.set(if role == Role::Client { 2 } else { 3 });
            let connection = H3Connection::new(a);
            let peer = async {
                let (_, mut send) = b.open_uni_stream().await.unwrap().unwrap();
                let wire = [&[0, 4, 0][..], &frames].concat();
                let _ = send.write_all(&wire).await;
                std::future::pending::<()>().await;
            };
            let error = tokio::select! {
                result = connection.closed() => result.unwrap_err(),
                _ = peer => unreachable!(),
            };
            assert_eq!(error, expected, "role {role:?}");
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
        for (fields, capacity, blocked) in
            [(max + 1, 0, 0), (0, max + 1, 0), (0, 0, VARINT_MAX + 1)]
        {
            assert!(matches!(
                Settings::new(fields, capacity, blocked),
                Err(Error::H3_SETTINGS_ERROR)
            ));
        }
    }

    #[tokio::test]
    async fn close_wakes_pending_stream_operations_and_preserves_first_error() {
        let (transport, _peer) = pair();
        transport.blocked_open.set(true);
        let connection = H3Connection::new(transport);
        let open = connection.open_bi();
        let accept = connection.accept_bi();
        tokio::pin!(open, accept);
        poll_fn(|cx| {
            assert!(open.as_mut().poll(cx).is_pending());
            assert!(accept.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        connection.close(Error::H3_INTERNAL_ERROR);
        connection.close(Error::H3_NO_ERROR);
        assert_eq!(open.await.err(), Some(Error::H3_INTERNAL_ERROR));
        assert_eq!(accept.await.err(), Some(Error::H3_INTERNAL_ERROR));
        assert_eq!(connection.closed().await, Err(Error::H3_INTERNAL_ERROR));
        assert_eq!(connection.goaway().await, Err(Error::H3_INTERNAL_ERROR));
        assert_eq!(connection.qpack().error(), Some(Error::H3_INTERNAL_ERROR));
    }
}
