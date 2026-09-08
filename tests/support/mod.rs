#![allow(dead_code, unused_imports)]
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
#[cfg(feature = "webtransport")]
use futures::StreamExt;
use futures::{FutureExt, Sink, SinkExt, Stream, future::BoxFuture};
use h3x::{
    Code, Settings,
    transport::{self, RecvStream, SendStream},
};
use http_body_util::{BodyExt, Full};
#[cfg(feature = "webtransport")]
use tokio::sync::oneshot;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

pub(crate) type BiStream = (MemoryRecv, MemorySend);

pub(crate) trait StreamIdValue {
    fn as_u64(&self) -> u64;
}

impl StreamIdValue for h3x::StreamId {
    fn as_u64(&self) -> u64 {
        (*self).into()
    }
}

// Test runtime owns the drivers; the production Connection has no task registry.
pub(crate) struct Connection<T: transport::Connection> {
    protocol: h3x::Connection<T>,
    requests: Arc<AsyncMutex<mpsc::Receiver<(http::Request<h3x::ChunkBody>, h3x::ResponseSender)>>>,
}
impl<T: transport::Connection> Clone for Connection<T> {
    fn clone(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
            requests: self.requests.clone(),
        }
    }
}
impl<T: transport::Connection> std::ops::Deref for Connection<T> {
    type Target = h3x::Connection<T>;
    fn deref(&self) -> &Self::Target {
        &self.protocol
    }
}
impl<T: transport::Connection> Connection<T> {
    pub(crate) async fn new(transport: T, settings: Settings) -> Result<Self, h3x::Error> {
        let (protocol, driver) = h3x::Connection::new(transport, settings).await?;
        Ok(Self::run(protocol, driver))
    }

    fn run(protocol: h3x::Connection<T>, driver: h3x::ConnectionDriver<T>) -> Self {
        let (requests, incoming) = mpsc::channel(256);
        tokio::spawn(driver.run(move |request, sender| {
            let requests = requests.clone();
            async move {
                let _ = requests.send((request, sender)).await;
            }
        }));
        Self {
            protocol,
            requests: Arc::new(AsyncMutex::new(incoming)),
        }
    }

    pub(crate) async fn accept(
        &self,
    ) -> Result<Option<(http::Request<h3x::ChunkBody>, h3x::ResponseSender)>, h3x::Error> {
        tokio::select! {
            biased;
            request = async { self.requests.lock().await.recv().await } => match request {
                Some(request) => Ok(Some(request)),
                None => self.protocol.closed().await.map(|()| None),
            },
            result = self.protocol.closed() => result.map(|()| None),
        }
    }

    pub(crate) async fn request(
        &self,
        parts: http::request::Parts,
    ) -> Result<
        (
            h3x::BodyWriter,
            BoxFuture<'static, Result<http::Response<h3x::ChunkBody>, h3x::Error>>,
        ),
        h3x::Error,
    > {
        let (writer, response, work) = self.protocol.request(parts).await?;
        tokio::spawn(work);
        Ok((
            writer,
            Box::pin(async move { response.await.map(h3x::Response::into_http) }),
        ))
    }

    pub(crate) async fn send(
        &self,
        request: http::Request<Full<Bytes>>,
    ) -> Result<http::Response<h3x::ChunkBody>, h3x::Error> {
        use tokio::io::AsyncWriteExt;
        let (parts, body) = request.into_parts();
        let (mut writer, response) = self.request(parts).await?;
        writer
            .write_all(&body.collect().await.unwrap().to_bytes())
            .await
            .map_err(|error| {
                error
                    .into_inner()
                    .and_then(|error| error.downcast::<h3x::Error>().ok())
                    .map(|error| *error)
                    .unwrap_or(h3x::Error::OwnerStopped)
            })?;
        writer.finish().await?;
        response.await
    }
}
#[cfg(feature = "webtransport")]
impl<T: transport::webtransport::Connection> Connection<T> {
    pub(crate) async fn new_webtransport(
        transport: T,
        settings: Settings,
    ) -> Result<Self, h3x::Error> {
        let (protocol, driver) = h3x::Connection::new_webtransport(transport, settings).await?;
        Ok(Self::run(protocol, driver))
    }
}

#[cfg(feature = "webtransport")]
pub(crate) fn accepted(
    response: h3x::webtransport::ConnectResponse,
) -> (http::Response<()>, h3x::webtransport::Session) {
    match response {
        h3x::webtransport::ConnectResponse::Accepted { response, session } => (response, session),
        h3x::webtransport::ConnectResponse::Rejected(response) => {
            panic!(
                "WebTransport CONNECT was rejected with {}",
                response.status()
            )
        }
    }
}

#[derive(Default)]
pub(crate) struct CloseState {
    pub(crate) error: Mutex<Option<transport::ConnectionError>>,
    pub(crate) notify: Notify,
}

impl CloseState {
    fn close(&self, error: transport::ConnectionError) {
        let mut current = self.error.lock().expect("close state poisoned");
        if current.is_none() {
            *current = Some(error);
            drop(current);
            self.notify.notify_waiters();
        }
    }

    fn current(&self) -> Option<transport::ConnectionError> {
        self.error.lock().expect("close state poisoned").clone()
    }

    async fn closed(&self) -> transport::ConnectionError {
        loop {
            let notified = self.notify.notified();
            if let Some(error) = self.current() {
                return error;
            }
            notified.await;
        }
    }
}

#[derive(Clone)]
pub(crate) struct MemoryTransport {
    pub(crate) next_bi: Arc<AtomicU64>,
    pub(crate) next_uni: Arc<AtomicU64>,
    pub(crate) uni_writes:
        Arc<Mutex<Vec<mpsc::UnboundedSender<Result<Bytes, transport::StreamError>>>>>,
    pub(crate) incoming_bi: Arc<AsyncMutex<mpsc::UnboundedReceiver<BiStream>>>,
    pub(crate) incoming_uni: Arc<AsyncMutex<mpsc::UnboundedReceiver<MemoryRecv>>>,
    pub(crate) peer_bi: mpsc::UnboundedSender<BiStream>,
    pub(crate) peer_uni: mpsc::UnboundedSender<MemoryRecv>,
    #[cfg(feature = "webtransport")]
    pub(crate) incoming_datagrams: Arc<AsyncMutex<mpsc::UnboundedReceiver<Bytes>>>,
    #[cfg(feature = "webtransport")]
    pub(crate) peer_datagrams: mpsc::UnboundedSender<Bytes>,
    #[cfg(feature = "webtransport")]
    pub(crate) reliable_resets: Arc<Mutex<Vec<(h3x::StreamId, Code, u64)>>>,
    pub(crate) close: Arc<CloseState>,
}

impl MemoryTransport {
    pub(crate) fn pair() -> (Self, Self) {
        let (a_bi_tx, a_bi_rx) = mpsc::unbounded_channel();
        let (b_bi_tx, b_bi_rx) = mpsc::unbounded_channel();
        let (a_uni_tx, a_uni_rx) = mpsc::unbounded_channel();
        let (b_uni_tx, b_uni_rx) = mpsc::unbounded_channel();
        #[cfg(feature = "webtransport")]
        let (a_datagram_tx, a_datagram_rx) = mpsc::unbounded_channel();
        #[cfg(feature = "webtransport")]
        let (b_datagram_tx, b_datagram_rx) = mpsc::unbounded_channel();
        let close = Arc::new(CloseState::default());

        let a = Self {
            next_bi: Arc::new(AtomicU64::new(0)),
            next_uni: Arc::new(AtomicU64::new(2)),
            uni_writes: Arc::default(),
            incoming_bi: Arc::new(AsyncMutex::new(a_bi_rx)),
            incoming_uni: Arc::new(AsyncMutex::new(a_uni_rx)),
            peer_bi: b_bi_tx,
            peer_uni: b_uni_tx,
            #[cfg(feature = "webtransport")]
            incoming_datagrams: Arc::new(AsyncMutex::new(a_datagram_rx)),
            #[cfg(feature = "webtransport")]
            peer_datagrams: b_datagram_tx,
            #[cfg(feature = "webtransport")]
            reliable_resets: Arc::new(Mutex::new(Vec::new())),
            close: Arc::clone(&close),
        };
        let b = Self {
            next_bi: Arc::new(AtomicU64::new(1)),
            next_uni: Arc::new(AtomicU64::new(3)),
            uni_writes: Arc::default(),
            incoming_bi: Arc::new(AsyncMutex::new(b_bi_rx)),
            incoming_uni: Arc::new(AsyncMutex::new(b_uni_rx)),
            peer_bi: a_bi_tx,
            peer_uni: a_uni_tx,
            #[cfg(feature = "webtransport")]
            incoming_datagrams: Arc::new(AsyncMutex::new(b_datagram_rx)),
            #[cfg(feature = "webtransport")]
            peer_datagrams: a_datagram_tx,
            #[cfg(feature = "webtransport")]
            reliable_resets: Arc::new(Mutex::new(Vec::new())),
            close,
        };
        (a, b)
    }

    fn check_open(&self) -> Result<(), transport::ConnectionError> {
        match self.close.current() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(feature = "webtransport")]
impl transport::webtransport::Connection for MemoryTransport {
    fn supports_reset_stream_at(&self) -> bool {
        true
    }

    fn max_datagram_size(&self) -> usize {
        1200
    }

    async fn send_datagram(&self, datagram: Bytes) -> Result<(), transport::ConnectionError> {
        self.check_open()?;
        self.peer_datagrams
            .send(datagram)
            .map_err(|_| transport::ConnectionError::transport(io::Error::other("peer closed")))
    }

    async fn receive_datagram(&self) -> Result<Bytes, transport::ConnectionError> {
        tokio::select! {
            datagram = async { self.incoming_datagrams.lock().await.recv().await } => {
                datagram.ok_or_else(|| transport::ConnectionError::transport(io::Error::other("peer closed")))
            }
            error = self.close.closed() => Err(error),
        }
    }

    fn reset_stream_at(
        &self,
        stream: &mut Self::SendStream,
        code: Code,
        reliable_size: u64,
    ) -> Result<(), transport::StreamError> {
        self.reliable_resets
            .lock()
            .expect("reliable reset actions poisoned")
            .push((stream.id, code, reliable_size));
        stream.reset(code)
    }
}

impl transport::Connection for MemoryTransport {
    type RecvStream = MemoryRecv;
    type SendStream = MemorySend;

    async fn open_bi(
        &self,
    ) -> Result<(h3x::StreamId, (Self::RecvStream, Self::SendStream)), transport::ConnectionError> {
        self.check_open()?;
        let id = self.next_bi.fetch_add(4, Ordering::Relaxed);
        let (local_recv, peer_send) = stream_direction(id);
        let (peer_recv, local_send) = stream_direction(id);
        self.peer_bi
            .send((peer_recv, peer_send))
            .map_err(|_| transport::ConnectionError::transport(io::Error::other("peer closed")))?;
        Ok((local_recv.id, (local_recv, local_send)))
    }

    async fn open_uni(&self) -> Result<(h3x::StreamId, Self::SendStream), transport::ConnectionError> {
        self.check_open()?;
        let id = self.next_uni.fetch_add(4, Ordering::Relaxed);
        let (peer_recv, local_send) = stream_direction(id);
        if self.uni_writes.lock().unwrap().is_empty() {
            self.uni_writes
                .lock()
                .unwrap()
                .push(local_send.sender.as_ref().unwrap().clone());
        }
        self.peer_uni
            .send(peer_recv)
            .map_err(|_| transport::ConnectionError::transport(io::Error::other("peer closed")))?;
        Ok((local_send.id, local_send))
    }

    async fn accept_bi(
        &self,
    ) -> Result<(h3x::StreamId, (Self::RecvStream, Self::SendStream)), transport::ConnectionError> {
        tokio::select! {
            stream = async { self.incoming_bi.lock().await.recv().await } => {
                stream.map(|(recv, send)| (recv.id, (recv, send))).ok_or_else(|| transport::ConnectionError::transport(io::Error::other("peer closed")))
            }
            error = self.close.closed() => Err(error),
        }
    }

    async fn accept_uni(&self) -> Result<(h3x::StreamId, Self::RecvStream), transport::ConnectionError> {
        tokio::select! {
            stream = async { self.incoming_uni.lock().await.recv().await } => {
                stream.map(|recv| (recv.id, recv)).ok_or_else(|| transport::ConnectionError::transport(io::Error::other("peer closed")))
            }
            error = self.close.closed() => Err(error),
        }
    }

    fn close(&self, code: Code, reason: &[u8]) {
        self.close.close(transport::ConnectionError::application(
            code,
            Bytes::copy_from_slice(reason),
        ));
    }

    async fn closed(&self) -> transport::ConnectionError {
        self.close.closed().await
    }
}

#[derive(Default)]
pub(crate) struct StreamActions {
    pub(crate) reads: AtomicU64,
    pub(crate) stops: Mutex<Vec<Code>>,
    pub(crate) resets: Mutex<Vec<Code>>,
}

pub(crate) struct MemoryRecv {
    pub(crate) id: h3x::StreamId,
    pub(crate) receiver: mpsc::UnboundedReceiver<Result<Bytes, transport::StreamError>>,
    pub(crate) actions: Arc<StreamActions>,
}

impl Stream for MemoryRecv {
    type Item = Result<Bytes, transport::StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = self.receiver.poll_recv(cx);
        if matches!(&result, Poll::Ready(Some(Ok(_)))) {
            self.actions.reads.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

impl RecvStream for MemoryRecv {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, transport::StreamError>>> {
        Stream::poll_next(Pin::new(self), cx)
    }

    fn stop(&mut self, code: Code) -> Result<(), transport::StreamError> {
        self.actions
            .stops
            .lock()
            .expect("stop actions poisoned")
            .push(code);
        self.receiver.close();
        Ok(())
    }
}

pub(crate) struct MemorySend {
    pub(crate) id: h3x::StreamId,
    pub(crate) sender: Option<mpsc::UnboundedSender<Result<Bytes, transport::StreamError>>>,
    pub(crate) actions: Arc<StreamActions>,
}

impl Sink<Bytes> for MemorySend {
    type Error = transport::StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.sender.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(transport::StreamError::reset(
                Code::H3_REQUEST_CANCELLED,
            )))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.sender
            .as_ref()
            .ok_or_else(|| transport::StreamError::reset(Code::H3_REQUEST_CANCELLED))?
            .send(Ok(item))
            .map_err(|_| transport::StreamError::reset(Code::H3_REQUEST_CANCELLED))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.sender.take();
        Poll::Ready(Ok(()))
    }
}

impl SendStream for MemorySend {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), transport::StreamError>> {
        Sink::poll_ready(Pin::new(self), cx)
    }

    fn start_send(&mut self, item: Bytes) -> Result<(), transport::StreamError> {
        Sink::start_send(Pin::new(self), item)
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), transport::StreamError>> {
        Sink::poll_close(Pin::new(self), cx)
    }

    fn reset(&mut self, code: Code) -> Result<(), transport::StreamError> {
        self.actions
            .resets
            .lock()
            .expect("reset actions poisoned")
            .push(code);
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(Err(transport::StreamError::reset(code)));
        }
        Ok(())
    }
}

pub(crate) fn stream_direction(id: u64) -> (MemoryRecv, MemorySend) {
    let id =
        h3x::StreamId::from(qbase::varint::VarInt::try_from(id).expect("test stream ID is valid"));
    let (sender, receiver) = mpsc::unbounded_channel();
    let actions = Arc::new(StreamActions::default());
    (
        MemoryRecv {
            id,
            receiver,
            actions: Arc::clone(&actions),
        },
        MemorySend {
            id,
            sender: Some(sender),
            actions,
        },
    )
}

pub(crate) async fn connection_pair() -> (Connection<MemoryTransport>, Connection<MemoryTransport>)
{
    let (a, b) = MemoryTransport::pair();
    let (a, b) = tokio::join!(
        Connection::new(a, Settings::default()),
        Connection::new(b, Settings::default())
    );
    (a.expect("left connection"), b.expect("right connection"))
}

pub(crate) async fn connection_pair_with_settings(
    left: Settings,
    right: Settings,
) -> (Connection<MemoryTransport>, Connection<MemoryTransport>) {
    let (a, b) = MemoryTransport::pair();
    let (a, b) = tokio::join!(Connection::new(a, left), Connection::new(b, right));
    (a.expect("left connection"), b.expect("right connection"))
}
