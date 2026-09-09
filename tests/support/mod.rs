#![allow(dead_code)]
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::{BufMut, Bytes, BytesMut, buf::UninitSlice};
use dquic::{
    prelude::{StreamReader, StreamWriter},
    qconnection::{ArcReliableFrameDeque, DataStreams},
};
use h3x::{
    Code, Settings, StreamId,
    transport::{self, Role},
};
use qbase::{
    flow::ArcSendControler,
    frame::{Frame, StreamCtlFrame, StreamFrame, io::ReceiveFrame},
    packet::RecordFrame,
    param::{
        ArcParameters, Parameters,
        handy::{client_parameters, server_parameters},
    },
    sid::handy::DemandConcurrency,
    util::ContinuousData,
};
use tokio::sync::watch;

pub type Connection = Arc<h3x::Connection<MemoryTransport>>;
pub trait StreamIdValue {
    fn as_u64(&self) -> u64;
}
impl StreamIdValue for StreamId {
    fn as_u64(&self) -> u64 {
        (*self).into()
    }
}

struct Streams {
    data: DataStreams,
    params: ArcParameters,
    controls: ArcReliableFrameDeque,
    flow: ArcSendControler<ArcReliableFrameDeque>,
    offsets: Mutex<HashMap<StreamId, u64>>,
}
impl Streams {
    fn new(role: Role) -> Self {
        let mut client = client_parameters();
        let mut server = server_parameters();
        let cid = qbase::cid::ConnectionId::default();
        client
            .set(qbase::param::ParameterId::InitialSourceConnectionId, cid)
            .unwrap();
        server
            .set(qbase::param::ParameterId::InitialSourceConnectionId, cid)
            .unwrap();
        server
            .set(
                qbase::param::ParameterId::OriginalDestinationConnectionId,
                cid,
            )
            .unwrap();
        let controls = ArcReliableFrameDeque::with_capacity_and_wakers(16, Default::default());
        let data = match role {
            Role::Client => DataStreams::new(
                role,
                &client,
                &server,
                Box::new(DemandConcurrency),
                controls.clone(),
                Default::default(),
                None,
            ),
            Role::Server => DataStreams::new(
                role,
                &server,
                &qbase::param::ClientParameters::default(),
                Box::new(DemandConcurrency),
                controls.clone(),
                Default::default(),
                None,
            ),
        };
        match role {
            Role::Client => data.revise_params(false, &server),
            Role::Server => data.revise_params(false, &client),
        };
        let mut params = match role {
            Role::Client => {
                Parameters::new_client(client.clone(), Some(server.clone()), Default::default())
            }
            Role::Server => Parameters::new_server(server.clone()),
        };
        match role {
            Role::Client => params.recv_remote_params(server).unwrap(),
            Role::Server => params.recv_remote_params(client).unwrap(),
        }
        params.initial_scid_from_peer_need_equal(cid).unwrap();
        Self {
            data,
            params: params.into(),
            controls: controls.clone(),
            flow: ArcSendControler::new(1 << 28, controls, Default::default()),
            offsets: Mutex::default(),
        }
    }
    fn transfer(&self, peer: &Self) {
        let mut packet = Packet {
            bytes: BytesMut::with_capacity(1 << 20),
            data: Vec::new(),
            controls: Vec::new(),
        };
        let _ = self.data.try_load_data_into(&mut packet, &self.flow, false);
        let _ = self.controls.try_load_frames_into(&mut packet);
        for (frame, bytes) in packet.data {
            self.offsets
                .lock()
                .unwrap()
                .insert(frame.stream_id(), frame.range().end);
            if peer.data.recv_frame((frame.clone(), bytes)).is_ok() {
                self.data.on_data_acked(frame);
            }
        }
        for frame in packet.controls {
            let _ = peer.data.recv_stream_control(frame);
        }
    }
}

#[derive(Clone)]
pub struct MemoryTransport {
    role: Role,
    streams: Arc<Streams>,
    peer: Arc<Streams>,
    closed: watch::Sender<Option<transport::ConnectionError>>,
    pub next_bi: Arc<AtomicU64>,
}
impl MemoryTransport {
    pub fn pair() -> (Self, Self) {
        let a = Arc::new(Streams::new(Role::Client));
        let b = Arc::new(Streams::new(Role::Server));
        let (closed, _) = watch::channel(None);
        let weak_a = Arc::downgrade(&a);
        let weak_b = Arc::downgrade(&b);
        let mut stop = closed.subscribe();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(1));
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let (Some(a), Some(b)) = (weak_a.upgrade(), weak_b.upgrade()) else { break };
                        a.transfer(&b); b.transfer(&a);
                    }
                    _ = stop.changed() => break,
                }
            }
        });
        (
            Self {
                role: Role::Client,
                streams: a.clone(),
                peer: b.clone(),
                closed: closed.clone(),
                next_bi: Arc::new(AtomicU64::new(0)),
            },
            Self {
                role: Role::Server,
                streams: b,
                peer: a,
                closed,
                next_bi: Arc::new(AtomicU64::new(1)),
            },
        )
    }
    pub fn inject_control(&self, bytes: Bytes) {
        self.streams.transfer(&self.peer);
        let id = StreamId::new(self.role, qbase::sid::Dir::Uni, 0);
        let mut offsets = self.streams.offsets.lock().unwrap();
        let offset = offsets.get_mut(&id).unwrap();
        self.peer
            .data
            .recv_frame((StreamFrame::new(id, *offset, bytes.len()), bytes.clone()))
            .unwrap();
        *offset += bytes.len() as u64;
    }
    pub fn fail(&self) {
        self.closed
            .send_replace(Some(transport::ConnectionError::transport(
                std::io::Error::other("connection disappeared"),
            )));
        let error = qbase::error::QuicError::with_default_fty(
            qbase::error::ErrorKind::Internal,
            "test failure",
        )
        .into();
        self.streams.data.on_conn_error(&error);
        self.peer.data.on_conn_error(&error);
    }
}
impl transport::Connection for MemoryTransport {
    fn role(&self) -> Result<Role, transport::ConnectionError> {
        Ok(self.role)
    }
    async fn open_bi(
        &self,
    ) -> Result<(StreamId, (StreamReader, StreamWriter)), transport::ConnectionError> {
        let stream = self
            .streams
            .data
            .open_bi(&self.streams.params)
            .await?
            .unwrap();
        self.next_bi.fetch_add(4, Ordering::Relaxed);
        Ok(stream)
    }
    async fn open_uni(&self) -> Result<(StreamId, StreamWriter), transport::ConnectionError> {
        Ok(self
            .streams
            .data
            .open_uni(&self.streams.params)
            .await?
            .unwrap())
    }
    async fn accept_bi(
        &self,
    ) -> Result<(StreamId, (StreamReader, StreamWriter)), transport::ConnectionError> {
        Ok(self.streams.data.accept_bi(&self.streams.params).await?)
    }
    async fn accept_uni(&self) -> Result<(StreamId, StreamReader), transport::ConnectionError> {
        Ok(self.streams.data.accept_uni().await?)
    }
    fn close(&self, code: Code, reason: &[u8]) {
        if self.closed.borrow().is_some() {
            return;
        }
        self.closed
            .send_replace(Some(transport::ConnectionError::application(
                code,
                Bytes::copy_from_slice(reason),
            )));
        let error = qbase::error::AppError::new(
            qbase::varint::VarInt::try_from(code.as_u64()).unwrap(),
            "test close",
        )
        .into();
        self.streams.data.on_conn_error(&error);
        self.peer.data.on_conn_error(&error);
    }
    async fn closed(&self) -> transport::ConnectionError {
        self.closed
            .subscribe()
            .wait_for(Option::is_some)
            .await
            .unwrap()
            .clone()
            .unwrap()
    }
}

pub async fn new_connection(
    transport: MemoryTransport,
    settings: Settings,
) -> Result<Connection, h3x::Error> {
    h3x::protocol::new(transport, settings).await.map(Arc::new)
}
pub async fn connection_pair() -> (Connection, Connection) {
    connection_pair_with_settings(Settings::default(), Settings::default()).await
}
pub async fn connection_pair_with_settings(
    left: Settings,
    right: Settings,
) -> (Connection, Connection) {
    let (a, b) = MemoryTransport::pair();
    let (a, b) = tokio::join!(new_connection(a, left), new_connection(b, right));
    (a.unwrap(), b.unwrap())
}

struct Packet {
    bytes: BytesMut,
    data: Vec<(StreamFrame, Bytes)>,
    controls: Vec<StreamCtlFrame>,
}
// SAFETY: BytesMut owns storage and implements the initialized-length contract.
unsafe impl BufMut for Packet {
    fn remaining_mut(&self) -> usize {
        self.bytes.remaining_mut()
    }
    unsafe fn advance_mut(&mut self, count: usize) {
        unsafe { self.bytes.advance_mut(count) }
    }
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.bytes.chunk_mut()
    }
}
impl<D: ContinuousData> RecordFrame<Frame<D>, D> for Packet {
    fn record_frame(&mut self, frame: &Frame<D>) {
        match frame {
            Frame::Stream(frame, data) => self.data.push((frame.clone(), data.to_bytes())),
            Frame::StreamCtl(frame) => self.controls.push(frame.clone()),
            _ => {}
        }
    }
}

/// Single-stream convenience for tests that do not exercise the runtime accept loop.
pub async fn read_next_request(
    connection: &Connection,
) -> Result<Option<(http::Request<h3x::ChunkBody>, h3x::server::ResponseSender)>, h3x::Error> {
    let (id, (recv, send)) = transport::Connection::accept_bi(connection.transport())
        .await
        .map_err(|error| h3x::Error::Transport {
            source: Arc::new(error),
        })?;
    connection.read_request(id, recv, send).await
}
