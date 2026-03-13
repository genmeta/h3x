//! DHTTP/3 protocol layer implementation.
//!
//! [`DHttpLayer`] encapsulates all HTTP/3-specific logic for stream identification
//! and protocol initialization. It implements [`Protocol`] to participate in
//! the layered stream routing architecture.

use std::{
    ops,
    pin::{Pin, pin},
    sync::Arc,
};

use futures::{
    FutureExt, Sink, SinkExt, StreamExt,
    future::{self, BoxFuture},
    never::Never,
    stream::{self, FusedStream},
};
use snafu::Snafu;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    buflist::BufList,
    codec::{
        BoxReadStream, BoxWriteStream, DecodeExt, EncodeExt, ErasedPeekableBiStream,
        ErasedPeekableUniStream, ErasedStreamReader, ErasedStreamWriter, Feed, SinkWriter,
        StreamReader,
    },
    connection::{ConnectionGoaway, ConnectionState, LifecycleExt, StreamError},
    dhttp::{
        frame::{Frame, stream::FrameStream},
        goaway::Goaway,
        settings::Settings,
        stream::UnidirectionalStream,
    },
    error::{
        Code, H3CriticalStreamClosed, H3FrameUnexpected, H3IdError, H3MissingSettings,
        H3StreamCreationError,
    },
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, CancelStreamExt, ConnectionError, GetStreamIdExt, StopStreamExt},
    runtime::ErasedConnection,
    util::{ring_channel::RingChannel, set_once::SetOnce, watch::Watch},
    varint::VarInt,
};

type BoxSink<'a, Item, Err> = Pin<Box<dyn Sink<Item, Error = Err> + Send + 'a>>;

/// Internal shared state for the DHTTP/3 layer.
///
/// This struct holds the HTTP/3-specific protocol state that is shared
/// between the layer and its background tasks.
#[derive(Debug)]
pub struct DHttpState {
    /// Local HTTP/3 settings advertised to the peer.
    pub local_settings: Arc<Settings>,
    /// Peer's HTTP/3 settings, received via the control stream.
    pub peer_settings: SetOnce<Arc<Settings>>,
    /// Local GOAWAY state, set when this endpoint initiates graceful shutdown.
    pub local_goaway: Watch<Goaway>,
    /// Peer's GOAWAY state, set when the peer initiates graceful shutdown.
    pub peer_goaway: Watch<Goaway>,
    /// Maximum stream ID that this endpoint has initialized (opened).
    pub max_initialized_stream_id: Watch<VarInt>,
    /// Maximum stream ID that this endpoint has received from the peer.
    pub max_received_stream_id: Watch<VarInt>,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        sync::Arc,
    };

    use super::*;
    use crate::dhttp::settings::{Setting, Settings};

    fn hash_of<T: Hash>(t: &T) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }

    #[test]
    fn dhttp_factory_same_settings_equal_hash() {
        let s1 = Arc::new(Settings::default());
        let s2 = Arc::new(Settings::default());

        let f1 = DHttpProtocolFactory::new(s1);
        let f2 = DHttpProtocolFactory::new(s2);

        assert_eq!(hash_of(&f1), hash_of(&f2));
    }

    #[test]
    fn dhttp_factory_different_settings_different_hash() {
        let s_default = Settings::default();
        let mut s_other = Settings::default();

        s_other.set(Setting::enable_connect_protocol(true));

        let f1 = DHttpProtocolFactory::new(Arc::new(s_default));
        let f2 = DHttpProtocolFactory::new(Arc::new(s_other));

        assert_ne!(hash_of(&f1), hash_of(&f2));
    }

    #[test]
    fn dhttp_factory_same_settings_eq() {
        let s1 = Arc::new(Settings::default());
        let s2 = Arc::new(Settings::default());

        let f1 = DHttpProtocolFactory::new(s1);
        let f2 = DHttpProtocolFactory::new(s2);

        assert_eq!(f1, f2);
    }

    #[test]
    fn dhttp_factory_different_settings_not_eq() {
        let s_default = Settings::default();
        let mut s_other = Settings::default();
        s_other.set(Setting::enable_connect_protocol(true));

        let f1 = DHttpProtocolFactory::new(Arc::new(s_default));
        let f2 = DHttpProtocolFactory::new(Arc::new(s_other));

        assert_ne!(f1, f2);
    }
}

impl DHttpState {
    /// Creates a new `DHttpLayerState` with the given local settings.
    fn new(local_settings: Arc<Settings>) -> Self {
        Self {
            local_settings,
            peer_settings: SetOnce::new(),
            local_goaway: Watch::new(),
            peer_goaway: Watch::new(),
            max_initialized_stream_id: Watch::new(),
            max_received_stream_id: Watch::new(),
        }
    }

    fn new_goaway(&self) -> Goaway {
        let mut local_goaway = self.local_goaway.lock();
        let max_received_stream_id = self.max_received_stream_id.lock();

        let max_received_stream_id = max_received_stream_id
            .get()
            .copied()
            .unwrap_or(VarInt::from_u32(0));

        let goaway = Goaway::new(max_received_stream_id);
        local_goaway.set(goaway);

        goaway
    }

    async fn handle_control_stream<S: quic::ReadStream>(
        &self,
        stream: StreamReader<S>,
    ) -> Result<Never, StreamError> {
        let mut control_frame_stream = pin!(FrameStream::new(stream));

        // First frame MUST be SETTINGS.
        let mut settings_frame = control_frame_stream
            .as_mut()
            .next_frame()
            .await
            .ok_or(H3CriticalStreamClosed::Control)??;
        if settings_frame.r#type() != Frame::SETTINGS_FRAME_TYPE {
            return Err(H3MissingSettings.into());
        }
        let settings = Arc::new(settings_frame.decode_one::<Settings>().await?);
        tracing::debug!(?settings, "Received remote settings");
        self.peer_settings
            .set(settings)
            .expect("handle control task set once");

        loop {
            let mut frame = control_frame_stream
                .as_mut()
                .next_unreserved_frame()
                .await
                .ok_or(H3CriticalStreamClosed::Control)??;
            if frame.r#type() == Frame::SETTINGS_FRAME_TYPE {
                return Err(H3FrameUnexpected::DuplicateSettings.into());
            } else if frame.r#type() == Frame::GOAWAY_FRAME_TYPE {
                let goaway = frame.decode_one::<Goaway>().await?;
                if let Some(previous_goaway) = self.peer_goaway.peek()
                    && goaway.stream_id() > previous_goaway.stream_id()
                {
                    return Err(H3IdError::GoawayStreamIdOrdering.into());
                }
                _ = self.peer_goaway.set(goaway)
            } else {
                // unknown frame type
            }
        }
    }

    fn on_initialized_message_stream(&self, stream_id: VarInt) -> Result<(), ConnectionGoaway> {
        if let Some(goaway) = self.peer_goaway.peek()
            && goaway.stream_id() >= stream_id
        {
            return Err(ConnectionGoaway::Peer);
        }
        let mut max_received_stream_id = self.max_received_stream_id.lock();
        max_received_stream_id.set(
            max_received_stream_id
                .get()
                .map_or(stream_id, |current| *current.max(&stream_id)),
        );

        Ok(())
    }

    fn on_accepted_message_stream(&self, stream_id: VarInt) -> Result<(), ConnectionGoaway> {
        if let Some(goaway) = self.peer_goaway.peek()
            && goaway.stream_id() >= stream_id
        {
            return Err(ConnectionGoaway::Peer);
        }
        let mut max_received_stream_id = self.max_received_stream_id.lock();
        max_received_stream_id.set(
            max_received_stream_id
                .get()
                .map_or(stream_id, |current| *current.max(&stream_id)),
        );

        Ok(())
    }
}

type FrameSink = Feed<BoxSink<'static, Frame<BufList>, StreamError>, Frame<BufList>>;

pub type BoxDynQuicStreamReader = BoxReadStream;
pub type BoxDynQuicStreamWriter = BoxWriteStream;

/// DHTTP/3 protocol layer.
///
/// Implements [`Protocol`] to handle HTTP/3 stream identification and
/// initialization. This layer recognizes HTTP/3 unidirectional stream types
/// (control, push, reserved) and accepts all
/// bidirectional streams as HTTP/3 request streams.
pub struct DHttpProtocol {
    /// DHTTP/3 protocol state.
    pub state: Arc<DHttpState>,

    /// Erased connection for lifecycle operations.
    pub connection: Arc<dyn ErasedConnection>,

    /// Control stream frame sink
    pub control_stream: AsyncMutex<FrameSink>,

    handle_control_stream: SetOnce<AbortOnDropHandle<()>>,

    unresolved_request_streams: RingChannel<(ErasedStreamReader, ErasedStreamWriter)>,
}

impl ops::Deref for DHttpProtocol {
    type Target = Arc<DHttpState>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl std::fmt::Debug for DHttpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DHttpLayer")
            .field("state", &self.state)
            .field("control_stream", &"...")
            .finish()
    }
}

impl DHttpProtocol {
    pub async fn max_unresolved_request_streams(&self) -> usize {
        self.unresolved_request_streams.capacity()
    }

    async fn accept_uni(
        &self,
        mut stream: ErasedPeekableUniStream,
    ) -> Result<StreamVerdict<ErasedPeekableUniStream>, StreamError> {
        let Ok(stream_type) = stream.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed(stream));
        };

        let raw = stream_type.into_inner();

        if stream_type == UnidirectionalStream::CONTROL_STREAM_TYPE {
            let state = self.state.clone();
            let connection = self.connection.clone();

            let init_handle_control_task = || {
                let handle_control = async move {
                    tokio::select! {
                        biased;
                        Err(stream_error) = state.handle_control_stream(stream.into_stream_reader()) => {
                            connection.handle_stream_error(stream_error).await;
                        }
                        _connection_error = connection.closed() => {
                            // Connection error occurred, likely due to shutdown. Just exit the task.
                        }
                    }
                };
                AbortOnDropHandle::new(tokio::spawn(handle_control.in_current_span()))
            };

            if self
                .handle_control_stream
                .set_with(init_handle_control_task)
                .is_err()
            {
                return Err(H3StreamCreationError::DuplicateControlStream.into());
            }
            Ok(StreamVerdict::Accepted)
        } else if stream_type == UnidirectionalStream::PUSH_STREAM_TYPE {
            // The push ID space begins at zero and ends at a maximum value set by
            // the MAX_PUSH_ID frame. In particular, a server is not able to push
            // until after the client sends a MAX_PUSH_ID frame. A client sends
            // MAX_PUSH_ID frames to control the number of pushes that a server can
            // promise. A server SHOULD use push IDs sequentially, beginning from
            // zero. A client MUST treat receipt of a push stream as a connection
            // error of type H3_ID_ERROR when no MAX_PUSH_ID frame has been sent or
            // when the stream references a push ID that is greater than the maximum
            // push ID.
            //
            // https://datatracker.ietf.org/doc/html/rfc9114#section-4.6-3
            Err(H3IdError::PushIdExceedsLimit.into())
        } else if raw >= 0x21 && (raw - 0x21).is_multiple_of(0x1f) {
            // Reserved unidirectional stream types are accepted but ignored.
            stream.stop(Code::H3_NO_ERROR.into_inner()).await?;
            Ok(StreamVerdict::Accepted)
        } else {
            // Not an HTTP/3 stream type. Reset cursor so the next layer
            // can re-read the stream type VarInt.
            Ok(StreamVerdict::Passed(stream))
        }
    }

    async fn accept_bi(
        &self,
        (mut reader, writer): ErasedPeekableBiStream,
    ) -> Result<StreamVerdict<ErasedPeekableBiStream>, StreamError> {
        // HTTP/3 bidirectional streams are request streams (RFC 9114 §4.1).
        // The first bytes on a request stream are HTTP/3 frames, starting with
        // a frame type VarInt. We peek the first VarInt to determine whether
        // this stream belongs to HTTP/3 or to another protocol (e.g.,
        // WebTransport uses signal value 0x41 which is NOT a valid HTTP/3
        // frame type).
        //
        // Known HTTP/3 frame types and reserved types (0x1f*N+0x21) are
        // accepted. Note that reserved frames MAY appear before HEADERS on a
        // request stream (RFC 9114 §7.2.8). Everything else is passed to the
        // next protocol layer.
        let frame_type = match reader.decode_one::<VarInt>().await {
            Ok(v) => v,
            Err(_) => {
                // Stream closed or error before we could read a frame type.
                // Cannot determine protocol — pass to the next layer.
                return Ok(StreamVerdict::Passed((reader, writer)));
            }
        };

        if Self::is_http3_frame_type(frame_type) {
            // This is an HTTP/3 request stream. Reset the peek cursor so the
            // frame type can be re-read by FrameStream during request processing.
            Pin::new(&mut reader).reset();
            let reader = reader.into_stream_reader();
            let item = (reader, writer);
            if let Some(mut unresolved) = self.unresolved_request_streams.send(item) {
                // Ring channel is full — reject the oldest unresolved request.
                let code = Code::H3_REQUEST_REJECTED.into_inner();
                _ = tokio::join!(unresolved.0.stop(code), unresolved.1.cancel(code));
            }
            Ok(StreamVerdict::Accepted)
        } else {
            // Not an HTTP/3 frame type. Reset cursor so the next protocol
            // layer can re-read the first bytes.
            Ok(StreamVerdict::Passed((reader, writer)))
        }
    }

    /// Returns `true` if the given VarInt is a known HTTP/3 frame type or a
    /// reserved frame type (RFC 9114 §7.2.8).
    ///
    /// Known frame types (RFC 9114 §11.1):
    /// - 0x00 DATA, 0x01 HEADERS, 0x03 CANCEL_PUSH, 0x04 SETTINGS,
    ///   0x05 PUSH_PROMISE, 0x07 GOAWAY, 0x0d MAX_PUSH_ID
    ///
    /// Reserved: 0x1f * N + 0x21 for non-negative integer N
    const fn is_http3_frame_type(frame_type: VarInt) -> bool {
        let raw = frame_type.into_inner();
        matches!(raw, 0x00 | 0x01 | 0x03 | 0x04 | 0x05 | 0x07 | 0x0d)
            || (raw >= 0x21 && (raw - 0x21).is_multiple_of(0x1f))
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(connection: Arc<dyn ErasedConnection>) -> Self {
        let sink: BoxSink<'static, Frame<BufList>, StreamError> =
            Box::pin(futures::sink::drain().sink_map_err(|never| match never {}));

        Self {
            state: Arc::new(DHttpState::new(Arc::new(Settings::default()))),
            connection,
            control_stream: AsyncMutex::new(Feed::new(sink)),
            handle_control_stream: SetOnce::new(),
            unresolved_request_streams: RingChannel::new(32),
        }
    }
}

impl Protocol for DHttpProtocol {
    fn accept_uni<'a>(
        &'a self,
        stream: ErasedPeekableUniStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
        Box::pin(self.accept_uni(stream))
    }

    fn accept_bi<'a>(
        &'a self,
        stream: ErasedPeekableBiStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
        Box::pin(self.accept_bi(stream))
    }
}

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DHttpProtocolFactory {
    local_settings: Arc<Settings>,
}

impl DHttpProtocolFactory {
    pub fn new(local_settings: Arc<Settings>) -> Self {
        Self { local_settings }
    }

    pub async fn init<C: quic::Connection>(
        &self,
        conn: &Arc<C>,
    ) -> Result<DHttpProtocol, quic::ConnectionError> {
        let uni_stream = SinkWriter::new(Box::pin(conn.open_uni().await?));
        let mut control_stream = match UnidirectionalStream::initial_control_stream(uni_stream)
            .await
        {
            Ok(stream) => {
                let control_frame_sink = stream.into_encode_sink().sink_map_err(
                    |error: quic::StreamError| match error {
                        quic::StreamError::Reset { .. } => H3CriticalStreamClosed::Control.into(),
                        quic_stream_error => quic_stream_error.into(),
                    },
                );
                Feed::new(Box::pin(control_frame_sink) as BoxSink<_, _>)
            }
            Err(stream_error) => {
                conn.handle_stream_error(stream_error).await;
                return Err(conn.closed().await);
            }
        };

        let Ok(settings_frame) = BufList::new().encode(self.local_settings.as_ref()).await;
        match control_stream.send(settings_frame).await {
            Ok(()) => (),
            Err(stream_error) => {
                conn.handle_stream_error(stream_error).await;
                return Err(conn.closed().await);
            }
        }

        let connection: Arc<dyn ErasedConnection> = conn.clone();

        Ok(DHttpProtocol {
            state: Arc::new(DHttpState::new(self.local_settings.clone())),
            connection,
            control_stream: AsyncMutex::new(control_stream),
            handle_control_stream: SetOnce::new(),
            unresolved_request_streams: RingChannel::new(32), // TODO: configurable capacity
        })
    }
}

impl<C: quic::Connection> ProductProtocol<C> for DHttpProtocolFactory {
    type Protocol = DHttpProtocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a Protocols,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
        _ = layers;
        Box::pin(self.init(conn))
    }
}

impl<C: ?Sized> ConnectionState<C> {
    #[doc(alias = "http")]
    pub fn dhttp(&self) -> &DHttpProtocol {
        self.protocol::<DHttpProtocol>()
            .expect("DHttp protocol cannot be omitted")
    }

    pub fn settings(&self) -> Arc<Settings> {
        self.dhttp().local_settings.clone()
    }

    pub fn max_received_stream_id(&self) -> Option<VarInt> {
        self.dhttp().max_received_stream_id.peek()
    }

    pub fn max_initialized_stream_id(&self) -> Option<VarInt> {
        self.dhttp().max_initialized_stream_id.peek()
    }

    pub fn peek_peer_goaway(&self) -> Option<Goaway> {
        self.dhttp().peer_goaway.peek()
    }
}

impl<C: quic::Lifecycle + Sync + ?Sized> ConnectionState<C> {
    pub async fn peer_settings(
        &self,
    ) -> impl Future<Output = Result<Arc<Settings>, quic::ConnectionError>> + Send + use<'_, C>
    {
        let error = self.closed();
        (self.dhttp().peer_settings.get()).then(|option| match option {
            Some(settings) => future::ready(Ok(settings)).left_future(),
            None => error.map(Err).right_future(),
        })
    }

    pub fn peer_goawaies(
        &self,
    ) -> impl FusedStream<Item = Result<Goaway, quic::ConnectionError>> + Send + use<'_, C> {
        stream::select(
            self.dhttp().peer_goaway.watch().map(Ok),
            self.closed().map(Err).into_stream(),
        )
    }

    pub async fn goaway(&self) -> Result<(), quic::ConnectionError> {
        let send_goaway = async {
            let dhttp = self.dhttp();
            let mut control_stream = dhttp.control_stream.lock().await;
            let Ok(goaway_frame) = BufList::new().encode(dhttp.new_goaway()).await;
            control_stream.send(goaway_frame).await
        };

        if let Err(stream_error) = send_goaway.await {
            self.quic().handle_stream_error(stream_error).await;
            return Err(self.closed().await);
        }

        Ok(())
    }
}

#[derive(Debug, Snafu, Clone)]
pub enum InitialRawMessageStreamError {
    #[snafu(transparent)]
    Connection { source: quic::ConnectionError },
    #[snafu(transparent)]
    ResponseStream { source: quic::StreamError },
    #[snafu(transparent)]
    Goaway { source: ConnectionGoaway },
}

#[derive(Debug, Snafu, Clone)]
#[snafu(module)]
pub enum AcceptRawMessageStreamError {
    #[snafu(transparent)]
    Connection { source: quic::ConnectionError },
    #[snafu(transparent)]
    RequestStream { source: quic::StreamError },
    #[snafu(transparent)]
    Goaway { source: ConnectionGoaway },
}

impl<C: quic::Lifecycle + quic::ManageStream + Send + Sync + ?Sized> ConnectionState<C> {
    pub async fn initial_raw_message_stream(
        &self,
    ) -> Result<(ErasedStreamReader, ErasedStreamWriter), InitialRawMessageStreamError> {
        let (reader, writer) = self.open_bi().await?;
        let (mut reader, writer) = (Box::pin(reader), Box::pin(writer));
        self.dhttp()
            .on_initialized_message_stream(reader.stream_id().await?)?;
        Ok((StreamReader::new(reader), SinkWriter::new(writer)))
    }

    pub async fn accept_raw_message_stream(
        &self,
    ) -> Result<(ErasedStreamReader, ErasedStreamWriter), AcceptRawMessageStreamError> {
        let (reader, writer) = tokio::select! {
            biased;
            stream = self.dhttp().unresolved_request_streams.receive() => stream,
            connection_error = self.closed() => return Err(connection_error.into()),
            // TODO: goaway branch
        };
        let mut reader = Box::pin(reader);
        self.dhttp()
            .on_accepted_message_stream(reader.stream_id().await?)?;
        Ok((StreamReader::new(reader), writer))
    }
}
