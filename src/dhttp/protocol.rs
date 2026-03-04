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
        BoxPeekableBiStream, BoxPeekableUniStream, DecodeExt, Encode, EncodeExt, Feed, SinkWriter,
        StreamReader,
    },
    connection::{
        ConnectionGoaway, ConnectionState, QuicConnection, StreamError,
        stream::UnidirectionalStream,
    },
    dhttp::settings::Settings,
    error::{Code, H3CriticalStreamClosed, H3FrameUnexpected, H3IdError, H3StreamCreationError},
    frame::{Frame, goaway::Goaway, stream::FrameStream},
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, CancelStreamExt, ConnectionError, GetStreamIdExt, StopStreamExt},
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
            return Err(Code::H3_MISSING_SETTINGS.into());
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
                    return Err(Code::H3_ID_ERROR.into());
                }
                _ = self.peer_goaway.set(goaway)
            } else {
                // unknown frame type
            }
        }
    }

    fn on_initialed_message_stream(&self, stream_id: VarInt) -> Result<(), ConnectionGoaway> {
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

pub type BoxDynQuicStreeamReader = Pin<Box<dyn quic::ReadStream + Send>>;
pub type BoxDynQuicStreamWriter = Pin<Box<dyn quic::WriteStream + Send>>;

/// DHTTP/3 protocol layer.
///
/// Implements [`Protocol`] to handle HTTP/3 stream identification and
/// initialization. This layer recognizes HTTP/3 unidirectional stream types
/// (control, push, reserved) and accepts all
/// bidirectional streams as HTTP/3 request streams.
pub struct DHttpProtocol {
    /// DHTTP/3 protocol state.
    pub state: Arc<DHttpState>,

    /// Control stream frame sink
    pub control_stream: AsyncMutex<FrameSink>,

    handle_control_stream: SetOnce<AbortOnDropHandle<()>>,

    unresolved_request_streams: RingChannel<(
        StreamReader<BoxDynQuicStreeamReader>,
        SinkWriter<BoxDynQuicStreamWriter>,
    )>,
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

    async fn accept_uni<C: quic::Connection + ?Sized>(
        &self,
        connection: &Arc<QuicConnection<C>>,
        mut stream: BoxPeekableUniStream<C>,
    ) -> Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError> {
        let Ok(stream_type) = stream.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed(stream));
        };

        let raw = stream_type.into_inner();

        if stream_type == UnidirectionalStream::CONTROL_STREAM_TYPE {
            let state = self.state.clone();
            let connection = connection.clone();

            let init_handle_control_task = || {
                let handle_control = async move {
                    tokio::select! {
                        biased;
                        Err(stream_error) = state.handle_control_stream(stream.into_stream_reader()) => {
                            connection.handle_stream_error(stream_error).await;
                        }
                        _connection_error = connection.error() => {
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

    async fn accept_bi<C: quic::Connection + ?Sized>(
        &self,
        (mut reader, writer): BoxPeekableBiStream<C>,
    ) -> Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError> {
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
            let reader = reader
                .into_stream_reader()
                .map_stream(|b| b as BoxDynQuicStreeamReader);
            let writer = writer.map_sink(|b| b as BoxDynQuicStreamWriter);
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
}

impl<C: quic::Connection + ?Sized> Protocol<C> for DHttpProtocol {
    fn accept_uni<'a>(
        &'a self,
        connection: &'a Arc<QuicConnection<C>>,
        stream: BoxPeekableUniStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>> {
        Box::pin(self.accept_uni(connection, stream))
    }

    fn accept_bi<'a>(
        &'a self,
        connection: &'a Arc<QuicConnection<C>>,
        stream: BoxPeekableBiStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>> {
        _ = connection;
        Box::pin(self.accept_bi::<C>(stream))
    }
}

#[derive(Default, Debug, Clone)]
pub struct DHttpProtocolFactory {
    local_settings: Arc<Settings>,
}

impl DHttpProtocolFactory {
    pub fn new(local_settings: Arc<Settings>) -> Self {
        Self { local_settings }
    }

    pub async fn init<C: quic::Connection + ?Sized>(
        &self,
        conn: &QuicConnection<C>,
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
                return Err(conn.error().await);
            }
        };

        let Ok(settings_frame) = BufList::new().encode(self.local_settings.as_ref()).await;
        match control_stream.send(settings_frame).await {
            Ok(()) => (),
            Err(stream_error) => {
                conn.handle_stream_error(stream_error).await;
                return Err(conn.error().await);
            }
        }

        Ok(DHttpProtocol {
            state: Arc::new(DHttpState::new(self.local_settings.clone())),
            control_stream: AsyncMutex::new(control_stream),
            handle_control_stream: SetOnce::new(),
            unresolved_request_streams: RingChannel::new(32), // TODO: configurable capacity
        })
    }
}

impl<C: quic::Connection + ?Sized> ProductProtocol<C> for DHttpProtocolFactory {
    type Protocol = DHttpProtocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<QuicConnection<C>>,
        layers: &'a Protocols<C>,
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

impl<C: quic::Close + ?Sized> ConnectionState<C> {
    pub async fn peer_settings(
        &self,
    ) -> impl Future<Output = Result<Arc<Settings>, quic::ConnectionError>> + Send + use<C> {
        let error = self.closed();
        (self.dhttp().peer_settings.get()).then(|option| match option {
            Some(settings) => future::ready(Ok(settings)).left_future(),
            None => error.map(Err).right_future(),
        })
    }

    pub fn peer_goawaies(
        &self,
    ) -> impl FusedStream<Item = Result<Goaway, quic::ConnectionError>> + Send + use<C> {
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
            self.quic_connection()
                .handle_stream_error(stream_error)
                .await;
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

impl<C: quic::Close + quic::ManageStream + Send + Sync + ?Sized> ConnectionState<C> {
    pub async fn initial_raw_message_stream(
        &self,
    ) -> Result<
        (
            StreamReader<BoxDynQuicStreeamReader>,
            SinkWriter<BoxDynQuicStreamWriter>,
        ),
        InitialRawMessageStreamError,
    > {
        let (reader, writer) = self.quic_connection().open_bi().await?;
        let (mut reader, writer) = (Box::pin(reader), Box::pin(writer));
        self.dhttp()
            .on_initialed_message_stream(reader.stream_id().await?)?;
        Ok((StreamReader::new(reader), SinkWriter::new(writer)))
    }

    pub async fn accept_raw_message_stream(
        &self,
    ) -> Result<
        (
            StreamReader<BoxDynQuicStreeamReader>,
            SinkWriter<BoxDynQuicStreamWriter>,
        ),
        AcceptRawMessageStreamError,
    > {
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

// #[cfg(test)]
// mod tests {
//     use std::{any::Any, pin::Pin, sync::Arc};

//     use bytes::Bytes;

//     use super::DHttpLayer;
//     use crate::{
//         codec::{StreamReader, peekable::PeekableStreamReader},
//         connection::settings::Settings,
//         layer::{BoxPeekableUniStream, Protocol, StreamVerdict},
//         varint::VarInt,
//     };

//     /// Helper: create a BoxPeekableUniStream from raw byte chunks.
//     fn peekable_uni_from_chunks(chunks: Vec<&'static [u8]>) -> BoxPeekableUniStream {
//         let chunks_owned: Vec<Bytes> = chunks.into_iter().map(Bytes::from_static).collect();
//         // We need a Pin<Box<dyn quic::ReadStream + Send>>. Our mock stream
//         // needs to implement GetStreamId, StopStream, Stream, and Any.
//         // Use the mock_stream_pair from quic::test for proper streams,
//         // but for simpler unit tests we can use a custom approach.

//         // For these tests, we'll construct the PeekableStreamReader directly
//         // from a StreamReader over a stream that yields the right types.
//         // BoxPeekableUniStream = PeekableStreamReader<Pin<Box<dyn ReadStream + Send>>>
//         // This requires the inner stream to implement ReadStream which needs
//         // GetStreamId + StopStream + Stream<Item=Result<Bytes, StreamError>> + Send + Any.

//         // Use mock_stream_pair and feed data into it.
//         let (reader, mut writer) = crate::quic::test::mock_stream_pair(VarInt::from_u32(0));

//         // Spawn a task to feed data into the writer
//         tokio::spawn(async move {
//             use futures::SinkExt;
//             for chunk in chunks_owned {
//                 if writer.send(chunk).await.is_err() {
//                     break;
//                 }
//             }
//             // Close the writer
//             let _ = writer.close().await;
//         });

//         let boxed_reader: Pin<Box<dyn crate::quic::ReadStream + Send>> = Box::pin(reader);
//         let stream_reader = StreamReader::new(boxed_reader);
//         PeekableStreamReader::new(stream_reader)
//     }

//     /// Helper: create a BoxPeekableBiStream from raw byte chunks for the read side.
//     fn peekable_bi_from_chunks(read_chunks: Vec<&'static [u8]>) -> crate::layer::BoxPeekableBiStream {
//         let (reader, mut writer_feed) = crate::quic::test::mock_stream_pair(VarInt::from_u32(4));
//         let (_, write_side) = crate::quic::test::mock_stream_pair(VarInt::from_u32(4));

//         let chunks_owned: Vec<Bytes> = read_chunks.into_iter().map(Bytes::from_static).collect();
//         tokio::spawn(async move {
//             use futures::SinkExt;
//             for chunk in chunks_owned {
//                 if writer_feed.send(chunk).await.is_err() {
//                     break;
//                 }
//             }
//             let _ = writer_feed.close().await;
//         });

//         let boxed_reader: Pin<Box<dyn crate::quic::ReadStream + Send>> = Box::pin(reader);
//         let boxed_writer: Pin<Box<dyn crate::quic::WriteStream + Send>> = Box::pin(write_side);
//         let stream_reader = StreamReader::new(boxed_reader);
//         let peekable = PeekableStreamReader::new(stream_reader);
//         (peekable, boxed_writer)
//     }

//     #[test]
//     fn test_dhttp_layer_new() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = DHttpLayer::with_default_settings();
//         assert_eq!(Protocol::<()>::name(&layer), "dhttp3");
//         assert!(layer.peer_settings().is_none());
//         assert!(layer.local_goaway().is_none());
//         assert!(layer.peer_goaway().is_none());
//     }

//     #[test]
//     fn test_dhttp_layer_new_with_settings() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let settings = Arc::new(Settings::default());
//         let layer = DHttpLayer::new(settings.clone());
//         assert_eq!(Protocol::<()>::name(&layer), "dhttp3");
//         assert!(std::sync::Arc::ptr_eq(layer.local_settings(), &settings));
//     }

//     #[tokio::test]
//     async fn test_accept_uni_control_stream() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = DHttpLayer::with_default_settings();

//         // Install dispatch channel so accept_uni can dispatch
//         let (control_tx, _control_rx) = futures::channel::oneshot::channel();
//         layer.set_control_dispatch_channel(control_tx);

//         // Stream type 0x00 = control stream (1-byte VarInt)
//         let stream = peekable_uni_from_chunks(vec![&[0x00], b"hello"]);
//         let result = Protocol::<()>::accept_uni(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
//     }

//     #[tokio::test]
//     async fn test_accept_uni_push_stream() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = DHttpLayer::with_default_settings();

//         let (control_tx, _control_rx) = futures::channel::oneshot::channel();
//         layer.set_control_dispatch_channel(control_tx);

//         // Stream type 0x01 = push stream
//         let stream = peekable_uni_from_chunks(vec![&[0x01]]);
//         let result = Protocol::<()>::accept_uni(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
//     }

//     #[tokio::test]
//     async fn test_accept_uni_reserved_stream() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = DHttpLayer::with_default_settings();

//         let (control_tx, _control_rx) = futures::channel::oneshot::channel();
//         layer.set_control_dispatch_channel(control_tx);

//         // Stream type 0x21 = reserved (0x21 + 0*0x1f)
//         // 0x21 as 2-byte VarInt: 0x40, 0x21
//         let stream = peekable_uni_from_chunks(vec![&[0x40, 0x21]]);
//         let result = Protocol::<()>::accept_uni(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
//     }

//     #[tokio::test]
//     async fn test_accept_uni_unknown_stream_type() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = DHttpLayer::with_default_settings();

//         // Stream type 0x04 = unknown, not HTTP/3
//         let stream = peekable_uni_from_chunks(vec![&[0x04], b"data"]);
//         let result = Protocol::<()>::accept_uni(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
//     }

//     #[tokio::test]
//     async fn test_accept_uni_another_unknown_type() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = DHttpLayer::with_default_settings();

//         // Stream type 0x10 = unknown, not HTTP/3
//         let stream = peekable_uni_from_chunks(vec![&[0x10]]);
//         let result = Protocol::<()>::accept_uni(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
//     }

//     #[tokio::test]
//     async fn test_accept_bi_always_accepted() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = DHttpLayer::with_default_settings();

//         let stream = peekable_bi_from_chunks(vec![b"request data"]);
//         let result = Protocol::<()>::accept_bi(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
//     }

//     #[test]
//     fn test_trait_upcasting_downcast() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = DHttpLayer::with_default_settings();
//         let layer_ref: &dyn Protocol<()> = &layer;
//         let any_ref: &dyn Any = layer_ref;
//         assert!(any_ref.downcast_ref::<DHttpLayer>().is_some());
//     }
// }
