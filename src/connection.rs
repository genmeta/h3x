use std::{
    any::{Any, TypeId},
    collections::HashMap,
    error::Error as StdError,
    fmt::Debug,
    io,
    pin::Pin,
    sync::Arc,
};

pub mod settings;
pub mod stream;

use futures::{
    FutureExt, SinkExt, Stream, StreamExt,
    future::{self, BoxFuture},
    stream::FusedStream,
};
use snafu::Snafu;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    agent,
    buflist::BufList,
    codec::{Encode, Feed, SinkWriter, StreamReader, peekable::PeekableStreamReader},
    connection::settings::Settings,
    error::{Code, HasErrorCode},
    frame::{Frame, goaway::Goaway},
    layer::{ProtocolLayer, StreamVerdict, dhttp::DHttpLayer, qpack::QPackLayer},
    message,
    qpack::{
        BoxInstructionSink, BoxInstructionStream, BoxSink,
        decoder::{Decoder, DecoderInstruction},
        encoder::{Encoder, EncoderInstruction},
    },
    quic::{self, GetStreamIdExt, StopStreamExt},
    util::{set_once::SetOnce, watch::Watch},
    varint::VarInt,
};

#[derive(Debug, Snafu, Clone)]
pub enum StreamError {
    #[snafu(transparent)]
    Quic { source: quic::StreamError },
    #[snafu(transparent)]
    Code {
        source: Arc<dyn HasErrorCode + Send + Sync>,
    },
}

impl From<quic::ConnectionError> for StreamError {
    fn from(value: quic::ConnectionError) -> Self {
        Self::Quic {
            source: value.into(),
        }
    }
}

impl StreamError {
    pub fn map_stream_reset(self, map: impl FnOnce(VarInt) -> Self) -> Self {
        match self {
            StreamError::Quic {
                source: quic::StreamError::Reset { code },
            } => map(code),
            error => error,
        }
    }
}

impl<E: HasErrorCode + StdError + Send + Sync + 'static> From<E> for StreamError {
    fn from(value: E) -> Self {
        StreamError::Code {
            source: Arc::new(value),
        }
    }
}

impl From<StreamError> for io::Error {
    fn from(value: StreamError) -> Self {
        io::Error::other(value)
    }
}

impl From<io::Error> for StreamError {
    fn from(source: io::Error) -> Self {
        let error = match source.downcast::<StreamError>() {
            Ok(error) => return error,
            Err(error) => error,
        };
        let error = match quic::StreamError::try_from(error) {
            Ok(error) => return error.into(),
            Err(error) => error,
        };
        match error.downcast::<Arc<dyn HasErrorCode + Send + Sync + 'static>>() {
            Ok(error) => error.into(),
            Err(error) => unreachable!(
                "io::Error({error:?}) cannot be converted to connection::StreamError, this is a bug"
            ),
        }
    }
}

#[derive(Debug)]
pub struct ConnectionState<C: ?Sized> {
    error: SetOnce<quic::ConnectionError>,
    local_settings: Arc<Settings>,
    pub(crate) peer_settings: SetOnce<Arc<Settings>>,
    local_goaway: Watch<Goaway>,
    pub(crate) peer_goaway: Watch<Goaway>,
    max_initialized_stream_id: Watch<VarInt>,
    max_received_stream_id: Watch<VarInt>,

    quic_connection: C,
}

impl<C: ?Sized> ConnectionState<C> {
    fn new(quic: C, local_settings: Arc<Settings>) -> Self
    where
        C: Sized,
    {
        Self {
            quic_connection: quic,
            error: SetOnce::new(),
            local_settings,
            peer_settings: SetOnce::new(),
            local_goaway: Watch::new(),
            peer_goaway: Watch::new(),
            max_initialized_stream_id: Watch::new(),
            max_received_stream_id: Watch::new(),
        }
    }
}

impl<C: quic::ManageStream + ?Sized> ConnectionState<C> {
    async fn open_bi(&self) -> Result<(C::StreamReader, C::StreamWriter), quic::ConnectionError> {
        { self.quic_connection.open_bi() }.await
    }

    pub(crate) async fn open_uni(&self) -> Result<C::StreamWriter, quic::ConnectionError> {
        { self.quic_connection.open_uni() }.await
    }

    async fn accept_bi(&self) -> Result<(C::StreamReader, C::StreamWriter), quic::ConnectionError> {
        { self.quic_connection.accept_bi() }.await
    }

    async fn accept_uni(&self) -> Result<C::StreamReader, quic::ConnectionError> {
        { self.quic_connection.accept_uni() }.await
    }
}

impl<C: quic::WithLocalAgent + Sync + ?Sized> ConnectionState<C> {
    fn local_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<Arc<dyn agent::LocalAgent>>, quic::ConnectionError>> {
        Box::pin(async {
            Ok(self
                .quic_connection
                .local_agent()
                .await?
                .map(|a| Arc::new(a) as Arc<dyn agent::LocalAgent>))
        })
    }
}

impl<C: quic::WithRemoteAgent + Sync + ?Sized> ConnectionState<C> {
    fn remote_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<Arc<dyn agent::RemoteAgent>>, quic::ConnectionError>> {
        Box::pin(async {
            Ok(self
                .quic_connection
                .remote_agent()
                .await?
                .map(|a| Arc::new(a) as Arc<dyn agent::RemoteAgent>))
        })
    }
}

#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionGoaway {
    #[snafu(display("local goaway"))]
    Local,
    #[snafu(display("peer goaway"))]
    Peer,
}

impl<C: quic::Close + ?Sized> ConnectionState<C> {
    pub fn close(&self, error: &(impl HasErrorCode + ?Sized)) {
        if self.error.peek().is_some() {
            return;
        }
        self.quic_connection
            .close(error.code(), error.to_string().into())
    }

    pub async fn handle_error(&self, error: StreamError) -> quic::StreamError {
        match error {
            StreamError::Quic { source } => match source {
                quic::StreamError::Connection { source } => {
                    _ = self.error.set_with(|| source);
                    self.error().await.into()
                }
                quic::StreamError::Reset { .. } => source,
            },
            StreamError::Code { source } => {
                self.close(source.as_ref());
                self.error().await.into()
            }
        }
    }

    pub(crate) fn local_settings(&self) -> &Settings {
        &self.local_settings
    }

    pub fn error(&self) -> impl Future<Output = quic::ConnectionError> + use<C> {
        self.error
            .get()
            .map(|option| option.expect("connection closed without error"))
    }

    pub fn settings(&self) -> Arc<Settings> {
        self.local_settings.clone()
    }

    pub fn peer_settings(
        &self,
    ) -> impl Future<Output = Result<Arc<Settings>, quic::ConnectionError>> + use<C> {
        let error = self.error();
        self.peer_settings.get().then(|option| match option {
            Some(settings) => future::ready(Ok(settings)).left_future(),
            None => error.map(Err).right_future(),
        })
    }

    pub fn peer_goawaies(
        &self,
    ) -> impl FusedStream<Item = Result<Goaway, quic::ConnectionError>> + use<C> {
        let goawaies = self.peer_goaway.watch().map(Ok);
        goawaies.chain(self.error().map(Err).into_stream())
    }

    pub fn local_goaway(&self) -> Result<Option<Goaway>, quic::ConnectionError> {
        if let Some(error) = self.error.peek() {
            return Err(error.clone());
        }
        Ok(self.local_goaway.peek())
    }

    pub fn goaway(&self) -> Goaway {
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
}

#[derive(Debug, Snafu, Clone)]
#[snafu(module)]
pub enum OpenRequestStreamError {
    #[snafu(transparent)]
    RequestStream { source: quic::StreamError },
    #[snafu(transparent)]
    Goaway { source: ConnectionGoaway },
}

impl From<quic::ConnectionError> for OpenRequestStreamError {
    fn from(error: quic::ConnectionError) -> Self {
        Self::RequestStream {
            source: error.into(),
        }
    }
}

#[derive(Debug, Snafu, Clone)]
#[snafu(module)]
pub enum AcceptRequestStreamError {
    #[snafu(transparent)]
    Quic { source: quic::StreamError },
    #[snafu(transparent)]
    Goaway { source: ConnectionGoaway },
}

impl From<quic::ConnectionError> for AcceptRequestStreamError {
    fn from(error: quic::ConnectionError) -> Self {
        Self::Quic {
            source: error.into(),
        }
    }
}

impl<C: quic::Close + quic::ManageStream + ?Sized> ConnectionState<C> {
    pub async fn open_request_stream(
        &self,
    ) -> Result<(Pin<Box<C::StreamReader>>, Pin<Box<C::StreamWriter>>), OpenRequestStreamError>
    {
        let (reader, writer) = self.open_bi().await?;
        let mut reader = Box::pin(reader);
        let writer = Box::pin(writer);
        let stream_id = reader.stream_id().await?;
        {
            let mut max_initialized_stream_id = self.max_initialized_stream_id.lock();
            max_initialized_stream_id.set(
                max_initialized_stream_id
                    .get()
                    .map_or(stream_id, |current| *current.max(&stream_id)),
            );
        }
        if let Some(goaway) = self.peer_goaway.peek()
            && goaway.stream_id() >= stream_id
        {
            return Err(ConnectionGoaway::Peer.into());
        }

        Ok((reader, writer))
    }

    pub async fn accept_request_stream(
        &self,
    ) -> Result<(Pin<Box<C::StreamReader>>, Pin<Box<C::StreamWriter>>), AcceptRequestStreamError>
    {
        let (reader, writer) = self.accept_bi().await?;
        let mut reader = Box::pin(reader);
        let writer = Box::pin(writer);
        let stream_id = reader.stream_id().await?;

        match self.local_goaway.peek() {
            None => Ok((reader, writer)),
            Some(goaway) if goaway.stream_id() >= stream_id => Err(ConnectionGoaway::Local.into()),
            Some(..) => {
                let mut max_received_stream_id = self.max_received_stream_id.lock();
                max_received_stream_id.set(
                    max_received_stream_id
                        .get()
                        .map_or(stream_id, |current| *current.max(&stream_id)),
                );
                Ok((reader, writer))
            }
        }
    }
}

pub type BoxStreamWriter<C> = SinkWriter<Pin<Box<<C as quic::ManageStream>::StreamWriter>>>;
pub type BoxStreamReader<C> = StreamReader<Pin<Box<<C as quic::ManageStream>::StreamReader>>>;

pub type QPackEncoder = Encoder<
    BoxInstructionSink<'static, EncoderInstruction>,
    BoxInstructionStream<'static, DecoderInstruction>,
>;

pub type QPackDecoder = Decoder<
    BoxInstructionSink<'static, DecoderInstruction>,
    BoxInstructionStream<'static, EncoderInstruction>,
>;

pub type FrameSink = Feed<BoxSink<'static, Frame<BufList>, StreamError>, Frame<BufList>>;

pub struct Connection<C: quic::Connection + ?Sized> {
    state: Arc<ConnectionState<C>>,
    layers: HashMap<TypeId, Arc<dyn ProtocolLayer<C>>>,
    task: AbortOnDropHandle<()>,
}

impl<C: quic::Connection + ?Sized + Debug> Debug for Connection<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("state", &self.state)
            .field(
                "layers",
                &self.layers.values().map(|l| l.name()).collect::<Vec<_>>(),
            )
            .field("task", &self.task)
            .finish()
    }
}

impl<C: quic::Connection + ?Sized> Connection<C> {
    pub async fn new(settings: Arc<Settings>, quic: C) -> Result<Self, quic::ConnectionError>
    where
        C: Sized,
    {
        let state = Arc::new(ConnectionState::new(quic, settings.clone()));

        // Create layers
        let dhttp_layer = Arc::new(DHttpLayer::new(settings));
        let qpack_layer = Arc::new(QPackLayer::new());

        // Initialize QPackLayer first (creates encoder/decoder)
        let (qpack_encoder, receive_decoder_instructions) = qpack_layer.init_qpack(&state);
        // Initialize DHttpLayer (opens control stream, sends SETTINGS, spawns handle_control)
        let handle_control_stream = dhttp_layer.init_dhttp(&state, qpack_encoder).await?;

        // Layer-based routing loop: iterate layers for each incoming uni stream
        let conn_state = state.clone();
        let layers_for_routing: Vec<Arc<dyn ProtocolLayer<C>>> = vec![
            qpack_layer.clone() as Arc<dyn ProtocolLayer<C>>,
            dhttp_layer.clone() as Arc<dyn ProtocolLayer<C>>,
        ];
        let accept_uni = async move {
            loop {
                let uni_stream = conn_state.accept_uni().await?;
                let uni_stream: Pin<Box<dyn crate::quic::ReadStream + Send>> = Box::pin(uni_stream);
                let stream_reader = StreamReader::new(uni_stream);
                let mut peekable = Some(PeekableStreamReader::new(stream_reader));

                let mut accepted = false;
                for layer in &layers_for_routing {
                    // Invariant: `peekable` is always `Some` here because `Passed`
                    // returns the stream and `Accepted` breaks out of the loop.
                    let stream = peekable.take().ok_or(StreamError::Quic {
                        source: quic::StreamError::Reset {
                            code: Code::H3_INTERNAL_ERROR.value(),
                        },
                    })?;
                    match layer.accept_uni(stream).await? {
                        StreamVerdict::Accepted => {
                            accepted = true;
                            break;
                        }
                        StreamVerdict::Passed(returned_stream) => {
                            peekable = Some(returned_stream);
                        }
                    }
                }

                if !accepted {
                    // No layer accepted the stream — stop it with H3_STREAM_CREATION_ERROR.
                    // https://datatracker.ietf.org/doc/html/rfc9114#section-6.2-7
                    if let Some(stream) = peekable {
                        let mut stream_reader = stream.into_stream_reader();
                        let _ = stream_reader
                            .stop(Code::H3_STREAM_CREATION_ERROR.value())
                            .await;
                    }
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, StreamError>(())
        };
        let accept_uni_task = AbortOnDropHandle::new(tokio::spawn(accept_uni.in_current_span()));

        // Supervisor task: join all background tasks
        let conn_state = state.clone();
        let task = async move {
            match tokio::try_join!(
                accept_uni_task.map(Result::unwrap),
                handle_control_stream.map(Result::unwrap),
                receive_decoder_instructions.map(Result::unwrap)
            ) {
                Ok(_) => unreachable!(),
                Err(error) => _ = conn_state.handle_error(error).await,
            }
        };
        let task = AbortOnDropHandle::new(tokio::spawn(task.in_current_span()));

        // Build unified layer map for typed access
        let mut layers = HashMap::new();
        layers.insert(
            TypeId::of::<QPackLayer>(),
            qpack_layer.clone() as Arc<dyn ProtocolLayer<C>>,
        );
        layers.insert(
            TypeId::of::<DHttpLayer>(),
            dhttp_layer.clone() as Arc<dyn ProtocolLayer<C>>,
        );

        Ok(Self {
            state,
            layers,
            task,
        })
    }

    /// Returns a typed reference to a registered protocol layer.
    ///
    /// Uses `TypeId`-based lookup in the layer map, then downcasts to `Arc<L>`.
    pub fn layer<L: ProtocolLayer<C>>(&self) -> Option<Arc<L>> {
        self.layers.get(&TypeId::of::<L>()).and_then(|layer| {
            let any: Arc<dyn Any + Send + Sync> = layer.clone();
            any.downcast::<L>().ok()
        })
    }

    pub fn settings(&self) -> Arc<Settings> {
        self.state.local_settings.clone()
    }

    pub async fn peer_settings(&self) -> Result<Arc<Settings>, quic::ConnectionError> {
        self.state.peer_settings().await
    }

    pub fn max_received_stream_id(&self) -> Option<VarInt> {
        self.state.max_received_stream_id.peek()
    }

    pub fn max_initialized_stream_id(&self) -> Option<VarInt> {
        self.state.max_initialized_stream_id.peek()
    }

    pub fn peer_goaway(&self) -> Option<Goaway> {
        self.state.peer_goaway.peek()
    }

    pub fn peer_goawaies(&self) -> impl Stream<Item = Result<Goaway, quic::ConnectionError>> {
        self.state.peer_goawaies()
    }

    // TODO: close with handy way(code + reason)
    pub fn close(&self, error: &(impl HasErrorCode + ?Sized)) {
        self.state.close(error);
    }

    pub async fn closed(&self) -> quic::ConnectionError {
        self.state.error().await
    }

    pub fn local_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<Arc<dyn agent::LocalAgent>>, quic::ConnectionError>> {
        self.state.local_agent()
    }

    pub fn remote_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<Arc<dyn agent::RemoteAgent>>, quic::ConnectionError>> {
        self.state.remote_agent()
    }
}

impl<C: quic::Connection /* TODO: + ?Sized */> Connection<C> {
    pub async fn goaway(&self, goaway: Goaway) -> Result<(), quic::StreamError> {
        let dhttp = self.layer::<DHttpLayer>().ok_or(quic::StreamError::Reset {
            code: Code::H3_INTERNAL_ERROR.value(),
        })?;
        let control_stream_lock = dhttp.control_stream().ok_or(quic::StreamError::Reset {
            code: Code::H3_INTERNAL_ERROR.value(),
        })?;
        let mut control_stream = control_stream_lock.lock().await;
        let Ok(goaway_frame) = BufList::new().encode(goaway).await;
        match control_stream.send(goaway_frame).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.state.handle_error(error).await),
        }
    }

    pub async fn open_request_stream(
        &self,
    ) -> Result<(message::stream::ReadStream, message::stream::WriteStream), OpenRequestStreamError>
    {
        let dhttp = self
            .layer::<DHttpLayer>()
            .ok_or(OpenRequestStreamError::RequestStream {
                source: quic::StreamError::Reset {
                    code: Code::H3_INTERNAL_ERROR.value(),
                },
            })?;
        let qpack = self
            .layer::<QPackLayer>()
            .ok_or(OpenRequestStreamError::RequestStream {
                source: quic::StreamError::Reset {
                    code: Code::H3_INTERNAL_ERROR.value(),
                },
            })?;
        let (stream_reader, stream_writer) = self.state.open_request_stream().await?;
        let qpack_decoder = qpack
            .qpack_decoder()
            .ok_or(OpenRequestStreamError::RequestStream {
                source: quic::StreamError::Reset {
                    code: Code::H3_INTERNAL_ERROR.value(),
                },
            })?
            .clone();
        let qpack_encoder = qpack
            .qpack_encoder()
            .ok_or(OpenRequestStreamError::RequestStream {
                source: quic::StreamError::Reset {
                    code: Code::H3_INTERNAL_ERROR.value(),
                },
            })?
            .clone();
        Ok((
            message::stream::ReadStream::new(stream_reader, qpack_decoder, dhttp.clone()),
            message::stream::WriteStream::new(stream_writer, qpack_encoder, dhttp),
        ))
    }

    pub async fn accept_request_stream(
        &self,
    ) -> Result<(message::stream::ReadStream, message::stream::WriteStream), AcceptRequestStreamError>
    {
        let dhttp = self
            .layer::<DHttpLayer>()
            .ok_or(AcceptRequestStreamError::Quic {
                source: quic::StreamError::Reset {
                    code: Code::H3_INTERNAL_ERROR.value(),
                },
            })?;
        let qpack = self
            .layer::<QPackLayer>()
            .ok_or(AcceptRequestStreamError::Quic {
                source: quic::StreamError::Reset {
                    code: Code::H3_INTERNAL_ERROR.value(),
                },
            })?;
        let (stream_reader, stream_writer) = self.state.accept_request_stream().await?;
        let qpack_decoder = qpack
            .qpack_decoder()
            .ok_or(AcceptRequestStreamError::Quic {
                source: quic::StreamError::Reset {
                    code: Code::H3_INTERNAL_ERROR.value(),
                },
            })?
            .clone();
        let qpack_encoder = qpack
            .qpack_encoder()
            .ok_or(AcceptRequestStreamError::Quic {
                source: quic::StreamError::Reset {
                    code: Code::H3_INTERNAL_ERROR.value(),
                },
            })?
            .clone();
        Ok((
            message::stream::ReadStream::new(stream_reader, qpack_decoder, dhttp.clone()),
            message::stream::WriteStream::new(stream_writer, qpack_encoder, dhttp),
        ))
    }
}

impl<C: quic::Connection + ?Sized> Drop for Connection<C> {
    fn drop(&mut self) {
        self.close(&Code::H3_NO_ERROR);
    }
}
