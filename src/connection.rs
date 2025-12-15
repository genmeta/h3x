use std::{
    error::Error as StdError,
    fmt::Debug,
    io,
    pin::{Pin, pin},
    sync::Arc,
};

pub mod settings;
pub mod stream;

use futures::{
    FutureExt, SinkExt, Stream, StreamExt,
    channel::oneshot,
    future::{self, BoxFuture},
    stream::FusedStream,
};
use snafu::Snafu;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    agent::{LocalAgent, RemoteAgent},
    buflist::BufList,
    codec::{DecodeExt, Encode, EncodeExt, Feed, SinkWriter, StreamReader},
    connection::{
        settings::Settings,
        stream::{H3StreamCreationError, UnidirectionalStream},
    },
    error::{Code, H3CriticalStreamClosed, H3FrameUnexpected, HasErrorCode},
    frame::{Frame, goaway::Goaway},
    message,
    qpack::{
        BoxInstructionSink, BoxInstructionStream, BoxSink,
        decoder::{Decoder, DecoderInstruction},
        encoder::{Encoder, EncoderInstruction},
    },
    quic::{self, GetStreamIdExt, StopStreamExt},
    util::{set_once::SetOnce, try_future::TryFuture, watch::Watch},
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
        let source = match source.downcast::<StreamError>() {
            Ok(error) => return error,
            Err(source) => source,
        };
        let source = match source.downcast::<quic::StreamError>() {
            Ok(error) => return StreamError::Quic { source: error },
            Err(source) => source,
        };
        let source = match source.downcast::<Arc<dyn HasErrorCode + Send + Sync + 'static>>() {
            Ok(error) => return StreamError::Code { source: error },
            Err(source) => source,
        };
        match source.downcast::<quic::ConnectionError>() {
            Ok(error) => StreamError::Quic {
                source: error.into(),
            },
            Err(source) => panic!("io::Error({source:?}) is neither from StreamReader nor Decoder"),
        }
    }
}

#[derive(Debug)]
pub struct ConnectionState<C: ?Sized> {
    error: SetOnce<quic::ConnectionError>,
    local_settings: Arc<Settings>,
    peer_settings: SetOnce<Arc<Settings>>,
    local_goaway: Watch<Goaway>,
    peer_goaway: Watch<Goaway>,
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

    async fn open_uni(&self) -> Result<C::StreamWriter, quic::ConnectionError> {
        { self.quic_connection.open_uni() }.await
    }

    async fn accept_bi(&self) -> Result<(C::StreamReader, C::StreamWriter), quic::ConnectionError> {
        { self.quic_connection.accept_bi() }.await
    }

    async fn accept_uni(&self) -> Result<C::StreamReader, quic::ConnectionError> {
        { self.quic_connection.accept_uni() }.await
    }
}

impl<C: quic::WithLocalAgent + ?Sized> ConnectionState<C> {
    fn local_agent(&self) -> BoxFuture<'_, Result<Option<LocalAgent>, quic::ConnectionError>> {
        self.quic_connection.local_agent()
    }
}

impl<C: quic::WithRemoteAgent + ?Sized> ConnectionState<C> {
    fn remote_agent(&self) -> BoxFuture<'_, Result<Option<RemoteAgent>, quic::ConnectionError>> {
        self.quic_connection.remote_agent()
    }
}

#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionGoaway {
    #[snafu(display("Local goaway"))]
    Local,
    #[snafu(display("Peer goaway"))]
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

    fn local_settings(&self) -> &Settings {
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
pub enum InitialRequestStreamError {
    #[snafu(transparent)]
    Quic { source: quic::StreamError },
    #[snafu(transparent)]
    Goaway { source: ConnectionGoaway },
}

impl From<quic::ConnectionError> for InitialRequestStreamError {
    fn from(error: quic::ConnectionError) -> Self {
        Self::Quic {
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
    pub async fn initial_request_stream(
        &self,
    ) -> Result<(Pin<Box<C::StreamReader>>, Pin<Box<C::StreamWriter>>), InitialRequestStreamError>
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

type FrameSink = Feed<BoxSink<'static, Frame<BufList>, StreamError>, Frame<BufList>>;

pub struct Connection<C: quic::Connection + ?Sized> {
    state: Arc<ConnectionState<C>>,
    qpack_encoder: Arc<QPackEncoder>,
    qpack_decoder: Arc<QPackDecoder>,
    control_stream: AsyncMutex<FrameSink>,
    task: AbortOnDropHandle<()>,
}

impl<C: quic::Connection + ?Sized + Debug> Debug for Connection<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("state", &self.state)
            .field("qpack_encoder", &"...")
            .field("qpack_decoder", &"...")
            .field("control_stream", &"...")
            .field("task", &self.task)
            .finish()
    }
}

impl<C: quic::Connection + ?Sized> Connection<C> {
    pub async fn new(settings: Arc<Settings>, quic: C) -> Result<Self, quic::ConnectionError>
    where
        C: Sized,
    {
        let state = Arc::new(ConnectionState::new(quic, settings));

        let (qpack_encoder_inst_receiver_tx, qpack_encoder_inst_receiver_rx) = oneshot::channel();
        let (qpack_decoder_inst_receiver_tx, qpack_decoder_inst_receiver_rx) = oneshot::channel();
        let (control_stream_tx, control_stream_rx) = oneshot::channel();

        let qpack_encoder = {
            // lazily open QPACK encoder stream. if the dynamic table is never used, the stream is never opened.
            let conn_state = state.clone();
            let qpack_encoder_inst_sender = Box::pin(TryFuture::from(Box::pin(async move {
                // open QPACK encoder stream
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                // send encoder stream type
                let encoder_stream =
                    UnidirectionalStream::new_qpack_encoder_stream(uni_stream).await?;
                // turn into EncoderInstruction sink
                Ok::<_, StreamError>(encoder_stream.into_encode_sink())
            })));

            let connection_error = state.error();
            let qpack_decoder_inst_receiver = Box::pin(TryFuture::from(async move {
                tokio::select! {
                    Ok(inst_stream) = qpack_decoder_inst_receiver_rx => Ok(inst_stream),
                    error = connection_error => Err(error),
                }
            }));

            Arc::new(Encoder::new(
                Arc::<Settings>::default(),
                qpack_encoder_inst_sender as BoxInstructionSink<'static, EncoderInstruction>,
                qpack_decoder_inst_receiver as BoxInstructionStream<'static, DecoderInstruction>,
            ))
        };

        let qpack_decoder = {
            // lazily open QPACK decoder stream. if the dynamic table is never used by peer, the stream is never opened.
            let conn_state = state.clone();
            let qpack_decoder_inst_sender = Box::pin(TryFuture::from(async move {
                // open QPACK encoder stream
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                // send encoder stream type
                let decoder_stream =
                    UnidirectionalStream::new_qpack_decoder_stream(uni_stream).await?;
                // turn into DecoderInstruction sink
                Ok::<_, StreamError>(decoder_stream.into_encode_sink())
            }));

            let connection_error = state.error();
            let qpack_encoder_inst_receiver = Box::pin(TryFuture::from(async move {
                tokio::select! {
                    Ok(inst_stream) = qpack_encoder_inst_receiver_rx => Ok(inst_stream),
                    error = connection_error => Err(error),
                }
            }));

            Arc::new(Decoder::new(
                state.local_settings().clone(),
                qpack_decoder_inst_sender as BoxInstructionSink<'static, DecoderInstruction>,
                qpack_encoder_inst_receiver as BoxInstructionStream<'static, EncoderInstruction>,
            ))
        };

        let conn_state = state.clone();
        let accept_uni = async move {
            let mut qpack_encoder_inst_receiver_tx = Some(qpack_encoder_inst_receiver_tx);
            let mut qpack_decoder_inst_receiver_tx = Some(qpack_decoder_inst_receiver_tx);
            let mut control_stream_tx = Some(control_stream_tx);
            loop {
                let uni_stream = conn_state.accept_uni().await?;
                let uni_stream = StreamReader::new(Box::pin(uni_stream));
                if let Ok(mut uni_stream) =
                    uni_stream.into_decoded::<UnidirectionalStream<_>>().await
                {
                    // Only one control stream per peer is permitted; receipt of a second
                    // stream claiming to be a control stream MUST be treated as a connection
                    // error of type H3_STREAM_CREATION_ERROR.
                    //
                    // https://datatracker.ietf.org/doc/html/rfc9114#section-6.2.1-2
                    if uni_stream.is_control_stream() {
                        let tx = control_stream_tx
                            .take()
                            .ok_or(H3StreamCreationError::DuplicateControlStream)?;
                        _ = tx.send(uni_stream)
                    }
                    /* TODO: else if stream.is_push_promise() { ... } */
                    else if uni_stream.is_qpack_encoder_stream() {
                        let tx = qpack_encoder_inst_receiver_tx
                            .take()
                            .ok_or(H3StreamCreationError::DuplicateQpackEncoderStream)?;
                        _ = tx.send(uni_stream.into_decode_stream())
                    } else if uni_stream.is_qpack_decoder_stream() {
                        let tx = qpack_decoder_inst_receiver_tx
                            .take()
                            .ok_or(H3StreamCreationError::DuplicateQpackDecoderStream)?;
                        _ = tx.send(uni_stream.into_decode_stream())
                    } else if uni_stream.is_reserved_stream() {
                        // The payload and length of the stream are selected in any manner the
                        // sending implementation chooses. When sending a reserved stream type,
                        // the implementation MAY either terminate the stream cleanly or reset
                        // it. When resetting the stream, either the H3_NO_ERROR error code or
                        // a reserved error code (Section 8.1) SHOULD be used.
                        //
                        // https://datatracker.ietf.org/doc/html/rfc9114#section-6.2.3-2
                        _ = uni_stream.stop(Code::H3_NO_ERROR.value()).await;
                    } else {
                        // If the stream header indicates a stream type that is not supported by
                        // the recipient, the remainder of the stream cannot be consumed as the
                        // semantics are unknown. Recipients of unknown stream types MUST either
                        // abort reading of the stream or discard incoming data without further
                        // processing. If reading is aborted, the recipient SHOULD use the
                        // H3_STREAM_CREATION_ERROR error code or a reserved error code (Section
                        // 8.1). The recipient MUST NOT consider unknown stream types to be a
                        // connection error of any kind.
                        _ = uni_stream
                            .stop(Code::H3_STREAM_CREATION_ERROR.value())
                            .await;
                    }
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, StreamError>(())
        };
        let accept_uni_task = AbortOnDropHandle::new(tokio::spawn(accept_uni.in_current_span()));

        let encoder = qpack_encoder.clone();
        let conn_state = state.clone();
        let handle_control = async move {
            let control_stream = tokio::select! {
                Ok(control_stream) = control_stream_rx => control_stream.into_inner(),
                _error = conn_state.error() => return Ok::<_, StreamError>(()),
            };
            let mut control_frame_stream = pin!(control_stream.into_decode_stream::<Frame<_>, _>());

            // SETTINGS frames always apply to an entire HTTP/3 connection, never a
            // single stream. A SETTINGS frame MUST be sent as the first frame of
            // each control stream (see Section 6.2.1) by each peer, and it MUST NOT
            // be sent subsequently. If an endpoint receives a second SETTINGS frame
            // on the control stream, the endpoint MUST respond with a connection
            // error of type H3_FRAME_UNEXPECTED.
            //
            // https://datatracker.ietf.org/doc/html/rfc9114#frame-settings
            let mut settings_frame = control_frame_stream
                .next()
                .await
                .ok_or(H3CriticalStreamClosed::Control)??;
            if settings_frame.r#type() != Frame::SETTINGS_FRAME_TYPE {
                return Err(Code::H3_MISSING_SETTINGS.into());
            }
            let settings = Arc::new(settings_frame.decode_one::<Settings>().await?);
            tracing::debug!("Remote settings applied: {:?}", settings);
            conn_state
                .peer_settings
                .set(settings.clone())
                .expect("duplicate peer settings");
            encoder.apply_settings(settings.clone()).await;

            loop {
                let mut frame = control_frame_stream
                    .next()
                    .await
                    .ok_or(H3CriticalStreamClosed::Control)??;

                // https://datatracker.ietf.org/doc/html/rfc9114#frame-settings
                if frame.r#type() == Frame::SETTINGS_FRAME_TYPE {
                    return Err(H3FrameUnexpected::DuplicateSettings.into());
                } else if frame.r#type() == Frame::GOAWAY_FRAME_TYPE {
                    let goaway = frame.decode_one::<Goaway>().await?;
                    // An endpoint MAY send multiple GOAWAY frames indicating different
                    // identifiers, but the identifier in each frame MUST NOT be greater
                    // than the identifier in any previous frame, since clients might
                    // already have retried unprocessed requests on another HTTP connection.
                    // Receiving a GOAWAY containing a larger identifier than previously
                    // received MUST be treated as a connection error of type H3_ID_ERROR.
                    if let Some(previous_goaway) = conn_state.peer_goaway.peek()
                        && goaway.stream_id() > previous_goaway.stream_id()
                    {
                        return Err(Code::H3_ID_ERROR.into());
                    }
                    _ = conn_state.peer_goaway.set(goaway)
                }
                // https://datatracker.ietf.org/doc/html/rfc9114#name-reserved-frame-types
                else if frame.is_reversed_frame() {
                    // skip the frame
                    continue;
                }
            }
        };
        let handle_control_stream =
            AbortOnDropHandle::new(tokio::spawn(handle_control.in_current_span()));

        let encoder = qpack_encoder.clone();
        let receive_decoder_instructions = async move {
            loop {
                encoder.receive_instruction().await?
            }

            #[allow(unreachable_code)]
            Ok::<_, StreamError>(())
        };
        let receive_decoder_instructions =
            AbortOnDropHandle::new(tokio::spawn(receive_decoder_instructions.in_current_span()));

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

        // open control stream
        let uni_stream = SinkWriter::new(Box::pin(state.open_uni().await?));
        // send control stream type
        let mut control_stream = match UnidirectionalStream::new_control_stream(uni_stream).await {
            Ok(control_stream) => {
                let control_frame_sink = control_stream.into_encode_sink().sink_map_err(
                    |stream_error| match stream_error {
                        quic::StreamError::Reset { .. } => H3CriticalStreamClosed::Control.into(),
                        stream_error => stream_error.into(),
                    },
                );
                Feed::new(Box::pin(control_frame_sink) as BoxSink<_, _>)
            }
            Err(error) => {
                state.handle_error(error).await;
                return Err(state.error().await);
            }
        };
        let Ok(settings_frame) = BufList::new().encode(state.local_settings.as_ref()).await;
        match control_stream.send(settings_frame).await {
            Ok(()) => (),
            Err(error) => {
                state.handle_error(error).await;
                return Err(state.error().await);
            }
        }
        match control_stream.flush().await {
            Ok(()) => (),
            Err(error) => {
                state.handle_error(error).await;
                return Err(state.error().await);
            }
        }

        Ok(Self {
            state,
            qpack_encoder,
            qpack_decoder,
            control_stream: AsyncMutex::new(control_stream),
            task: AbortOnDropHandle::new(tokio::spawn(task.in_current_span())),
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

    pub async fn goaway(&self, goaway: Goaway) -> Result<(), quic::StreamError> {
        let mut control_stream = self.control_stream.lock().await;
        let Ok(goaway_frame) = BufList::new().encode(goaway).await;
        match control_stream.send(goaway_frame).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.state.handle_error(error).await),
        }
    }

    pub fn close(&self, error: &(impl HasErrorCode + ?Sized)) {
        self.state.close(error);
    }

    pub async fn closed(&self) -> quic::ConnectionError {
        self.state.error().await
    }

    pub fn local_agent(&self) -> BoxFuture<'_, Result<Option<LocalAgent>, quic::ConnectionError>> {
        self.state.local_agent()
    }

    pub fn remote_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<RemoteAgent>, quic::ConnectionError>> {
        self.state.remote_agent()
    }
}

impl<C: quic::Connection /* TODO: + ?Sized */> Connection<C> {
    pub async fn open_request_stream(
        &self,
    ) -> Result<
        (message::stream::ReadStream, message::stream::WriteStream),
        InitialRequestStreamError,
    > {
        let (stream_reader, stream_writer) = self.state.initial_request_stream().await?;
        Ok((
            message::stream::ReadStream::new(
                stream_reader,
                self.qpack_decoder.clone(),
                self.state.clone(),
            ),
            message::stream::WriteStream::new(
                stream_writer,
                self.qpack_encoder.clone(),
                self.state.clone(),
            ),
        ))
    }

    pub async fn accept_request_stream(
        &self,
    ) -> Result<(message::stream::ReadStream, message::stream::WriteStream), AcceptRequestStreamError>
    {
        let (stream_reader, stream_writer) = self.state.accept_request_stream().await?;
        Ok((
            message::stream::ReadStream::new(
                stream_reader,
                self.qpack_decoder.clone(),
                self.state.clone(),
            ),
            message::stream::WriteStream::new(
                stream_writer,
                self.qpack_encoder.clone(),
                self.state.clone(),
            ),
        ))
    }
}

impl<C: quic::Connection + ?Sized> Drop for Connection<C> {
    fn drop(&mut self) {
        self.close(&Code::H3_NO_ERROR);
    }
}
