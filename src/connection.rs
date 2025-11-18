use std::{
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex, MutexGuard as SyncMutexGuard},
};

use futures::{FutureExt, SinkExt, channel::oneshot, future};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    buflist::BufList,
    codec::{DecodeExt, Encode, EncodeExt, Feed, SinkWriter, StreamReader},
    error::{
        Code, ConnectionError, Error, H3CriticalStreamClosed, H3FrameUnexpected, HasErrorCode,
        StreamError,
    },
    frame::Frame,
    goaway::Goaway,
    message::{MessageReader, MessageWriter},
    qpack::{
        BoxInstructionSink, BoxInstructionStream, BoxSink,
        decoder::Decoder,
        encoder::Encoder,
        instruction::{DecoderInstruction, EncoderInstruction},
    },
    quic::{QuicConnect, StopSendingExt},
    settings::Settings,
    stream::{H3StreamCreationError, TryFutureStream, UnidirectionalStream},
    util::{SetOnce, Watch},
    varint::VarInt,
};

pub struct State<C> {
    quic_connection: SyncMutex<C>,

    error: SetOnce<ConnectionError>,
    local_settings: Settings,
    peer_settings: SetOnce<Settings>,
    peer_goaway: Watch<Goaway>,
    max_received_stream_id: Watch<VarInt>,
}

impl<C: QuicConnect + Unpin> State<C> {
    fn new(quic: C, local_settings: Settings) -> Self {
        Self {
            quic_connection: SyncMutex::new(quic),
            error: SetOnce::new(),
            local_settings,
            peer_settings: SetOnce::new(),
            peer_goaway: Watch::new(),
            max_received_stream_id: Watch::new(),
        }
    }

    fn quic_connection<'c>(&'c self) -> SyncMutexGuard<'c, C> {
        self.quic_connection.lock().unwrap()
    }

    async fn open_bi(&self) -> Result<(C::StreamReader, C::StreamWriter), ConnectionError> {
        { Pin::new(self.quic_connection().deref_mut()).open_bi() }.await
    }

    async fn open_uni(&self) -> Result<C::StreamWriter, ConnectionError> {
        { Pin::new(self.quic_connection().deref_mut()).open_uni() }.await
    }

    async fn accept_bi(&self) -> Result<(C::StreamReader, C::StreamWriter), ConnectionError> {
        { Pin::new(self.quic_connection().deref_mut()).accept_bi() }.await
    }

    async fn accept_uni(&self) -> Result<C::StreamReader, ConnectionError> {
        { Pin::new(self.quic_connection().deref_mut()).accept_uni() }.await
    }

    pub fn close(&self, error: &(impl HasErrorCode + ?Sized)) {
        if self.error.peek().is_some() {
            return;
        }
        Pin::new(self.quic_connection().deref_mut()).close(error.code(), error.to_string().into())
    }

    pub async fn handle_error(&self, error: Error) -> StreamError {
        match error {
            Error::Stream { source } => match source {
                StreamError::Connection { source } => {
                    _ = self.error.set_with(|| source);
                    self.error().await.into()
                }
                StreamError::Reset { .. } => source,
            },
            Error::Code { source } => {
                self.close(source.as_ref());
                self.error().await.into()
            }
        }
    }

    fn local_settings(&self) -> &Settings {
        &self.local_settings
    }

    pub fn error(&self) -> impl Future<Output = ConnectionError> + use<C> {
        self.error
            .get()
            .map(|option| option.expect("connection closed without error"))
    }

    fn peer_settings(&self) -> impl Future<Output = Result<Settings, ConnectionError>> + use<C> {
        let error = self.error();
        self.peer_settings.get().then(|option| match option {
            Some(settings) => future::ready(Ok(settings)).left_future(),
            None => error.map(Err).right_future(),
        })
    }

    fn max_received_stream_id(
        &self,
    ) -> impl Future<Output = Result<VarInt, ConnectionError>> + use<C> {
        let error = self.error();
        self.max_received_stream_id
            .get()
            .then(|option| match option {
                Some(stream_id) => future::ready(Ok(stream_id)).left_future(),
                None => error.map(Err).right_future(),
            })
    }

    fn peer_goaway(&self) -> impl Future<Output = Result<Goaway, ConnectionError>> + use<C> {
        let error = self.error();
        self.peer_goaway.get().then(|option| match option {
            Some(goaway) => future::ready(Ok(goaway)).left_future(),
            None => error.map(Err).right_future(),
        })
    }
}

pub type BoxStreamWriter<C> = SinkWriter<Pin<Box<<C as QuicConnect>::StreamWriter>>>;
pub type BoxStreamReader<C> = StreamReader<Pin<Box<<C as QuicConnect>::StreamReader>>>;

pub type QPackEncoder = Encoder<
    BoxInstructionSink<'static, EncoderInstruction>,
    BoxInstructionStream<'static, DecoderInstruction>,
>;

pub type QPackDecoder = Decoder<
    BoxInstructionSink<'static, DecoderInstruction>,
    BoxInstructionStream<'static, EncoderInstruction>,
>;

type FrameSink = Feed<BoxSink<'static, Frame<BufList>, Error>, Frame<BufList>>;

pub struct Connection<C: QuicConnect + Unpin> {
    state: Arc<State<C>>,
    qpack_encoder: Arc<QPackEncoder>,
    qpack_decoder: Arc<QPackDecoder>,
    control_stream: AsyncMutex<FrameSink>,
    task: AbortOnDropHandle<()>,
}

// #[bon::bon]
impl<C: QuicConnect + Unpin> Connection<C> {
    // #[builder]
    pub async fn new(
        // #[builder(default)]
        settings: Settings,
        quic: C,
    ) -> Result<Self, ConnectionError>
    where
        C: Send + 'static,
        C::StreamReader: Send + 'static,
        C::StreamWriter: Send + 'static,
    {
        let state = Arc::new(State::new(quic, settings));

        let (qpack_encoder_inst_receiver_tx, qpack_encoder_inst_receiver_rx) = oneshot::channel();
        let (qpack_decoder_inst_receiver_tx, qpack_decoder_inst_receiver_rx) = oneshot::channel();
        let (control_stream_tx, control_stream_rx) = oneshot::channel();

        let qpack_encoder = {
            // lazily open QPACK encoder stream. if the dynamic table is never used, the stream is never opened.
            let conn_state = state.clone();
            let qpack_encoder_inst_sender = Box::pin(TryFutureStream::from(Box::pin(async move {
                // open QPACK encoder stream
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                // send encoder stream type
                let encoder_stream =
                    UnidirectionalStream::new_qpack_encoder_stream(uni_stream).await?;
                // turn into EncoderInstruction sink
                Ok::<_, Error>(encoder_stream.into_encode_sink())
            })));

            let connection_error = state.error();
            let qpack_decoder_inst_receiver = Box::pin(TryFutureStream::from(async move {
                tokio::select! {
                    Ok(inst_stream) = qpack_decoder_inst_receiver_rx => Ok(inst_stream),
                    error = connection_error => Err(error),
                }
            }));

            Arc::new(Encoder::new(
                Settings::default(),
                qpack_encoder_inst_sender as BoxInstructionSink<'static, EncoderInstruction>,
                qpack_decoder_inst_receiver as BoxInstructionStream<'static, DecoderInstruction>,
            ))
        };

        let qpack_decoder = {
            // lazily open QPACK decoder stream. if the dynamic table is never used by peer, the stream is never opened.
            let conn_state = state.clone();
            let qpack_decoder_inst_sender = Box::pin(TryFutureStream::from(async move {
                // open QPACK encoder stream
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                // send encoder stream type
                let decoder_stream =
                    UnidirectionalStream::new_qpack_decoder_stream(uni_stream).await?;
                // turn into DecoderInstruction sink
                Ok::<_, Error>(decoder_stream.into_encode_sink())
            }));

            let connection_error = state.error();
            let qpack_encoder_inst_receiver = Box::pin(TryFutureStream::from(async move {
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
                        _ = uni_stream.stop_sending(Code::H3_NO_ERROR.value()).await;
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
                            .stop_sending(Code::H3_STREAM_CREATION_ERROR.value())
                            .await;
                    }
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, Error>(())
        };
        let accept_uni_task = AbortOnDropHandle::new(tokio::spawn(accept_uni.in_current_span()));

        let encoder = qpack_encoder.clone();
        let conn_state = state.clone();
        let handle_control = async move {
            let control_stream = tokio::select! {
                Ok(control_stream) = control_stream_rx => control_stream.into_inner(),
                _error = conn_state.error() => return Ok::<_, Error>(()),
            };

            // SETTINGS frames always apply to an entire HTTP/3 connection, never a
            // single stream. A SETTINGS frame MUST be sent as the first frame of
            // each control stream (see Section 6.2.1) by each peer, and it MUST NOT
            // be sent subsequently. If an endpoint receives a second SETTINGS frame
            // on the control stream, the endpoint MUST respond with a connection
            // error of type H3_FRAME_UNEXPECTED.
            //
            // https://datatracker.ietf.org/doc/html/rfc9114#frame-settings
            let mut settings_frame = control_stream.into_decoded::<Frame<_>>().await?;
            if settings_frame.r#type() != Frame::SETTINGS_FRAME_TYPE {
                return Err(Code::H3_MISSING_SETTINGS.into());
            }
            let settings = settings_frame.decode_one::<Settings>().await?;
            tracing::debug!("Remote settings applied: {:?}", settings);
            conn_state.peer_settings.set(settings.clone()).unwrap();
            encoder.apply_settings(settings.clone()).await;

            let mut frame = settings_frame
                .into_next_frame()
                .await
                .ok_or(H3CriticalStreamClosed::Control)??;

            loop {
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
                    frame = frame
                        .into_next_frame()
                        .await
                        .ok_or(H3CriticalStreamClosed::Control)??;
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
            Ok::<_, Error>(())
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
                        StreamError::Reset { .. } => H3CriticalStreamClosed::Control.into(),
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
        let settings_frame = BufList::new().encode(&state.local_settings).await.unwrap();
        match control_stream.send(settings_frame).await {
            Ok(()) => {}
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

    pub async fn open(
        &self,
    ) -> Result<
        (
            MessageWriter<C>,
            impl Future<Output = Result<MessageReader<C>, StreamError>>,
        ),
        StreamError,
    > {
        let (reader, writer) = self.state.open_bi().await?;
        let writer = MessageWriter::new(
            self.state.clone(),
            self.qpack_encoder.clone(),
            SinkWriter::new(Box::pin(writer)),
        );
        let reader = MessageReader::new(
            self.state.clone(),
            self.qpack_decoder.clone(),
            StreamReader::new(Box::pin(reader)),
        );
        Ok((writer, reader))
    }

    pub async fn accept(&self) -> Result<(MessageWriter<C>, MessageReader<C>), StreamError> {
        let (reader, writer) = self.state.accept_bi().await?;
        let writer = MessageWriter::new(
            self.state.clone(),
            self.qpack_encoder.clone(),
            SinkWriter::new(Box::pin(writer)),
        );
        let reader = MessageReader::new(
            self.state.clone(),
            self.qpack_decoder.clone(),
            StreamReader::new(Box::pin(reader)),
        )
        .await?;
        Ok((writer, reader))
    }

    pub async fn peer_settings(&self) -> Result<Settings, ConnectionError> {
        self.state.peer_settings().await
    }

    pub async fn max_received_stream_id(&self) -> Result<VarInt, ConnectionError> {
        self.state.max_received_stream_id().await
    }

    pub async fn peer_goaway(&self) -> Result<Goaway, ConnectionError> {
        self.state.peer_goaway().await
    }

    pub async fn goaway(&self, goaway: Goaway) -> Result<(), StreamError> {
        let mut control_stream = self.control_stream.lock().await;
        match control_stream
            .send(BufList::new().encode(goaway).await.unwrap())
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => Err(self.state.handle_error(error).await),
        }
    }

    pub fn close(&self, error: &(impl HasErrorCode + ?Sized)) {
        self.state.close(error);
    }
}

impl<C: QuicConnect + Unpin> Drop for Connection<C> {
    fn drop(&mut self) {
        self.close(&Code::H3_NO_ERROR);
    }
}
