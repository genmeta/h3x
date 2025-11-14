use std::{
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex, MutexGuard as SyncMutexGuard},
};

use futures::{FutureExt, channel::oneshot};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    codec::{
        BufSinkWriter, BufStreamReader,
        error::{DecodeStreamError, EncodeStreamError},
        util::{DecodeFrom, EncodeInto, decoder, encoder},
    },
    error::{
        ApplicationError, Code, ConnectionError, H3CriticalStreamClosed, H3FrameUnexpected,
        StreamError,
    },
    frame::Frame,
    message::{MessageReader, MessageWriter},
    qpack::{
        BoxInstructionSink, BoxInstructionStream,
        decoder::Decoder,
        encoder::Encoder,
        instruction::{DecoderInstruction, EncoderInstruction},
        settings::Settings,
    },
    quic::{QuicConnect, StopSendingExt},
    set_once::{self, SetOnce},
    stream::{H3StreamCreationError, TryFutureStream, UnidirectionalStream},
};

pub struct State<C> {
    quic_connection: SyncMutex<C>,

    error: Arc<SetOnce<ConnectionError>>,
    local_settings: Settings,
    remote_settings: Arc<SetOnce<Settings>>,
}

impl<C: QuicConnect + Unpin> State<C> {
    fn new(quic: C, local_settings: Settings) -> Self {
        Self {
            quic_connection: SyncMutex::new(quic),
            error: Arc::new(SetOnce::new()),
            local_settings,
            remote_settings: Arc::new(SetOnce::new()),
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

    pub fn close(&self, error: ApplicationError) {
        if self
            .error
            .set_with(|| ConnectionError::from(error.clone()))
            .is_err()
        {
            return;
        }
        Pin::new(self.quic_connection().deref_mut()).close(error.code, error.reason)
    }

    pub fn handle_encode_stream_error(&self, error: EncodeStreamError) {
        match error {
            EncodeStreamError::Stream { source } => match source {
                StreamError::Connection { source } => _ = self.error.set(source),
                StreamError::Reset { .. } => {
                    unreachable!("Reset should be converted before this point")
                }
            },
            EncodeStreamError::Encode { .. } => {
                unreachable!("Encode error should be converted before this point")
            }
            EncodeStreamError::Code { source } => self.close(ApplicationError::from(source)),
        }
    }

    pub fn handle_decode_stream_error(&self, error: DecodeStreamError) {
        match error {
            DecodeStreamError::Stream { source } => match source {
                StreamError::Connection { source } => _ = self.error.set(source),
                StreamError::Reset { .. } => {
                    unreachable!("Reset should be converted before this point")
                }
            },
            DecodeStreamError::Decode { .. } => {
                unreachable!("Decode error should be converted before this point")
            }
            DecodeStreamError::Code { source } => self.close(ApplicationError::from(source)),
        }
    }

    fn local_settings(&self) -> &Settings {
        &self.local_settings
    }

    fn remote_settings(&self) -> set_once::Get<Settings> {
        self.remote_settings.get()
    }

    pub fn error(&self) -> set_once::Get<ConnectionError> {
        self.error.get()
    }
}

pub type BoxStreamWriter<C> = BufSinkWriter<Pin<Box<<C as QuicConnect>::StreamWriter>>>;
pub type BoxStreamReader<C> = BufStreamReader<Pin<Box<<C as QuicConnect>::StreamReader>>>;

pub type QPackEncoder = Encoder<
    BoxInstructionSink<'static, EncoderInstruction>,
    BoxInstructionStream<'static, DecoderInstruction>,
>;

pub type QPackDecoder = Decoder<
    BoxInstructionSink<'static, DecoderInstruction>,
    BoxInstructionStream<'static, EncoderInstruction>,
>;

pub struct Connection<C: QuicConnect + Unpin> {
    state: Arc<State<C>>,
    qpack_encoder: Arc<QPackEncoder>,
    qpack_decoder: Arc<QPackDecoder>,
    control_stream: AsyncMutex<UnidirectionalStream<BoxStreamWriter<C>>>,
    task: AbortOnDropHandle<()>,
}

// #[bon::bon]
impl<C> Connection<C>
where
    C: QuicConnect + Unpin + Send + 'static,
    C::StreamReader: Send + Sync + 'static,
    C::StreamWriter: Send + 'static,
{
    // #[builder]
    pub async fn new(
        // #[builder(default)]
        settings: Settings,
        quic: C,
    ) -> Result<Self, ConnectionError> {
        let state = Arc::new(State::new(quic, settings));

        let (qpack_encoder_inst_receiver_tx, qpack_encoder_inst_receiver_rx) = oneshot::channel();
        let (qpack_decoder_inst_receiver_tx, qpack_decoder_inst_receiver_rx) = oneshot::channel();
        let (control_stream_tx, control_stream_rx) = oneshot::channel();

        let qpack_encoder = {
            // TODO: 所有FutureStream都组合一个错误Sink/Stream，使连接错误后能够打来流
            // lazily open QPACK encoder stream. if the dynamic table is never used, the stream is never opened.
            let conn_state = state.clone();
            let qpack_encoder_inst_sender = Box::pin(TryFutureStream::from(Box::pin(async move {
                // open QPACK encoder stream
                let uni_stream = Box::pin(BufSinkWriter::new(conn_state.open_uni().await?));
                // send encoder stream type
                let encoder_stream =
                    UnidirectionalStream::new_qpack_encoder_stream(uni_stream).await?;
                // turn into EncoderInstruction sink
                Ok::<_, EncodeStreamError>(encoder::<EncoderInstruction, _>(encoder_stream))
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
                let uni_stream = Box::pin(BufSinkWriter::new(conn_state.open_uni().await?));
                // send encoder stream type
                let decoder_stream =
                    UnidirectionalStream::new_qpack_decoder_stream(uni_stream).await?;
                // turn into DecoderInstruction sink
                Ok::<_, EncodeStreamError>(encoder(decoder_stream))
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

        let apply_remote_settings = {
            let qpack_encoder = qpack_encoder.clone();
            let remote_settings = state.remote_settings.get();
            async move { qpack_encoder.apply_settings(remote_settings.await).await }
        };
        let apply_remote_settings =
            AbortOnDropHandle::new(tokio::spawn(apply_remote_settings.in_current_span()));

        let conn_state = state.clone();
        let accept_uni = async move {
            let mut qpack_encoder_inst_receiver_tx = Some(qpack_encoder_inst_receiver_tx);
            let mut qpack_decoder_inst_receiver_tx = Some(qpack_decoder_inst_receiver_tx);
            let mut control_stream_tx = Some(control_stream_tx);
            loop {
                let uni_stream = conn_state.accept_uni().await?;
                let uni_stream = BufStreamReader::new(Box::pin(uni_stream));
                if let Ok(mut uni_stream) = UnidirectionalStream::decode_from(uni_stream).await {
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
                        _ = tx.send(decoder::<EncoderInstruction, _>(uni_stream))
                    } else if uni_stream.is_qpack_decoder_stream() {
                        let tx = qpack_decoder_inst_receiver_tx
                            .take()
                            .ok_or(H3StreamCreationError::DuplicateQpackDecoderStream)?;
                        _ = tx.send(decoder::<DecoderInstruction, _>(uni_stream))
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
            Ok::<_, DecodeStreamError>(())
        };
        let accept_uni_task = AbortOnDropHandle::new(tokio::spawn(accept_uni.in_current_span()));

        let conn_state = state.clone();
        let handle_control = async move {
            let control_stream = tokio::select! {
                Ok(control_stream) = control_stream_rx => control_stream.into_inner(),
                _error = conn_state.error() => return Ok::<_, DecodeStreamError>(()),
            };

            // SETTINGS frames always apply to an entire HTTP/3 connection, never a
            // single stream. A SETTINGS frame MUST be sent as the first frame of
            // each control stream (see Section 6.2.1) by each peer, and it MUST NOT
            // be sent subsequently. If an endpoint receives a second SETTINGS frame
            // on the control stream, the endpoint MUST respond with a connection
            // error of type H3_FRAME_UNEXPECTED.
            //
            // https://datatracker.ietf.org/doc/html/rfc9114#frame-settings
            let mut settings_frame = Frame::decode_from(control_stream).await?;
            if settings_frame.r#type() != Frame::SETTINGS_FRAME_TYPE {
                return Err(Code::H3_MISSING_SETTINGS.into());
            }
            let settings = Settings::decode_from(&mut settings_frame).await?;
            tracing::debug!("Remote settings applied: {:?}", settings);
            conn_state.remote_settings.set(settings).unwrap();

            let mut next_frame = settings_frame
                .into_next_frame()
                .await
                .ok_or(H3CriticalStreamClosed::Control)??;

            loop {
                // https://datatracker.ietf.org/doc/html/rfc9114#frame-settings
                if next_frame.r#type() == Frame::SETTINGS_FRAME_TYPE {
                    return Err(H3FrameUnexpected::DuplicateSettings.into());
                }
                if next_frame.r#type() == Frame::GOAWAY_FRAME_TYPE {
                    todo!()
                }
                // https://datatracker.ietf.org/doc/html/rfc9114#name-reserved-frame-types
                if next_frame.is_reversed_frame() {
                    next_frame = next_frame
                        .into_next_frame()
                        .await
                        .ok_or(H3CriticalStreamClosed::Control)??;
                }
            }
        };
        let handle_control = async move {
            handle_control.await.map_err(|error| {
                error
                    .map_stream_reset(|_| H3CriticalStreamClosed::Control.into())
                    .map_incomplete(|| H3CriticalStreamClosed::Control.into())
            })
        };
        let handle_control_stream =
            AbortOnDropHandle::new(tokio::spawn(handle_control.in_current_span()));

        let encoder = qpack_encoder.clone();
        let reveice_decoder_instructions = async move {
            loop {
                encoder.receive_instruction().await?
            }

            #[allow(unreachable_code)]
            Ok::<_, DecodeStreamError>(())
        };
        let receive_decoder_instructions = async move {
            reveice_decoder_instructions.await.map_err(|error| {
                error.map_stream_reset(|_| H3CriticalStreamClosed::QPackDecoder.into())
            })
        };
        let receive_decoder_instructions =
            AbortOnDropHandle::new(tokio::spawn(receive_decoder_instructions.in_current_span()));

        let conn_state = state.clone();
        let task = async move {
            let _move = apply_remote_settings;
            match tokio::try_join!(
                accept_uni_task.map(Result::unwrap),
                handle_control_stream.map(Result::unwrap),
                receive_decoder_instructions.map(Result::unwrap)
            ) {
                Ok(_) => unreachable!(),
                Err(error) => match error {
                    DecodeStreamError::Stream { source } => match source {
                        StreamError::Connection { source } => match source {
                            ConnectionError::Transport { .. } => _ = conn_state.error.set(source),
                            ConnectionError::Application { source } => conn_state.close(source),
                        },
                        StreamError::Reset { .. } => {
                            unreachable!("stream reset should already be converted")
                        }
                    },
                    DecodeStreamError::Decode { .. } => {
                        unreachable!("decode error should already be converted")
                    }
                    DecodeStreamError::Code { source } => {
                        conn_state.close(ApplicationError::from(source))
                    }
                },
            }
        };
        let task = AbortOnDropHandle::new(tokio::spawn(task.in_current_span()));

        // open control stream
        let uni_stream = BufSinkWriter::new(Box::pin(state.open_uni().await?));
        // send control stream type
        let mut control_stream = match UnidirectionalStream::new_control_stream(uni_stream).await {
            Ok(control_stream) => control_stream,
            Err(error) => {
                state.handle_encode_stream_error(error);
                return Err(state.error().await);
            }
        };
        let settings = state.local_settings.clone();
        match settings.encode_into(&mut control_stream).await {
            Ok(()) => {}
            Err(error) => {
                state.handle_encode_stream_error(error);
                return Err(state.error().await);
            }
        }

        Ok(Self {
            state,
            qpack_encoder,
            qpack_decoder,
            control_stream: AsyncMutex::new(control_stream),
            task,
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
        Ok((
            MessageWriter::new(
                self.state.clone(),
                self.qpack_encoder.clone(),
                BufSinkWriter::new(Box::pin(writer)),
            ),
            MessageReader::new(
                self.state.clone(),
                self.qpack_decoder.clone(),
                BufStreamReader::new(Box::pin(reader)),
            ),
        ))
    }

    pub async fn accept(&self) -> Result<(MessageWriter<C>, MessageReader<C>), StreamError> {
        let (reader, writer) = self.state.accept_bi().await?;
        Ok((
            MessageWriter::new(
                self.state.clone(),
                self.qpack_encoder.clone(),
                BufSinkWriter::new(Box::pin(writer)),
            ),
            MessageReader::new(
                self.state.clone(),
                self.qpack_decoder.clone(),
                BufStreamReader::new(Box::pin(reader)),
            )
            .await?,
        ))
    }

    pub async fn remote_settings(&self) -> Result<Settings, ConnectionError> {
        tokio::select! {
            settings = self.state.remote_settings() => Ok(settings),
            error = self.state.error() => Err(error),
        }
    }
}

impl<C: QuicConnect + Unpin> Drop for Connection<C> {
    fn drop(&mut self) {
        self.state.close(ApplicationError::from(Code::H3_NO_ERROR));
    }
}
