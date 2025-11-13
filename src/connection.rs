use std::{
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex, MutexGuard as SyncMutexGuard, atomic::AtomicBool},
};

use bytes::{Buf, Bytes};
use futures::{
    FutureExt, Sink, StreamExt, TryStreamExt,
    channel::oneshot,
    stream::{self, BoxStream},
};
use gm_quic::qbase::packet::header;
use http::{Request, Response, response};
use http_body_util::{
    BodyExt, StreamBody,
    combinators::{BoxBody, UnsyncBoxBody},
};
use tokio::{io::AsyncWriteExt, sync::Mutex as AsyncMutex};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    codec::{
        BufSinkWriter, BufStreamReader, FixedLengthReader,
        error::{DecodeStreamError, EncodeStreamError},
        util::{DecodeFrom, EncodeInto, decoder, encoder},
    },
    error::{
        ApplicationError, Code, ConnectionError, ErrorWithCode, H3CriticalStreamClosed,
        H3FrameUnexpected, StreamError,
    },
    frame::Frame,
    qpack::{
        BoxInstructionSink, BoxInstructionStream,
        decoder::Decoder,
        encoder::Encoder,
        field_section::FieldSection,
        instruction::{DecoderInstruction, EncoderInstruction},
        settings::Settings,
        strategy::{HuffmanAlways, StaticEncoder},
    },
    quic::{CancelStreamExt, QuicConnect, StopSendingExt},
    set_once::{self, SetOnce},
    stream::{H3StreamCreationError, TryFutureStream, UnidirectionalStream},
    varint::err,
};

pub struct State<C> {
    quic_connection: SyncMutex<C>,
    received_control_stream: AtomicBool,
    received_settings: AtomicBool,

    error: Arc<SetOnce<ConnectionError>>,
    local_settings: Settings,
    remote_settings: Arc<SetOnce<Settings>>,
}

impl<C: QuicConnect + Unpin> State<C> {
    fn new(quic: C, local_settings: Settings) -> Self {
        Self {
            quic_connection: SyncMutex::new(quic),
            received_control_stream: AtomicBool::new(false),
            received_settings: AtomicBool::new(false),
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

    fn error(&self) -> set_once::Get<ConnectionError> {
        self.error.get()
    }
}

type BoxUnidirectionalStream<C> =
    UnidirectionalStream<BufSinkWriter<Pin<Box<<C as QuicConnect>::StreamWriter>>>>;

pub struct Connection<C: QuicConnect + Unpin> {
    state: Arc<State<C>>,
    qpack_encoder: Arc<
        Encoder<
            BoxInstructionSink<'static, EncoderInstruction>,
            BoxInstructionStream<'static, DecoderInstruction>,
        >,
    >,
    qpack_decoder: Arc<
        Decoder<
            BoxInstructionSink<'static, DecoderInstruction>,
            BoxInstructionStream<'static, EncoderInstruction>,
        >,
    >,
    control_stream: AsyncMutex<BoxUnidirectionalStream<C>>,
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
            while let Ok(uni_stream) = conn_state.accept_uni().await {
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
                    /* TODO: else if stream.is_push_stream() { ... } */
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

            Ok::<_, ErrorWithCode>(())
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

        let conn_state = state.clone();
        let task = async move {
            let _move = apply_remote_settings;

            let handle_accept_uni_error = async {
                let Err(error) = accept_uni_task.map(Result::unwrap).await else {
                    unreachable!()
                };
                conn_state.close(ApplicationError::from(&error));
            };

            let handle_control_stream_error = async {
                let Err(error) = handle_control_stream.map(Result::unwrap).await else {
                    unreachable!()
                };
                match error {
                    DecodeStreamError::Stream { source } => match source {
                        StreamError::Connection { source } => match source {
                            ConnectionError::Transport { .. } => _ = conn_state.error.set(source),
                            ConnectionError::Application { source } => conn_state.close(source),
                        },
                        StreamError::Reset { .. } => {
                            unreachable!("control stream reset should be converted before")
                        }
                    },
                    DecodeStreamError::Decode { source } => {
                        let error = ErrorWithCode::new(Code::H3_FRAME_ERROR, Some(source));
                        conn_state.close(ApplicationError::from(error))
                    }
                    DecodeStreamError::Code { source } => {
                        conn_state.close(ApplicationError::from(source))
                    }
                }
            };
            tokio::select! {
                _ = handle_accept_uni_error => {},
                _ = handle_control_stream_error => {},
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

    pub async fn request<T>(
        &self,
        request: Request<T>,
    ) -> Result<Response<UnsyncBoxBody<Bytes, StreamError>>, StreamError>
    where
        T: http_body::Body<Data: Buf + Send, Error: Send> + Send + 'static,
    {
        let (response_stream, request_stream) = self.state.open_bi().await?;

        let mut request_stream = BufSinkWriter::new(Box::pin(request_stream));
        let connect_state = self.state.clone();
        let qpack_encoder = self.qpack_encoder.clone();
        const ENCODE_STRATEGY: StaticEncoder<HuffmanAlways> = StaticEncoder::new(HuffmanAlways);

        let _send_request = tokio::spawn(
            async move {
                let (parts, body) = request.into_parts();
                let field_section = FieldSection::try_from(parts).unwrap();
                if let Err(EncodeStreamError::Code { source }) = qpack_encoder
                    .encode(field_section, &ENCODE_STRATEGY, &mut request_stream)
                    .await
                {
                    connect_state.close(ApplicationError::from(source));
                }
                tracing::debug!("Request header sent");

                tokio::pin!(body);

                while let Some(frame) = body.frame().await {
                    let Ok(frame) = frame else {
                        _ = request_stream.cancel(Code::H3_NO_ERROR.into_inner()).await;
                        return;
                    };

                    let frame = match frame.into_data() {
                        Ok(bytes) => {
                            tracing::info!("Sending DATA frame with {} bytes", bytes.remaining());
                            let frame = Frame::new(Frame::DATA_FRAME_TYPE, [bytes]).unwrap();
                            match frame.encode_into(&mut request_stream).await {
                                Ok(_) => continue,
                                Err(error) => {
                                    tracing::debug!(
                                        "Failed to send request data frame: {}",
                                        snafu::Report::from_error(error)
                                    );
                                    _ = request_stream
                                        .cancel(Code::H3_INTERNAL_ERROR.into_inner())
                                        .await;
                                    return;
                                }
                            }
                        }
                        Err(frame) => frame,
                    };
                    let Ok(header_map) = frame.into_trailers() else {
                        panic!("only DATA and TRAILERS frames are supported in request body")
                    };
                    let field_section = FieldSection::from(header_map);
                    if let Err(EncodeStreamError::Code { source }) = qpack_encoder
                        .encode(field_section, &ENCODE_STRATEGY, &mut request_stream)
                        .await
                    {
                        connect_state.close(ApplicationError::from(source));
                    }
                }
                tracing::debug!("Request sent, shutdowning request stream");
                _ = request_stream.shutdown().await
            }
            .in_current_span(),
        );

        let handle_decode_stream_error = async |error: DecodeStreamError| match error {
            DecodeStreamError::Stream { source } => source,
            DecodeStreamError::Decode { .. } => todo!(),
            DecodeStreamError::Code { source } => {
                self.state.close(ApplicationError::from(source));
                self.state.error().await.into()
            }
        };

        let mut frmae =
            match Frame::decode_from(BufStreamReader::new(Box::pin(response_stream))).await {
                Ok(frame) => frame,
                Err(error) => return Err(handle_decode_stream_error(error).await),
            };
        while frmae.r#type() != Frame::HEADERS_FRAME_TYPE {
            match frmae {
                frame if frame.is_reversed_frame() => {
                    frmae = match frame.into_next_frame().await.transpose() {
                        Ok(Some(frame)) => frame,
                        Ok(None) => todo!(""),
                        Err(error) => return Err(handle_decode_stream_error(error).await),
                    }
                }
                _ => {
                    // TODO: lookup correct error code
                    self.state
                        .close(ApplicationError::from(Code::H3_FRAME_UNEXPECTED));
                    return Err(self.state.error().await.into());
                }
            }
        }

        let header_section = match self.qpack_decoder.decode(&mut frmae).await {
            Ok(section) => section,
            Err(error) => return Err(handle_decode_stream_error(error).await),
        };
        tracing::debug!("Response header received");

        // TODO: https://datatracker.ietf.org/doc/html/rfc9114#section-4.1.2-3
        let response_parts = match response::Parts::try_from(header_section) {
            Ok(parts) => parts,
            Err(error) => {
                self.state
                    .close(ApplicationError::from(ErrorWithCode::from(error)));
                return Err(self.state.error().await.into());
            }
        };

        let frame = match frmae.into_next_frame().await.transpose() {
            Ok(frame) => frame,
            Err(error) => return Err(handle_decode_stream_error(error).await),
        };

        let response_body = IncomingMessage {
            connect_state: self.state.clone(),
            qpack_decoder: self.qpack_decoder.clone(),
            frame,
        };

        Ok(Response::from_parts(
            response_parts,
            response_body.into_body().boxed_unsync(),
        ))
    }

    pub async fn response<T>(
        &self,
    ) -> Result<
        (
            Request<UnsyncBoxBody<Bytes, StreamError>>,
            oneshot::Sender<Response<T>>,
        ),
        StreamError,
    >
    where
        T: http_body::Body<Data: Buf + Send, Error: Send> + Send + 'static,
    {
        let (request_stream, response_stream) = self.state.accept_bi().await?;

        let handle_decode_stream_error = async |error: DecodeStreamError| match error {
            DecodeStreamError::Stream { source } => source,
            DecodeStreamError::Decode { .. } => todo!(),
            DecodeStreamError::Code { source } => {
                self.state.close(ApplicationError::from(source));
                self.state.error().await.into()
            }
        };

        let mut frmae =
            match Frame::decode_from(BufStreamReader::new(Box::pin(request_stream))).await {
                Ok(frame) => frame,
                Err(error) => return Err(handle_decode_stream_error(error).await),
            };

        while frmae.r#type() != Frame::HEADERS_FRAME_TYPE {
            match frmae {
                frame if frame.is_reversed_frame() => {
                    frmae = match frame.into_next_frame().await.transpose() {
                        Ok(Some(frame)) => frame,
                        Ok(None) => todo!(""),
                        Err(error) => return Err(handle_decode_stream_error(error).await),
                    }
                }
                _ => {
                    // TODO: lookup correct error code
                    self.state
                        .close(ApplicationError::from(Code::H3_FRAME_UNEXPECTED));
                    return Err(self.state.error().await.into());
                }
            }
        }

        let header_section = match self.qpack_decoder.decode(&mut frmae).await {
            Ok(section) => section,
            Err(error) => return Err(handle_decode_stream_error(error).await),
        };

        tracing::debug!("Request header received");
        let request_parts = match http::request::Parts::try_from(header_section) {
            Ok(parts) => parts,
            Err(error) => {
                self.state
                    .close(ApplicationError::from(ErrorWithCode::from(error)));
                return Err(self.state.error().await.into());
            }
        };
        let frame = match frmae.into_next_frame().await.transpose() {
            Ok(frame) => frame,
            Err(error) => return Err(handle_decode_stream_error(error).await),
        };
        let request_body = IncomingMessage {
            connect_state: self.state.clone(),
            qpack_decoder: self.qpack_decoder.clone(),
            frame,
        };
        let request = Request::from_parts(request_parts, request_body.into_body().boxed_unsync());

        let connect_state = self.state.clone();
        let qpack_encoder = self.qpack_encoder.clone();
        const ENCODE_STRATEGY: StaticEncoder<HuffmanAlways> = StaticEncoder::new(HuffmanAlways);
        let (response_tx, response_rx) = oneshot::channel::<Response<T>>();
        tokio::spawn(
            async move {
                let mut response_stream = BufSinkWriter::new(Box::pin(response_stream));
                let Ok(response) = response_rx.await else {
                    _ = response_stream.cancel(Code::H3_NO_ERROR.into_inner()).await;
                    return;
                };
                tracing::debug!("Response header sent");

                let (parts, body) = response.into_parts();
                let field_section = FieldSection::try_from(parts).unwrap();
                if let Err(EncodeStreamError::Code { source }) = qpack_encoder
                    .encode(field_section, &ENCODE_STRATEGY, &mut response_stream)
                    .await
                {
                    connect_state.close(ApplicationError::from(source));
                }

                tokio::pin!(body);

                while let Some(frame) = body.frame().await {
                    let frame = match frame {
                        Ok(frame) => frame,
                        Err(_) => {
                            _ = response_stream.cancel(Code::H3_NO_ERROR.into_inner()).await;
                            return;
                        }
                    };

                    let frame = match frame.into_data() {
                        Ok(bytes) => {
                            let frame = Frame::new(Frame::DATA_FRAME_TYPE, [bytes]).unwrap();
                            match frame.encode_into(&mut response_stream).await {
                                Ok(_) => continue,
                                Err(error) => {
                                    tracing::debug!(
                                        "Failed to send response data frame: {}",
                                        snafu::Report::from_error(error)
                                    );
                                    _ = response_stream
                                        .cancel(Code::H3_INTERNAL_ERROR.into_inner())
                                        .await;
                                    return;
                                }
                            }
                        }
                        Err(frame) => frame,
                    };
                    let Ok(header_map) = frame.into_trailers() else {
                        panic!("only DATA and TRAILERS frames are supported in request body")
                    };
                    let field_section = FieldSection::from(header_map);
                    if let Err(EncodeStreamError::Code { source }) = qpack_encoder
                        .encode(field_section, &ENCODE_STRATEGY, &mut response_stream)
                        .await
                    {
                        connect_state.close(ApplicationError::from(source));
                    }
                }
                tracing::debug!("Response sent, shutting down response stream...");
                _ = response_stream.shutdown().await
            }
            .in_current_span(),
        );

        Ok((request, response_tx))
    }
}

impl<C: QuicConnect + Unpin> Drop for Connection<C> {
    fn drop(&mut self) {
        self.state.close(ApplicationError::from(Code::H3_NO_ERROR));
    }
}

pub struct IncomingMessage<C: QuicConnect> {
    connect_state: Arc<State<C>>,
    qpack_decoder: Arc<
        Decoder<
            BoxInstructionSink<'static, DecoderInstruction>,
            BoxInstructionStream<'static, EncoderInstruction>,
        >,
    >,
    frame: Option<Frame<FixedLengthReader<BufStreamReader<Pin<Box<C::StreamReader>>>>>>,
}

impl<C: QuicConnect + Unpin> IncomingMessage<C> {
    async fn handle_error(&self, error: ErrorWithCode) -> StreamError {
        self.connect_state.close(ApplicationError::from(error));
        self.connect_state.error().await.into()
    }

    async fn handle_decode_stream_error(&self, error: DecodeStreamError) -> StreamError {
        match error {
            DecodeStreamError::Stream { source } => source,
            DecodeStreamError::Decode { .. } => todo!(),
            DecodeStreamError::Code { source } => self.handle_error(source).await,
        }
    }

    pub async fn frame(&mut self) -> Option<Result<http_body::Frame<Bytes>, StreamError>> {
        loop {
            match self.frame.take()? {
                mut frame if frame.r#type() == Frame::DATA_FRAME_TYPE => {
                    match frame.try_next().await {
                        Ok(Some(bytes)) => {
                            tracing::info!(
                                "Received bytes from DATA frame with {} bytes",
                                bytes.len()
                            );
                            self.frame = Some(frame);
                            return Some(Ok(http_body::Frame::data(bytes)));
                        }
                        Ok(None) => {
                            tracing::info!("DATA frame ended, try to get next frame");
                            self.frame = match frame.into_next_frame().await.transpose() {
                                Ok(frame) => frame,
                                Err(error) => {
                                    return Some(Err(self.handle_decode_stream_error(error).await));
                                }
                            };
                        }
                        Err(error) => {
                            return Some(Err(self.handle_decode_stream_error(error).await));
                        }
                    }
                }
                mut frame if frame.r#type() == Frame::HEADERS_FRAME_TYPE => {
                    let field_section = match self.qpack_decoder.decode(&mut frame).await {
                        Ok(field_section) => field_section,
                        Err(error) => {
                            return Some(Err(self.handle_decode_stream_error(error).await));
                        }
                    };
                    match field_section.try_into_trailers() {
                        Ok(trailers) => {
                            return Some(Ok(http_body::Frame::trailers(trailers)));
                        }
                        Err(error) => {
                            return Some(Err(self.handle_error(ErrorWithCode::from(error)).await));
                        }
                    }
                }
                frame if frame.is_reversed_frame() => {
                    self.frame = match frame.into_next_frame().await.transpose() {
                        Ok(frame) => frame,
                        Err(error) => {
                            return Some(Err(self.handle_decode_stream_error(error).await));
                        }
                    };
                }
                _frame => {
                    self.connect_state
                        .close(ApplicationError::from(Code::H3_FRAME_UNEXPECTED));
                    return Some(Err(self.connect_state.error().await.into()));
                }
            }
        }
    }

    pub fn into_body(self) -> impl http_body::Body<Data = Bytes, Error = StreamError> {
        StreamBody::new(stream::unfold(self, |mut body| async move {
            body.frame().await.map(|result| (result, body))
        }))
    }
}
