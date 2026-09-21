use std::{
    future::poll_fn,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Poll, ready},
};

use qrecovery::{recv::StopSending, send::CancelStream};

use super::stream::{H3ReadStream, H3WriteStream, bi::ArcBiStreams};
use crate::{
    Error, ErrorCode, Result, Transport,
    frame::{self, StreamType},
    qpack::{ArcQpack, MAX_PENDING_INSTRUCTION, instruction_send_error},
};

mod control;
mod settings;
pub use settings::Settings;

use crate::ErrorCode::NoError;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Tasks run until the transport terminates.
/// `goaway()` can drain requests and close the transport.
pub struct H3Connection<T: Transport> {
    pub(crate) transport: Arc<T>,
    qpack: ArcQpack,
    control: Arc<control::Control<T::StreamWriter>>,
    bi_streams: ArcBiStreams<T::StreamReader, T::StreamWriter>,
}

impl<T: Transport> H3Connection<T> {
    /// Start the control, SETTINGS, and connection tasks.
    /// On failure or cancellation, transport cleanup follows its own drop semantics.
    pub fn new(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = ArcBiStreams::new(transport.role());

        let qpack = ArcQpack::new(&settings)?;
        let (encoder_tx, encoder_rx) = tokio::sync::mpsc::channel(MAX_PENDING_INSTRUCTION);
        let (decoder_tx, decoder_rx) = tokio::sync::mpsc::channel(MAX_PENDING_INSTRUCTION);
        qpack.with_state(|state| {
            state.encoder.on_instruction(move |batch| {
                encoder_tx.try_send(batch).map_err(instruction_send_error)
            });
            state.decoder.on_instruction(move |batch| {
                decoder_tx.try_send(batch).map_err(instruction_send_error)
            });
            Ok(())
        })?;
        tokio::spawn({
            let qpack = qpack.clone();
            let transport = transport.clone();
            async move { qpack.sync_encoder_with(transport, encoder_rx).await }
        });
        tokio::spawn({
            let qpack = qpack.clone();
            let transport = transport.clone();
            async move { qpack.sync_decoder_with(transport, decoder_rx).await }
        });

        let control = Arc::new(control::Control::new(settings));
        tokio::spawn({
            let control = control.clone();
            let qpack = qpack.clone();
            let transport = transport.clone();
            async move { control.open_uni_and_send_setting(transport, qpack).await }
        });
        let connection = Self {
            transport,
            qpack,
            control,
            bi_streams: bi,
        };
        tokio::spawn(connection.clone().accept_and_process_uni());
        Ok(connection)
    }

    /// Compression state shared by messages on this connection.
    pub fn qpack(&self) -> &ArcQpack {
        &self.qpack
    }

    /// Open a bidirectional stream, returning (send, receive).
    /// Admission stops on peer GOAWAY or connection close, not local GOAWAY.
    pub async fn open_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::StreamWriter>,
        H3ReadStream<T::StreamReader>,
    )> {
        let mut opening = pin!(self.transport.open_bi());
        // Pending releases the lock; Ready registers the stream before GOAWAY can run.
        poll_fn(|cx| {
            let mut guard = self.bi_streams.lock().unwrap();
            let (id, (recv, send)) = ready!(opening.as_mut().poll(cx))?.ok_or_else(|| {
                ErrorCode::StreamCreationError
                    .reason("transport cannot open a bidirectional stream")
            })?;
            guard.remote_no_goway()?;
            let (read, write) =
                self.bi_streams
                    .insert(&mut guard, id, recv, send, self.qpack.clone());
            Poll::Ready(Ok((write, read)))
        })
        .await
    }

    /// Exchange GOAWAY and wait for admitted requests before closing the transport.
    /// Admission freezes immediately; the returned future writes and flushes GOAWAY,
    /// then waits for the peer and admitted requests before closing the transport.
    /// Dropping the future leaves admission frozen without completing shutdown.
    pub fn goaway(self) -> impl Future<Output = Result<()>> + Send {
        let qpack = self.qpack.clone();
        let local_goaway = self.bi_streams.lock().unwrap().goaway(&qpack);
        async move {
            tokio::select! {
                biased;
                error = self.qpack.failed() => return Err(error),
                result = async {
                    let local_goaway = local_goaway?;
                    let remote_goaway = self.bi_streams.lock().unwrap().recv_goway();
                    self.control.write_goaway(local_goaway).await?;
                    remote_goaway.await.map_err(|error| {
                        ErrorCode::InternalError.reason(format!("GOAWAY wait cancelled: {error}"))
                    })?;
                    let drained = self.bi_streams.drain();
                    drained.await;
                    Ok::<_, crate::Error>(())
                } => result?,
            }
            let result = self.transport.close(String::new(), NoError.as_u64());
            self.control.close().await;
            result
        }
    }

    pub(crate) fn local_goaway(&self) -> impl Future<Output = ()> + Send + use<T> {
        let notification = self.bi_streams.lock().unwrap().local_goaway();
        async move {
            notification.await;
        }
    }
}

impl<T: Transport> H3Connection<T> {
    /// Accept and register one peer bidirectional stream, returning (write, read).
    /// Admission stops on local GOAWAY or connection close, not peer GOAWAY.
    /// The application drives acceptance; no background request queue is maintained.
    pub async fn accept_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::StreamWriter>,
        H3ReadStream<T::StreamReader>,
    )> {
        let mut accepting = pin!(self.transport.accept_bi());
        poll_fn(|cx| {
            let mut guard = self.bi_streams.lock().unwrap();
            guard.local_not_goway()?;
            let (id, (mut recv, mut send)) = ready!(accepting.as_mut().poll(cx))?;
            let stream_id = qbase::varint::VarInt::try_from(id)
                .map(qbase::sid::StreamId::from)
                .map_err(|error| {
                    ErrorCode::IdError.reason(format!("invalid stream or push identifier: {error}"))
                });
            if let Err(error) = stream_id.and_then(|id| guard.accept(id)) {
                recv.stop(ErrorCode::RequestRejected.as_u64());
                send.cancel(ErrorCode::RequestRejected.as_u64());
                return Poll::Ready(Err(error));
            }
            let (read, write) =
                self.bi_streams
                    .insert(&mut guard, id, recv, send, self.qpack.clone());
            Poll::Ready(Ok((write, read)))
        })
        .await
    }
}

impl<T: Transport> H3Connection<T> {
    async fn accept_and_process_uni(self) {
        let peer_critical_streams = Arc::new(AtomicU8::new(0));
        let error = loop {
            tokio::select! {
                biased;
                error = self.qpack.failed() => break error,
                accepted = self.transport.accept_uni() => match accepted {
                    Ok((_, recv)) => {
                        tokio::spawn(self.clone().receive_uni(recv, peer_critical_streams.clone()));
                    }
                    Err(error) => break error,
                },
            }
        };
        let error = self.qpack.on_connection_error(error);
        let _ = self
            .transport
            .close(error.reason.clone(), error.code.as_u64());
        self.control.close().await;
        self.on_terminated(error);
    }

    async fn receive_uni(self, mut recv: T::StreamReader, peer_critical_streams: Arc<AtomicU8>) {
        let result = async {
            let Some(stream_type) = frame::be_stream_type(&mut recv).await? else {
                return Ok(());
            };
            if matches!(
                stream_type,
                StreamType::Control | StreamType::QpackEncoder | StreamType::QpackDecoder
            ) {
                // Claim before reading any payload. Receive tasks share this atomic
                // bitset for the connection's lifetime; claims are never released.
                let bit = 1 << (stream_type as u8);
                if peer_critical_streams.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
                    return Err(ErrorCode::StreamCreationError
                        .reason(format!("duplicate peer {stream_type:?} stream")));
                }
            }
            match stream_type {
                StreamType::Control => {
                    self.control
                        .receive_control(
                            &mut recv,
                            self.transport.role(),
                            |settings| {
                                let (peer, max_fields) = crate::qpack::limits(settings);
                                self.qpack.configure(peer, max_fields)
                            },
                            |id| {
                                self.bi_streams
                                    .lock()
                                    .unwrap()
                                    .on_goaway(id, self.qpack.clone())
                            },
                        )
                        .await
                }
                StreamType::Push => {
                    Err(ErrorCode::IdError.reason("invalid stream or push identifier"))
                }
                StreamType::QpackEncoder => self.qpack.receive_encoder(&mut recv).await,
                StreamType::QpackDecoder => self.qpack.receive_decoder(&mut recv).await,
            }
        };
        let result = tokio::select! {
            biased;
            error = self.qpack.failed() => Err(error),
            result = result => result,
        };
        // Retain the half until failure handling completes, including transport close.
        if let Err(error) = result {
            let error = self.qpack.on_connection_error(error);
            let _ = self
                .transport
                .close(error.reason.clone(), error.code.as_u64());
        }
    }

    /// Apply the failure observed by stream I/O and wake H3-level waiters.
    fn on_terminated(&self, error: Error) {
        let error = self.qpack.on_connection_error(error);
        self.bi_streams.lock().unwrap().close(error);
    }
}

impl<T: Transport> Clone for H3Connection<T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            qpack: self.qpack.clone(),
            control: self.control.clone(),
            bi_streams: self.bi_streams.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use qrecovery::{recv::StopSending, send::CancelStream};
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

    use super::*;

    #[derive(Default)]
    struct Io {
        bytes: VecDeque<u8>,
    }

    impl Io {
        fn from(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.iter().copied().collect(),
            }
        }
    }

    impl AsyncRead for Io {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            while buf.remaining() > 0 {
                let Some(byte) = self.bytes.pop_front() else {
                    break;
                };
                buf.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Io {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl StopSending for Io {
        fn stop(&mut self, _: u64) {}
    }

    impl CancelStream for Io {
        fn cancel(&mut self, _: u64) {}
    }

    impl crate::TransportError for Io {
        fn map_error(error: io::Error) -> crate::Error {
            crate::Error::from_stream_io(error)
        }
    }

    type BiStream = (u64, (Io, Io));

    struct TestTransport {
        open: Mutex<Option<Option<BiStream>>>,
        accept: Mutex<Option<Result<BiStream>>>,
        closes: AtomicUsize,
    }

    impl TestTransport {
        fn new(open: Option<BiStream>, accept: Result<BiStream>) -> Self {
            Self {
                open: Mutex::new(Some(open)),
                accept: Mutex::new(Some(accept)),
                closes: AtomicUsize::new(0),
            }
        }
    }

    impl Transport for TestTransport {
        type StreamReader = Io;
        type StreamWriter = Io;

        fn role(&self) -> crate::Role {
            crate::Role::Client
        }
        async fn open_bi(&self) -> Result<Option<(u64, (Io, Io))>> {
            Ok(self.open.lock().unwrap().take().unwrap())
        }
        async fn accept_bi(&self) -> Result<(u64, (Io, Io))> {
            self.accept.lock().unwrap().take().unwrap()
        }
        async fn open_uni(&self) -> Result<Option<(u64, Io)>> {
            Ok(Some((2, Io::default())))
        }
        async fn accept_uni(&self) -> Result<(u64, Io)> {
            Err(ErrorCode::InternalError.reason("unused"))
        }
        fn close(&self, _: String, _: u64) -> Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn connection(transport: TestTransport) -> H3Connection<TestTransport> {
        let settings = Arc::new(Settings::default());
        H3Connection {
            transport: Arc::new(transport),
            qpack: ArcQpack::new(&settings).unwrap(),
            control: Arc::new(control::Control::new(settings)),
            bi_streams: ArcBiStreams::new(crate::Role::Client),
        }
    }

    #[tokio::test]
    async fn bidirectional_admission_reports_transport_and_identifier_errors() {
        let error = connection(TestTransport::new(
            None,
            Err(ErrorCode::InternalError.reason("accept failed")),
        ))
        .open_bi()
        .await
        .err()
        .expect("opening an unavailable stream must fail");
        assert_eq!(error.code, ErrorCode::StreamCreationError);

        let invalid = (1_u64 << 62, (Io::default(), Io::default()));
        let invalid_connection = connection(TestTransport::new(None, Ok(invalid)));
        let error = invalid_connection
            .accept_bi()
            .await
            .err()
            .expect("accepting an invalid stream identifier must fail");
        assert_eq!(error.code, ErrorCode::IdError);

        let opened = connection(TestTransport::new(
            Some((0, (Io::default(), Io::default()))),
            Err(ErrorCode::InternalError.reason("unused")),
        ));
        assert!(opened.open_bi().await.is_ok());
        let accepted = connection(TestTransport::new(
            None,
            Ok((1, (Io::default(), Io::default()))),
        ));
        assert!(accepted.accept_bi().await.is_ok());
    }

    #[tokio::test]
    async fn unidirectional_stream_types_and_duplicates_fail_the_connection() {
        for bytes in [
            &[][..],
            &[1][..],
            &[2][..],
            &[3][..],
            &[0][..],
            &[0, 4, 0, 7, 1, 0][..],
        ] {
            let connection = connection(TestTransport::new(
                None,
                Err(ErrorCode::InternalError.reason("unused")),
            ));
            connection
                .clone()
                .receive_uni(Io::from(bytes), Arc::new(AtomicU8::new(0)))
                .await;
            if !bytes.is_empty() {
                assert!(connection.qpack().error().is_some());
            }
        }

        let connection = connection(TestTransport::new(
            None,
            Err(ErrorCode::InternalError.reason("unused")),
        ));
        connection
            .clone()
            .receive_uni(Io::from(&[0]), Arc::new(AtomicU8::new(1)))
            .await;
        assert_eq!(
            connection.qpack().error().unwrap().code,
            ErrorCode::StreamCreationError
        );
    }

    #[tokio::test]
    async fn goaway_notifies_local_waiters_and_closes_after_peer_goaway() {
        let connection = connection(TestTransport::new(
            None,
            Err(ErrorCode::InternalError.reason("unused")),
        ));
        let local = connection.local_goaway();
        let qpack = connection.qpack.clone();
        connection
            .bi_streams
            .lock()
            .unwrap()
            .on_goaway(
                qbase::sid::StreamId::new(crate::Role::Client, qbase::sid::Dir::Bi, 0),
                qpack.clone(),
            )
            .unwrap();
        let transport = connection.transport.clone();
        let control = connection.control.clone();
        let control_transport = transport.clone();
        let control_qpack = qpack.clone();
        control
            .open_uni_and_send_setting(control_transport, control_qpack)
            .await
            .unwrap();
        let shutdown = connection.goaway();
        local.await;
        assert_eq!(transport.closes.load(Ordering::SeqCst), 0);
        shutdown.await.unwrap();
        assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn goaway_before_local_settings_returns_error() {
        let connection = connection(TestTransport::new(
            None,
            Err(ErrorCode::InternalError.reason("unused")),
        ));
        let transport = connection.transport.clone();
        let error = connection.goaway().await.unwrap_err();
        assert_eq!(error.reason, "local SETTINGS have not been sent");
        assert_eq!(transport.closes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn constructor_starts_critical_stream_tasks_and_io_supports_writes() {
        let probe = TestTransport::new(None, Err(ErrorCode::InternalError.reason("unused")));
        assert_eq!(
            probe.accept_uni().await.err().unwrap().code,
            ErrorCode::InternalError
        );
        let connection = H3Connection::new(
            TestTransport::new(None, Err(ErrorCode::InternalError.reason("unused"))),
            Settings::default(),
        )
        .unwrap();
        tokio::task::yield_now().await;
        assert!(connection.qpack().error().is_some());

        let mut io = Io::default();
        io.write_all(b"test").await.unwrap();
        io.flush().await.unwrap();
        io.shutdown().await.unwrap();
    }
}
