//! Peer unidirectional stream admission, dispatch, and task lifetime.
use qbase::sid::{Dir, StreamId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::H3Connection;
use crate::{
    Error, ErrorCode, Result, Transport,
    protocol::{
        frame::{self, Control, Frame, StreamType, WriteControl as _, be_control},
        qpack,
    },
};

pub(super) async fn open_uni<T: Transport>(transport: &T) -> Result<T::StreamWriter> {
    transport
        .open_uni()
        .await?
        .map(|(_, send)| send)
        .ok_or_else(|| {
            ErrorCode::H3_STREAM_CREATION_ERROR.with_reason("unable to open control stream")
        })
}

fn control_error(error: std::io::Error) -> Error {
    let error = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<std::sync::Arc<std::io::Error>>())
        .map_or(&error, std::sync::Arc::as_ref);
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<Error>())
        .cloned()
        .unwrap_or_else(|| ErrorCode::H3_CLOSED_CRITICAL_STREAM.with_reason(error.to_string()))
}

impl<T: Transport> H3Connection<T> {
    pub(super) async fn send_settings(
        self,
        mut send: tokio::sync::OwnedMutexGuard<T::StreamWriter>,
    ) {
        let result = async {
            let mut bytes = vec![StreamType::Control as u8];
            bytes.put_control(&Control::Settings(Frame::new(self.settings.local.clone())?));
            send.write_all(&bytes).await.map_err(control_error)?;
            send.flush().await.map_err(control_error)
        }
        .await;
        if let Err(error) = result {
            self.fail(error);
        }
    }

    pub(super) async fn send_goaway(&self) -> Result<()> {
        let id = self.cursor.local_goaway()?;
        let mut send = self.cursor.control_stream.lock().await;
        if let super::stream_cursor::Cursor::Closed(error) =
            self.cursor.local.lock().unwrap().clone()
        {
            return Err(error);
        }
        let mut bytes = Vec::new();
        bytes.put_control(&Control::Goaway(Frame::new(frame::Goaway {
            id: id.into(),
        })?));
        send.write_all(&bytes).await.map_err(control_error)?;
        send.flush().await.map_err(control_error)
    }

    pub(super) async fn accept_and_process_uni(self) {
        let error = loop {
            tokio::select! {
                biased;
                error = self.transport.terminated() => break error,
                accepted = self.transport.accept_uni() => match accepted {
                    Ok((_, recv)) => { tokio::spawn(self.clone().receive(recv)); }
                    Err(error) => {
                        self.fail(error);
                        break self.transport.terminated().await;
                    }
                },
            }
        };
        self.on_terminated(error);
    }

    async fn receive(self, mut recv: T::StreamReader) {
        let result = async {
            let Some(stream_type) = frame::be_stream_type(&mut recv).await? else {
                return Ok(());
            };
            match stream_type {
                StreamType::Control => self.receive_control(&mut recv).await,
                StreamType::Push => {
                    Err(ErrorCode::H3_ID_ERROR.with_reason("invalid stream or push identifier"))
                }
                StreamType::QpackEncoder => self.qpack.receive_encoder(&mut recv).await,
                StreamType::QpackDecoder => self.qpack.receive_decoder(&mut recv).await,
            }
        };
        // Transport termination wakes the pending read with its I/O error.
        let result = result.await;
        // Retain the half until failure handling completes, including transport close.
        if let Err(error) = result {
            self.fail(error);
        }
    }

    /// Apply the transport terminal reason and wake all H3-level waiters.
    pub(crate) fn on_terminated(&self, error: Error) {
        let error = self.qpack.close(error);
        self.cursor.close(error.clone());
        self.bi_streams.close(error);
    }

    /// Initiate transport termination; the accept task owns local cleanup.
    pub(crate) fn fail(&self, error: Error) {
        let _ = self
            .transport
            .close(error.reason.clone(), error.code.as_u64());
    }
}

impl<T: Transport> H3Connection<T> {
    async fn receive_control(&self, recv: &mut T::StreamReader) -> Result<()> {
        let settings = match be_control(recv).await {
            Ok(Control::Settings(frame)) => frame.payload,
            Err(error) if error.code != ErrorCode::H3_FRAME_UNEXPECTED => return Err(error),
            Err(error) => {
                return Err(ErrorCode::H3_MISSING_SETTINGS.with_reason(format!(
                    "control stream did not start with SETTINGS: {error}"
                )));
            }
            _ => {
                return Err(ErrorCode::H3_MISSING_SETTINGS
                    .with_reason("control stream did not start with SETTINGS"));
            }
        };
        let (peer, max_fields) = qpack::limits(&settings);
        self.qpack.configure(peer, max_fields)?;
        *self.settings.peer.lock().unwrap() = Some(settings);

        let role = self.transport.role();
        let mut last_goaway_id = None;
        loop {
            match be_control(recv).await? {
                Control::Goaway(frame) => {
                    let id = StreamId::from(frame.payload.id);
                    if id.role() != role
                        || id.dir() != Dir::Bi
                        || last_goaway_id.is_some_and(|previous| id > previous)
                    {
                        return Err(
                            ErrorCode::H3_ID_ERROR.with_reason("invalid stream or push identifier")
                        );
                    }
                    last_goaway_id = Some(id);
                    // Freeze opens before scanning: registration uses the same lock.
                    self.cursor.receive_goaway(id);
                    for id in self.bi_streams.goaway(u64::from(id)) {
                        self.qpack.cancel(id)?;
                    }
                }
                // Server push is not supported.
                Control::MaxPushId(_) | Control::CancelPush(_) => {
                    return Err(
                        ErrorCode::H3_ID_ERROR.with_reason("invalid stream or push identifier")
                    );
                }
                Control::Unknown { length, .. } => {
                    let mut payload = (&mut *recv).take(length.into_u64());
                    tokio::io::copy(&mut payload, &mut tokio::io::sink())
                        .await
                        .map_err(|error| {
                            let error = error
                                .get_ref()
                                .and_then(|error| {
                                    error.downcast_ref::<std::sync::Arc<std::io::Error>>()
                                })
                                .map_or(&error, std::sync::Arc::as_ref);
                            error
                                .get_ref()
                                .and_then(|error| error.downcast_ref::<crate::Error>())
                                .cloned()
                                .unwrap_or_else(|| {
                                    let code = ErrorCode::H3_CLOSED_CRITICAL_STREAM;
                                    code.with_reason(error.to_string())
                                })
                        })?;
                    if payload.limit() != 0 {
                        return Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM
                            .with_reason("control stream ended while skipping an unknown frame"));
                    }
                }
                _ => {
                    return Err(ErrorCode::H3_FRAME_UNEXPECTED
                        .with_reason("frame is not allowed in this context"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        task::{Context, Waker},
        time::Duration,
    };

    use qbase::sid::{Dir, StreamId};

    use crate::{ErrorCode, Role, Transport, test_support};

    struct RecordingWriter(tokio::io::DuplexStream);
    impl tokio::io::AsyncWrite for RecordingWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, bytes)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
    impl qrecovery::send::CancelStream for RecordingWriter {
        fn cancel(&mut self, _: u64) {}
    }
    struct RecordingTransport {
        base: test_support::TestTransport,
        send: std::sync::Mutex<Option<tokio::io::DuplexStream>>,
    }
    impl Transport for RecordingTransport {
        type StreamReader = test_support::Reader;
        type StreamWriter = RecordingWriter;
        fn role(&self) -> Role {
            Role::Client
        }
        async fn open_bi(
            &self,
        ) -> crate::Result<Option<(u64, (Self::StreamReader, Self::StreamWriter))>> {
            Err(self.terminated().await)
        }
        async fn accept_bi(
            &self,
        ) -> crate::Result<(u64, (Self::StreamReader, Self::StreamWriter))> {
            Err(self.terminated().await)
        }
        async fn open_uni(&self) -> crate::Result<Option<(u64, Self::StreamWriter)>> {
            let send = self.send.lock().unwrap().take();
            if let Some(send) = send {
                return Ok(Some((2, RecordingWriter(send))));
            }
            Err(self.terminated().await)
        }
        async fn accept_uni(&self) -> crate::Result<(u64, Self::StreamReader)> {
            self.base.accept_uni().await
        }
        fn close(&self, reason: String, code: u64) -> crate::Result<()> {
            self.base.close(reason, code)
        }
        async fn terminated(&self) -> crate::Error {
            self.base.terminated().await
        }
    }

    #[tokio::test]
    async fn background_settings_precedes_immediate_goaway() {
        use crate::protocol::frame::{self, Control, StreamType};
        let (send, mut recv) = tokio::io::duplex(1024);
        let connection = crate::H3Connection::new(
            RecordingTransport {
                base: Default::default(),
                send: std::sync::Mutex::new(Some(send)),
            },
            Default::default(),
        )
        .await
        .unwrap();
        let mut goaway = Box::pin(connection.send_goaway());
        assert!(
            goaway
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        tokio::time::timeout(Duration::from_secs(1), goaway)
            .await
            .unwrap()
            .unwrap();
        use tokio::io::AsyncReadExt;
        assert_eq!(recv.read_u8().await.unwrap(), StreamType::Control as u8);
        assert!(matches!(
            frame::be_control(&mut recv).await.unwrap(),
            Control::Settings(_)
        ));
        let Control::Goaway(frame) = frame::be_control(&mut recv).await.unwrap() else {
            panic!("expected GOAWAY after SETTINGS");
        };
        assert_eq!(
            StreamId::from(frame.payload.id),
            StreamId::new(Role::Server, Dir::Bi, 0)
        );
    }

    #[tokio::test]
    async fn transport_close_releases_qpack_writers_waiting_for_instructions() {
        let connection = test_support::connection().await;
        tokio::task::yield_now().await;
        connection
            .transport
            .close(String::new(), ErrorCode::H3_NO_ERROR.as_u64())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while std::sync::Arc::strong_count(&connection.transport) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            (connection.qpack.error()).map(ErrorCode::from),
            Some(ErrorCode::H3_NO_ERROR)
        );
    }

    #[tokio::test]
    async fn local_field_limit_does_not_close_connection_but_receive_failure_does() {
        use crate::{
            client,
            protocol::{
                qpack,
                stream::{H3ReadStream, H3WriteStream},
            },
        };
        let connection = test_support::connection().await;
        connection
            .qpack
            .configure(qpack::Settings::default(), 256)
            .unwrap();
        use crate::WriteRequest;
        let request = client::Request::get("https://example.com/").unwrap();
        let oversized = client::Request::get("https://example.com/")
            .unwrap()
            .header(
                http::HeaderName::from_static("x-large"),
                http::HeaderValue::from_str(&"x".repeat(1024)).unwrap(),
            );
        assert!(matches!(
            client::write_bytes_request(
                oversized,
                H3WriteStream::new(0, test_support::Writer),
                H3ReadStream::new(0, test_support::Reader),
                connection.qpack().clone()
            ),
            Err(h3x::Error {
                code: ErrorCode::H3_EXCESSIVE_LOAD,
                ..
            })
        ));
        tokio::task::yield_now().await;
        let mut ended = Box::pin(connection.transport.terminated());
        assert!(
            ended
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert!(
            client::write_bytes_request(
                request,
                H3WriteStream::new(4, test_support::Writer),
                H3ReadStream::new(4, test_support::Reader),
                connection.qpack().clone()
            )
            .is_ok()
        );
        connection.fail(
            ErrorCode::H3_EXCESSIVE_LOAD
                .with_reason("test closes the connection during stream processing"),
        );
        tokio::task::yield_now().await;
        assert_eq!(ErrorCode::from(ended.await), ErrorCode::H3_EXCESSIVE_LOAD);
        assert_eq!(
            (connection.qpack.error()).map(ErrorCode::from),
            Some(ErrorCode::H3_EXCESSIVE_LOAD)
        );
    }

    #[tokio::test]
    async fn protocol_failure_preserves_observed_transport_reason_and_closes_streams() {
        let connection = test_support::connection().await;
        let (mut send, _recv) = connection
            .bi_streams
            .insert(0, test_support::Reader, test_support::Writer)
            .unwrap();
        connection
            .transport
            .close(String::new(), ErrorCode::H3_INTERNAL_ERROR.as_u64())
            .unwrap();
        // Let the connection observe transport termination before a later protocol failure.
        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.qpack.error().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        connection.fail(
            ErrorCode::QPACK_DECOMPRESSION_FAILED
                .with_reason("test closes the connection during stream processing"),
        );
        tokio::task::yield_now().await;
        assert_eq!(
            (connection.qpack.error()).map(ErrorCode::from),
            Some(ErrorCode::H3_INTERNAL_ERROR)
        );
        assert_eq!(
            (connection.open_bi().await.err()).map(ErrorCode::from),
            Some(ErrorCode::H3_INTERNAL_ERROR)
        );
        use tokio::io::AsyncWriteExt;
        let error = send.write_all(b"x").await.unwrap_err();
        assert_eq!(ErrorCode::from(error), ErrorCode::H3_INTERNAL_ERROR);
    }

    #[tokio::test]
    async fn goaway_waits_for_peer_before_closing() {
        let connection = test_support::connection().await;
        let mut closing = Box::pin(connection.clone().goaway());
        assert!(
            closing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        tokio::task::yield_now().await;
        let mut ended = Box::pin(connection.transport.terminated());
        assert!(
            ended
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        connection
            .cursor
            .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 0));
        tokio::task::yield_now().await;
        assert!(
            ended
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        tokio::time::timeout(Duration::from_secs(1), closing)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ErrorCode::from(
                tokio::time::timeout(Duration::from_secs(1), ended)
                    .await
                    .unwrap()
            ),
            ErrorCode::H3_NO_ERROR
        );
    }

    #[tokio::test]
    async fn goaway_waits_for_admitted_streams_after_peer_goaway() {
        let connection = test_support::connection().await;
        let (send, recv) = connection
            .bi_streams
            .insert(0, test_support::Reader, test_support::Writer)
            .unwrap();
        connection
            .cursor
            .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 1));
        connection.cursor.local_goaway().unwrap();
        tokio::task::yield_now().await;
        let mut closing = Box::pin(connection.clone().goaway());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(closing.as_mut().poll(&mut cx).is_pending());
        drop(send);
        assert!(closing.as_mut().poll(&mut cx).is_pending());
        drop(recv);
        tokio::time::timeout(Duration::from_secs(1), closing)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn transport_termination_wakes_goaway_waiting_for_peer() {
        let connection = test_support::connection().await;
        connection.send_goaway().await.unwrap();
        let mut closing = Box::pin(connection.clone().goaway());
        assert!(
            closing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let error =
            ErrorCode::H3_INTERNAL_ERROR.with_reason("transport terminated while awaiting peer");
        connection
            .transport
            .close(error.reason.clone(), error.code.as_u64())
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), closing)
                .await
                .unwrap(),
            Err(error)
        );
    }

    #[tokio::test]
    async fn goaway_reports_transport_failure() {
        let connection = test_support::connection().await;
        connection
            .transport
            .close(String::new(), ErrorCode::H3_INTERNAL_ERROR.as_u64())
            .unwrap();
        assert_eq!(
            (connection.goaway().await).map_err(ErrorCode::from),
            Err(ErrorCode::H3_INTERNAL_ERROR)
        );
    }
}

#[cfg(test)]
mod admission_tests {
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Waker},
    };

    use qbase::sid::{Dir, StreamId};
    use tokio::sync::Semaphore;

    use crate::{
        ErrorCode, H3Connection, Result, Role, Transport,
        test_support::{Reader, TestTransport, Writer},
    };

    struct GatedTransport {
        base: TestTransport,
        ready: Semaphore,
        calls: AtomicUsize,
    }

    impl Transport for GatedTransport {
        type StreamReader = Reader;
        type StreamWriter = Writer;
        fn role(&self) -> Role {
            Role::Client
        }
        async fn open_bi(&self) -> Result<Option<(u64, (Reader, Writer))>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.ready.acquire().await.unwrap().forget();
            Ok(Some((0, (Reader, Writer))))
        }
        async fn accept_bi(&self) -> Result<(u64, (Reader, Writer))> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.ready.acquire().await.unwrap().forget();
            Ok((1, (Reader, Writer)))
        }
        async fn open_uni(&self) -> Result<Option<(u64, Writer)>> {
            self.base.open_uni().await
        }
        async fn accept_uni(&self) -> Result<(u64, Reader)> {
            self.base.accept_uni().await
        }
        fn close(&self, reason: String, code: u64) -> Result<()> {
            self.base.close(reason, code)
        }
        async fn terminated(&self) -> h3x::Error {
            self.base.terminated().await
        }
    }

    async fn connection() -> H3Connection<GatedTransport> {
        H3Connection::new(
            GatedTransport {
                base: TestTransport::default(),
                ready: Semaphore::new(0),
                calls: AtomicUsize::new(0),
            },
            Default::default(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn pending_opens_cannot_register_after_goaway_or_close_even_after_drain() {
        for transition in 0..2 {
            let connection = connection().await;
            let mut opening = Box::pin(connection.open_bi());
            let mut cx = Context::from_waker(Waker::noop());
            assert!(opening.as_mut().poll(&mut cx).is_pending());
            let error = match transition {
                0 => {
                    // A large boundary still prohibits every subsequent open.
                    connection
                        .cursor
                        .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 100));
                    ErrorCode::H3_REQUEST_REJECTED
                }
                _ => {
                    connection.on_terminated(
                        ErrorCode::H3_INTERNAL_ERROR
                            .with_reason("test closes the connection during stream processing"),
                    );
                    ErrorCode::H3_INTERNAL_ERROR
                }
            };
            assert!(matches!(connection.open_bi().await, Err(e) if e.code == error));
            assert_eq!(connection.transport.calls.load(Ordering::SeqCst), 1);
            if transition == 0 {
                connection.cursor.local_goaway().unwrap();
            }
            connection
                .cursor
                .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 0));
            connection.bi_streams.drained().await;
            connection.transport.ready.add_permits(1);
            assert!(matches!(opening.await, Err(e) if e.code == error));
            assert_eq!(connection.bi_streams.len(), 0);
        }
    }

    #[tokio::test]
    async fn pending_accepts_cannot_register_after_local_goaway_or_close() {
        for closed in [false, true] {
            let connection = connection().await;
            let mut accepting = Box::pin(connection.accept_bi());
            assert!(
                accepting
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            let error = if closed {
                connection.on_terminated(
                    ErrorCode::H3_INTERNAL_ERROR
                        .with_reason("test closes the connection during stream processing"),
                );
                ErrorCode::H3_INTERNAL_ERROR
            } else {
                connection.cursor.local_goaway().unwrap();
                ErrorCode::H3_REQUEST_REJECTED
            };
            assert!(matches!(connection.accept_bi().await, Err(e) if e.code == error));
            assert_eq!(connection.transport.calls.load(Ordering::SeqCst), 1);
            connection.transport.ready.add_permits(1);
            assert!(matches!(accepting.await, Err(e) if e.code == error));
            assert_eq!(connection.bi_streams.len(), 0);
        }
    }

    #[tokio::test]
    async fn goaway_only_freezes_its_own_admission_direction() {
        for opening in [false, true] {
            let connection = connection().await;
            let mut pending = Box::pin(async {
                if opening {
                    connection.open_bi().await
                } else {
                    connection.accept_bi().await
                }
            });
            assert!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            if opening {
                connection.cursor.local_goaway().unwrap();
            } else {
                connection
                    .cursor
                    .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 100));
            }
            connection.transport.ready.add_permits(1);
            let handles = pending.await.unwrap();
            assert_eq!(connection.bi_streams.len(), 1);
            drop(handles);
            // A call started after the opposite GOAWAY is allowed too.
            connection.transport.ready.add_permits(1);
            let result = if opening {
                connection.open_bi().await
            } else {
                connection.accept_bi().await
            };
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn peer_goaway_preserves_admitted_streams_below_boundary() {
        let connection = connection().await;
        connection.transport.ready.add_permits(1);
        let (send, recv) = connection.open_bi().await.unwrap();
        let boundary = StreamId::new(Role::Client, Dir::Bi, 100);
        connection.cursor.receive_goaway(boundary);
        connection.bi_streams.goaway(u64::from(boundary));
        connection.cursor.local_goaway().unwrap();
        let mut draining = Box::pin(connection.bi_streams.drained());
        assert!(
            draining
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop((send, recv));
        assert!(
            draining
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
    }
}

#[cfg(test)]
mod qpack_writer_tests {
    use std::{
        io,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };

    use qrecovery::send::CancelStream;
    use tokio::io::AsyncWrite;

    use super::*;
    use crate::{
        Role,
        test_support::{Reader, TestTransport},
    };

    struct FailingWriter(u8);
    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if bytes.first() == Some(&self.0) {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            } else {
                Poll::Ready(Ok(bytes.len()))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl CancelStream for FailingWriter {
        fn cancel(&mut self, _: u64) {}
    }

    struct FailingTransport {
        base: TestTransport,
        stream_type: u8,
    }
    impl Transport for FailingTransport {
        type StreamReader = Reader;
        type StreamWriter = FailingWriter;
        fn role(&self) -> Role {
            Role::Client
        }
        async fn open_bi(&self) -> Result<Option<(u64, (Reader, FailingWriter))>> {
            Err(self.terminated().await)
        }
        async fn accept_bi(&self) -> Result<(u64, (Reader, FailingWriter))> {
            Err(self.terminated().await)
        }
        async fn open_uni(&self) -> Result<Option<(u64, FailingWriter)>> {
            Ok(Some((2, FailingWriter(self.stream_type))))
        }
        async fn accept_uni(&self) -> Result<(u64, Reader)> {
            Err(self.terminated().await)
        }
        fn close(&self, reason: String, code: u64) -> Result<()> {
            self.base.close(reason, code)
        }
        async fn terminated(&self) -> h3x::Error {
            self.base.terminated().await
        }
    }

    #[tokio::test]
    async fn settings_failure_closes_admission_and_active_streams() {
        let stream_type = StreamType::Control;
        let connection = H3Connection::new(
            FailingTransport {
                base: TestTransport::default(),
                stream_type: stream_type as u8,
            },
            Default::default(),
        )
        .await
        .unwrap();
        let (mut send, _recv) = connection
            .bi_streams
            .insert(0, Reader, FailingWriter(255))
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), connection.transport.terminated())
            .await
            .unwrap();
        assert_eq!(error.code, ErrorCode::H3_CLOSED_CRITICAL_STREAM);
        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.qpack.error().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(connection.qpack.error(), Some(error.clone()));
        assert_eq!(
            error.reason,
            io::Error::from(io::ErrorKind::BrokenPipe).to_string()
        );
        assert_eq!(connection.open_bi().await.err(), Some(error.clone()));
        assert_eq!(
            ErrorCode::from(send.write_all(b"x").await.unwrap_err()),
            error.code
        );
        // The connection-owned writer tasks release their connection handles.
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&connection.transport), 1);
    }
}
