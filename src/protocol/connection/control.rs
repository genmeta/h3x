//! Peer unidirectional stream admission, dispatch, and task lifetime.
use qbase::sid::{Dir, StreamId};
use tokio::io::AsyncWriteExt;

use super::H3Connection;
use crate::{
    ErrorCode, Result, Transport,
    protocol::{
        frame::{self, Control, Frame, StreamType, WriteControl as _, be_control},
        qpack,
    },
};

impl<T: Transport> H3Connection<T> {
    /// Errors while receiving a message have protocol-defined scope. Local
    /// encoding and application send errors never enter this path.
    pub(crate) async fn receive_error(&self, error: ErrorCode) {
        if !matches!(
            error,
            ErrorCode::H3_REQUEST_CANCELLED
                | ErrorCode::H3_REQUEST_REJECTED
                | ErrorCode::H3_REQUEST_INCOMPLETE
                | ErrorCode::H3_MESSAGE_ERROR
        ) {
            self.fail(error).await;
        }
    }

    pub(super) async fn sync_qpack_encoder(
        self,
        instruction_source: qpack::encoder::InstructionSource,
    ) {
        let stream = self
            .transport
            .open_uni()
            .await
            .and_then(|stream| stream.ok_or(ErrorCode::H3_STREAM_CREATION_ERROR));
        match stream {
            Ok((_, mut send)) => {
                if let Err(error) =
                    qpack::encoder::Encoder::write(instruction_source, &mut send).await
                {
                    // Retain the critical stream until connection failure is handled.
                    self.fail(error).await;
                }
            }
            Err(error) => self.fail(error).await,
        }
    }

    pub(super) async fn sync_qpack_decoder(self, feedback_source: qpack::decoder::Instructions) {
        let stream = self
            .transport
            .open_uni()
            .await
            .and_then(|stream| stream.ok_or(ErrorCode::H3_STREAM_CREATION_ERROR));
        match stream {
            Ok((_, mut send)) => {
                if let Err(error) = qpack::decoder::Decoder::write(feedback_source, &mut send).await
                {
                    // Retain the critical stream until connection failure is handled.
                    self.fail(error).await;
                }
            }
            Err(error) => self.fail(error).await,
        }
    }

    pub(super) async fn accept_and_process_uni(self) {
        loop {
            match self.transport.accept_uni().await {
                Ok((_, recv)) => {
                    tokio::spawn(self.clone().receive(recv));
                }
                Err(error) => {
                    self.close(error);
                    return;
                }
            }
        }
    }

    async fn receive(self, mut recv: T::StreamReader) {
        let result = async {
            let Some(stream_type) = frame::be_stream_type(&mut recv).await? else {
                return Ok(());
            };
            match stream_type {
                StreamType::Control => self.receive_control(&mut recv).await,
                StreamType::Push => Err(ErrorCode::H3_ID_ERROR),
                StreamType::QpackEncoder => self.qpack.receive_encoder(&mut recv).await,
                StreamType::QpackDecoder => self.qpack.receive_decoder(&mut recv).await,
            }
        };
        let result = tokio::select! {
            biased;
            error = self.transport.terminated() => {
                self.close(error);
                return;
            }
            result = result => result,
        };
        // Retain the half until failure handling completes, including transport close.
        if let Err(error) = result {
            self.fail(error).await;
        }
    }

    pub(crate) fn close(&self, error: ErrorCode) {
        let error = self.qpack.close(error);
        self.cursor.close(error);
        self.bi_streams.close(error);
    }

    pub(crate) async fn fail(&self, error: ErrorCode) {
        // Prefer an existing transport result over a new protocol error.
        tokio::select! {
            biased;
            ended = self.transport.terminated() => self.close(ended),
            _ = std::future::ready(()) => {
                let error = self.qpack.close(error);
                let _ = self.transport.close(error.to_string(), error.as_u64());
                self.cursor.close(error);
                self.bi_streams.close(error);
            },
        }
    }
}

impl<T: Transport> H3Connection<T> {
    pub(super) async fn sync_settings_and_goaway(self) {
        let mut send = match self.transport.open_uni().await {
            Ok(Some((_, send))) => send,
            Ok(None) => {
                self.fail(ErrorCode::H3_STREAM_CREATION_ERROR).await;
                return;
            }
            Err(error) => {
                self.close(error);
                return;
            }
        };
        let result = tokio::select! {
            biased;
            error = self.transport.terminated() => {
                self.close(error);
                return;
            }
            result = async {
                self.send_control(&mut send).await?;
                self.cursor.peer_goaway().await?;
                self.bi_streams.drained().await;
                self.transport
                    .close(ErrorCode::H3_NO_ERROR.to_string(), ErrorCode::H3_NO_ERROR.as_u64())
            } => result,
        };
        if let Err(error) = result {
            self.fail(error).await;
            return;
        }
        // Keep the critical stream open after GOAWAY until transport termination.
        let error = self.transport.terminated().await;
        self.close(error);
    }

    async fn send_control(&self, send: &mut T::StreamWriter) -> Result<()> {
        let mut bytes = vec![StreamType::Control as u8];
        bytes.put_control(&Control::Settings(Frame::new(self.settings.local.clone())?));
        async {
            send.write_all(&bytes).await?;
            send.flush().await
        }
        .await
        .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)?;

        let id = self.cursor.local_goaway().await?;
        bytes.clear();
        bytes.put_control(&Control::Goaway(Frame::new(frame::Goaway {
            id: id.into(),
        })?));
        async {
            send.write_all(&bytes).await?;
            send.flush().await
        }
        .await
        .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)?;
        Ok(())
    }

    async fn receive_control(&self, recv: &mut T::StreamReader) -> Result<()> {
        let settings = match be_control(recv).await {
            Ok(Control::Settings(frame)) => frame.payload,
            Err(error) if error != ErrorCode::H3_FRAME_UNEXPECTED => return Err(error),
            _ => return Err(ErrorCode::H3_MISSING_SETTINGS),
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
                        return Err(ErrorCode::H3_ID_ERROR);
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
                    return Err(ErrorCode::H3_ID_ERROR);
                }
                Control::Unknown { length, .. } => {
                    frame::skip_payload(recv, length.into_u64())
                        .await
                        .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)?;
                }
                _ => return Err(ErrorCode::H3_FRAME_UNEXPECTED),
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

    #[tokio::test]
    async fn transport_close_releases_qpack_writers_waiting_for_instructions() {
        let connection = test_support::connection();
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
        assert_eq!(connection.qpack.error(), Some(ErrorCode::H3_NO_ERROR));
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
        let connection = test_support::connection();
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
            Err(ErrorCode::H3_EXCESSIVE_LOAD)
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
        connection.receive_error(ErrorCode::H3_EXCESSIVE_LOAD).await;
        assert_eq!(ended.await, ErrorCode::H3_EXCESSIVE_LOAD);
        assert_eq!(connection.qpack.error(), Some(ErrorCode::H3_EXCESSIVE_LOAD));
    }

    #[tokio::test]
    async fn protocol_failure_preserves_existing_transport_reason_and_closes_streams() {
        let connection = test_support::connection();
        let (mut send, _recv) = connection
            .bi_streams
            .insert(0, test_support::Reader, test_support::Writer)
            .unwrap();
        connection
            .transport
            .close(String::new(), ErrorCode::H3_INTERNAL_ERROR.as_u64())
            .unwrap();
        connection.fail(ErrorCode::QPACK_DECOMPRESSION_FAILED).await;
        assert_eq!(connection.qpack.error(), Some(ErrorCode::H3_INTERNAL_ERROR));
        assert_eq!(
            connection.open_bi().await.err(),
            Some(ErrorCode::H3_INTERNAL_ERROR)
        );
        use tokio::io::AsyncWriteExt;
        let error = send.write_all(b"x").await.unwrap_err();
        assert_eq!(ErrorCode::from(error), ErrorCode::H3_INTERNAL_ERROR);
    }

    #[tokio::test]
    async fn cancelling_goaway_wait_keeps_control_drain_running() {
        let connection = test_support::connection();
        let mut closing = Box::pin(connection.clone().goaway());
        assert!(
            closing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(closing);
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
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), ended)
                .await
                .unwrap(),
            ErrorCode::H3_NO_ERROR
        );
        assert!(connection.goaway().await.is_ok());
    }

    #[tokio::test]
    async fn goaway_reports_transport_failure() {
        let connection = test_support::connection();
        connection
            .transport
            .close(String::new(), ErrorCode::H3_INTERNAL_ERROR.as_u64())
            .unwrap();
        assert_eq!(connection.goaway().await, Err(ErrorCode::H3_INTERNAL_ERROR));
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
        async fn terminated(&self) -> ErrorCode {
            self.base.terminated().await
        }
    }

    fn connection() -> H3Connection<GatedTransport> {
        H3Connection::new(
            GatedTransport {
                base: TestTransport::default(),
                ready: Semaphore::new(0),
                calls: AtomicUsize::new(0),
            },
            Default::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn pending_opens_cannot_register_after_goaway_or_close_even_after_drain() {
        for transition in 0..2 {
            let connection = connection();
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
                    connection.close(ErrorCode::H3_INTERNAL_ERROR);
                    ErrorCode::H3_INTERNAL_ERROR
                }
            };
            assert!(matches!(connection.open_bi().await, Err(e) if e == error));
            assert_eq!(connection.transport.calls.load(Ordering::SeqCst), 1);
            connection.cursor.goaway().unwrap();
            connection
                .cursor
                .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 0));
            connection.bi_streams.drained().await;
            connection.transport.ready.add_permits(1);
            assert!(matches!(opening.await, Err(e) if e == error));
            assert_eq!(connection.bi_streams.len(), 0);
        }
    }

    #[tokio::test]
    async fn pending_accepts_cannot_register_after_local_goaway_or_close() {
        for closed in [false, true] {
            let connection = connection();
            let mut accepting = Box::pin(connection.accept_bi());
            assert!(
                accepting
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            let error = if closed {
                connection.close(ErrorCode::H3_INTERNAL_ERROR);
                ErrorCode::H3_INTERNAL_ERROR
            } else {
                connection.cursor.goaway().unwrap();
                ErrorCode::H3_REQUEST_REJECTED
            };
            assert!(matches!(connection.accept_bi().await, Err(e) if e == error));
            assert_eq!(connection.transport.calls.load(Ordering::SeqCst), 1);
            connection.transport.ready.add_permits(1);
            assert!(matches!(accepting.await, Err(e) if e == error));
            assert_eq!(connection.bi_streams.len(), 0);
        }
    }

    #[tokio::test]
    async fn goaway_only_freezes_its_own_admission_direction() {
        for opening in [false, true] {
            let connection = connection();
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
                connection.cursor.goaway().unwrap();
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
        let connection = connection();
        connection.transport.ready.add_permits(1);
        let (send, recv) = connection.open_bi().await.unwrap();
        let boundary = StreamId::new(Role::Client, Dir::Bi, 100);
        connection.cursor.receive_goaway(boundary);
        connection.bi_streams.goaway(u64::from(boundary));
        connection.cursor.goaway().unwrap();
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
            if bytes == [self.0] {
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
        async fn terminated(&self) -> ErrorCode {
            self.base.terminated().await
        }
    }

    #[tokio::test]
    async fn either_qpack_writer_failure_closes_admission_and_active_streams() {
        for stream_type in [StreamType::QpackEncoder, StreamType::QpackDecoder] {
            let connection = H3Connection::new(
                FailingTransport {
                    base: TestTransport::default(),
                    stream_type: stream_type as u8,
                },
                Default::default(),
            )
            .unwrap();
            let (mut send, _recv) = connection
                .bi_streams
                .insert(0, Reader, FailingWriter(255))
                .unwrap();
            let error =
                tokio::time::timeout(Duration::from_secs(1), connection.transport.terminated())
                    .await
                    .unwrap();
            assert_eq!(error, ErrorCode::H3_CLOSED_CRITICAL_STREAM);
            assert_eq!(connection.qpack.error(), Some(error));
            assert_eq!(connection.open_bi().await.err(), Some(error));
            assert_eq!(ErrorCode::from(send.write_all(b"x").await.unwrap_err()), error);
            // The connection-owned writer tasks release their connection handles.
            tokio::task::yield_now().await;
            assert_eq!(Arc::strong_count(&connection.transport), 1);
        }
    }
}
