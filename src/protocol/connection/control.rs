//! Peer unidirectional stream admission, dispatch, and task lifetime.
use qbase::sid::{Dir, StreamId};
use tokio::io::AsyncWriteExt;

use super::H3Connection;
use crate::{
    Error, Result, Transport,
    protocol::{
        frame::{self, Control, Frame, StreamType, WriteControl as _, be_control},
        qpack,
    },
};

impl<T: Transport> H3Connection<T> {
    pub(super) async fn accept_uni(self) {
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
                StreamType::Push => Err(Error::H3_ID_ERROR),
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

    fn close(&self, error: Error) {
        let error = self.qpack.close(error);
        self.cursor.close(error);
        self.bi_streams.close(error);
    }

    async fn fail(&self, error: Error) {
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
    pub(super) async fn send_uni(self) {
        let mut send = match self.transport.open_uni().await {
            Ok(Some((_, send))) => send,
            Ok(None) => {
                self.fail(Error::H3_STREAM_CREATION_ERROR).await;
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
                    .close(Error::H3_NO_ERROR.to_string(), Error::H3_NO_ERROR.as_u64())
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
        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;

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
        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
        Ok(())
    }

    async fn receive_control(&self, recv: &mut T::StreamReader) -> Result<()> {
        let settings = match be_control(recv).await {
            Ok(Control::Settings(frame)) => frame.payload,
            Err(error) if error != Error::H3_FRAME_UNEXPECTED => return Err(error),
            _ => return Err(Error::H3_MISSING_SETTINGS),
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
                        return Err(Error::H3_ID_ERROR);
                    }
                    last_goaway_id = Some(id);
                    // Freeze opens before scanning: registration uses the same lock.
                    self.cursor.receive_goaway(id);
                    self.bi_streams.goaway(u64::from(id), &self.qpack);
                }
                // Server push is not supported.
                Control::MaxPushId(_) | Control::CancelPush(_) => {
                    return Err(Error::H3_ID_ERROR);
                }
                Control::Unknown { length, .. } => {
                    frame::skip_payload(recv, length.into_u64())
                        .await
                        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
                }
                _ => return Err(Error::H3_FRAME_UNEXPECTED),
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

    use crate::{Error, Role, Transport, test_support};

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
            Error::H3_NO_ERROR
        );
        assert!(connection.goaway().await.is_ok());
    }

    #[tokio::test]
    async fn goaway_reports_transport_failure() {
        let connection = test_support::connection();
        connection
            .transport
            .close(String::new(), Error::H3_INTERNAL_ERROR.as_u64())
            .unwrap();
        assert_eq!(connection.goaway().await, Err(Error::H3_INTERNAL_ERROR));
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
        Error, H3Connection, Result, Role, Transport,
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
        async fn terminated(&self) -> Error {
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
                    Error::H3_REQUEST_REJECTED
                }
                _ => {
                    connection.close(Error::H3_INTERNAL_ERROR);
                    Error::H3_INTERNAL_ERROR
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
                connection.close(Error::H3_INTERNAL_ERROR);
                Error::H3_INTERNAL_ERROR
            } else {
                connection.cursor.goaway().unwrap();
                Error::H3_REQUEST_REJECTED
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
        connection
            .bi_streams
            .goaway(u64::from(boundary), &connection.qpack);
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
