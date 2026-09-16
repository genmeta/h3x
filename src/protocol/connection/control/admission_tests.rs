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
        tokio::select! {
            biased;
            error = self.base.terminated() => return Err(error),
            permit = self.ready.acquire() => permit.unwrap().forget(),
        }
        Ok(Some((0, (Reader, Writer))))
    }
    async fn accept_bi(&self) -> Result<(u64, (Reader, Writer))> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::select! {
            biased;
            error = self.base.terminated() => return Err(error),
            permit = self.ready.acquire() => permit.unwrap().forget(),
        }
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
                connection
                    .transport
                    .close(
                        "test closes the connection during stream processing".into(),
                        ErrorCode::H3_INTERNAL_ERROR.as_u64(),
                    )
                    .unwrap();
                ErrorCode::H3_INTERNAL_ERROR
            }
        };
        assert!(matches!(connection.open_bi().await, Err(e) if e.code == error));
        assert_eq!(
            connection.transport.calls.load(Ordering::SeqCst),
            if transition == 0 { 1 } else { 2 }
        );
        if transition == 0 {
            connection.cursor.local_goaway();
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
            connection
                .transport
                .close(
                    "test closes the connection during stream processing".into(),
                    ErrorCode::H3_INTERNAL_ERROR.as_u64(),
                )
                .unwrap();
            ErrorCode::H3_INTERNAL_ERROR
        } else {
            connection.cursor.local_goaway();
            ErrorCode::H3_REQUEST_REJECTED
        };
        assert!(matches!(connection.accept_bi().await, Err(e) if e.code == error));
        assert_eq!(
            connection.transport.calls.load(Ordering::SeqCst),
            if closed { 2 } else { 1 }
        );
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
            connection.cursor.local_goaway();
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
    connection.cursor.local_goaway();
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
