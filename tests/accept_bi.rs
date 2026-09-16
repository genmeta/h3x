mod support;

use std::{
    collections::VecDeque,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
};

use h3x::{ErrorCode, H3Connection, Result, Role, Transport};
use support::{Reader, TestTransport, Writer};

struct DirectTransport {
    base: TestTransport,
    calls: Arc<AtomicUsize>,
    streams: Mutex<VecDeque<Result<u64>>>,
}

impl Transport for DirectTransport {
    type StreamReader = Reader;
    type StreamWriter = Writer;
    fn role(&self) -> Role {
        Role::Client
    }
    async fn open_bi(&self) -> Result<Option<(u64, (Reader, Writer))>> {
        self.base.open_bi().await
    }
    async fn accept_bi(&self) -> Result<(u64, (Reader, Writer))> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let next = self.streams.lock().unwrap().pop_front();
        match next {
            Some(id) => Ok((id?, (Reader, Writer))),
            None => self.base.accept_bi().await,
        }
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

fn connection(
    ids: impl IntoIterator<Item = Result<u64>>,
) -> (H3Connection<DirectTransport>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = DirectTransport {
        base: TestTransport::default(),
        calls: calls.clone(),
        streams: Mutex::new(ids.into_iter().collect()),
    };
    (
        H3Connection::new(transport, Default::default()).unwrap(),
        calls,
    )
}

#[tokio::test]
async fn application_drives_acceptance_and_receives_transport_errors() {
    let (connection, calls) = connection([
        Ok(1),
        Ok(5),
        Err(ErrorCode::H3_INTERNAL_ERROR.with_reason("test transport failed to accept a stream")),
    ]);
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    for id in [1, 5] {
        let (write, read) = connection.accept_bi().await.unwrap();
        assert_eq!(write.stream_id(), id);
        assert_eq!(read.stream_id(), id);
    }
    assert!(matches!(
        connection.accept_bi().await,
        Err(h3x::Error {
            code: ErrorCode::H3_INTERNAL_ERROR,
            ..
        })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn acceptance_checks_ids_and_local_goaway() {
    let (connection, _) = connection([Ok(0), Ok(1), Ok(5)]);
    assert!(matches!(
        connection.accept_bi().await,
        Err(h3x::Error {
            code: ErrorCode::H3_ID_ERROR,
            ..
        })
    ));
    let (_write, _read) = connection.accept_bi().await.unwrap();
    let mut closing = Box::pin(connection.clone().goaway());
    assert!(
        closing
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(matches!(
        connection.accept_bi().await,
        Err(h3x::Error {
            code: ErrorCode::H3_REQUEST_REJECTED,
            ..
        })
    ));
}
