//! Directional admission boundaries and peer GOAWAY notification.
use std::sync::Mutex;

use qbase::{
    ArcReceiving,
    sid::{Dir, StreamId},
    varint::VarInt,
};

use crate::{Error, ErrorCode, Result, Role};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Cursor {
    /// Exclusive upper bound of admitted streams, initially the first peer stream.
    Max(StreamId),
    /// Frozen GOAWAY boundary; no more streams are admitted.
    Gone(StreamId),
    Closed(Error),
}

pub(crate) struct StreamCursor<W> {
    pub(super) local: Mutex<Cursor>,
    pub(super) remote: Mutex<Cursor>,
    pub(super) control_stream: std::sync::Arc<tokio::sync::Mutex<W>>,
    remote_goaway: ArcReceiving<()>,
}

impl<W> StreamCursor<W> {
    pub(super) fn new(role: Role, send: W) -> Self {
        Self {
            control_stream: std::sync::Arc::new(tokio::sync::Mutex::new(send)),
            local: Mutex::new(Cursor::Max(StreamId::new(!role, Dir::Bi, 0))),
            remote: Mutex::new(Cursor::Max(StreamId::new(role, Dir::Bi, 0))),
            remote_goaway: ArcReceiving::default(),
        }
    }

    /// Freeze admission and return the GOAWAY boundary.
    pub(crate) fn local_goaway(&self) -> Result<StreamId> {
        let mut local = self.local.lock().unwrap();
        match local.clone() {
            Cursor::Max(id) | Cursor::Gone(id) => {
                *local = Cursor::Gone(id);
                Ok(id)
            }
            Cursor::Closed(error) => Err(error),
        }
    }

    /// The control reader validates each boundary before publishing the first one.
    pub(crate) fn receive_goaway(&self, id: StreamId) {
        {
            let mut remote = self.remote.lock().unwrap();
            if matches!(*remote, Cursor::Closed(_)) {
                return;
            }
            *remote = Cursor::Gone(id);
        }
        self.remote_goaway.obtain(());
    }

    /// Freeze both directions before the connection clears the stream registry.
    pub(super) fn close(&self, error: Error) {
        self.local.lock().unwrap().close(error.clone());
        self.remote.lock().unwrap().close(error);
        self.remote_goaway.obtain(());
    }

    pub(crate) async fn remote_goaway(&self) -> Result<StreamId> {
        loop {
            match self.remote.lock().unwrap().clone() {
                Cursor::Gone(id) => return Ok(id),
                Cursor::Closed(error) => return Err(error),
                Cursor::Max(_) => {}
            }
            self.remote_goaway.clone().await.map_err(|error| {
                ErrorCode::H3_INTERNAL_ERROR.with_reason(format!("GOAWAY wait cancelled: {error}"))
            })?;
        }
    }
}

impl Cursor {
    pub(super) fn not_goaway(&self) -> Result<()> {
        match self {
            Self::Max(_) => Ok(()),
            Self::Gone(_) => Err(ErrorCode::H3_REQUEST_REJECTED.with_reason("request rejected")),
            Self::Closed(error) => Err(error.clone()),
        }
    }

    fn close(&mut self, error: Error) {
        if !matches!(self, Self::Closed(_)) {
            *self = Self::Closed(error);
        }
    }

    pub(super) fn accept(&mut self, id: StreamId) -> Result<()> {
        match self {
            Self::Max(boundary) => {
                if id.role() != boundary.role() || id.dir() != Dir::Bi {
                    return Err(
                        ErrorCode::H3_ID_ERROR.with_reason("invalid stream or push identifier")
                    );
                }
                if id >= *boundary {
                    // A GOAWAY boundary must still fit in a QUIC variable integer.
                    let next = VarInt::try_from(u64::from(id) + 4).map_err(|_| {
                        ErrorCode::H3_ID_ERROR.with_reason("invalid stream or push identifier")
                    })?;
                    *boundary = StreamId::from(next);
                }
                Ok(())
            }
            Self::Gone(_) => Err(ErrorCode::H3_REQUEST_REJECTED.with_reason("request rejected")),
            Self::Closed(error) => Err(error.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        task::{Context, Waker},
    };

    use super::*;

    #[tokio::test]
    async fn peer_goaway_is_retained_for_repeated_waits() {
        let cursor = StreamCursor::new(Role::Client, crate::test_support::Writer);
        let mut first = Box::pin(cursor.remote_goaway());
        let mut second = Box::pin(cursor.remote_goaway());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert!(second.as_mut().poll(&mut cx).is_pending());
        drop(first);
        let id = StreamId::new(Role::Client, Dir::Bi, 1);
        cursor.receive_goaway(id);
        assert_eq!(second.await.unwrap(), id);
        assert_eq!(cursor.remote_goaway().await.unwrap(), id);
    }

    #[tokio::test]
    async fn close_releases_peer_wait_with_original_error() {
        let cursor = StreamCursor::new(Role::Client, crate::test_support::Writer);
        let mut peer = Box::pin(cursor.remote_goaway());
        assert!(
            peer.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let error = ErrorCode::H3_CLOSED_CRITICAL_STREAM.with_reason("control stream failed");
        cursor.close(error.clone());
        assert_eq!(peer.await, Err(error.clone()));
        assert_eq!(cursor.local_goaway(), Err(error));
    }
}
