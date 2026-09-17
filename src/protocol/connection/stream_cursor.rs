//! Directional admission boundaries and peer GOAWAY notification.
use std::sync::Mutex;

use qbase::{
    ArcReceiving,
    sid::{Dir, StreamId},
    varint::VarInt,
};

use crate::{ErrorCode, Result, Role};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Cursor {
    /// Exclusive upper bound of admitted streams, initially the first stream in this direction.
    Max(StreamId),
    /// Frozen GOAWAY boundary; no more streams are admitted.
    Gone(StreamId),
}

pub(crate) struct StreamCursor {
    pub(super) local: Mutex<Cursor>,
    pub(super) remote: Mutex<Cursor>,
    remote_goaway: ArcReceiving<()>,
}

impl StreamCursor {
    pub(super) fn new(role: Role) -> Self {
        Self {
            local: Mutex::new(Cursor::Max(StreamId::new(!role, Dir::Bi, 0))),
            remote: Mutex::new(Cursor::Max(StreamId::new(role, Dir::Bi, 0))),
            remote_goaway: ArcReceiving::default(),
        }
    }

    /// Freeze admission and return the GOAWAY boundary.
    pub(crate) fn local_goaway(&self) -> StreamId {
        let mut local = self.local.lock().unwrap();
        let (Cursor::Max(id) | Cursor::Gone(id)) = *local;
        *local = Cursor::Gone(id);
        id
    }

    /// The control reader validates each boundary before publishing the first one.
    pub(crate) fn receive_goaway(&self, id: StreamId) {
        {
            let mut remote = self.remote.lock().unwrap();
            *remote = Cursor::Gone(id);
        }
        self.remote_goaway.obtain(());
    }

    pub(crate) async fn remote_goaway(&self) -> Result<StreamId> {
        loop {
            match self.remote.lock().unwrap().clone() {
                Cursor::Gone(id) => return Ok(id),
                Cursor::Max(_) => {}
            }
            self.remote_goaway.clone().await.map_err(|error| {
                ErrorCode::H3_INTERNAL_ERROR.reason(format!("GOAWAY wait cancelled: {error}"))
            })?;
        }
    }
}

impl Cursor {
    pub(super) fn not_goaway(&self) -> Result<()> {
        match self {
            Self::Max(_) => Ok(()),
            Self::Gone(_) => Err(ErrorCode::H3_REQUEST_REJECTED.reason("request rejected")),
        }
    }

    pub(super) fn accept(&mut self, id: StreamId) -> Result<()> {
        match self {
            Self::Max(boundary) => {
                if id.role() != boundary.role() || id.dir() != Dir::Bi {
                    return Err(
                        ErrorCode::H3_ID_ERROR.reason("invalid stream or push identifier")
                    );
                }
                if id >= *boundary {
                    // A GOAWAY boundary must still fit in a QUIC variable integer.
                    let next = VarInt::try_from(u64::from(id) + 4).map_err(|_| {
                        ErrorCode::H3_ID_ERROR.reason("invalid stream or push identifier")
                    })?;
                    *boundary = StreamId::from(next);
                }
                Ok(())
            }
            Self::Gone(_) => Err(ErrorCode::H3_REQUEST_REJECTED.reason("request rejected")),
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
        let cursor = StreamCursor::new(Role::Client);
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
}
