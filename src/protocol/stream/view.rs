//! Directional admission boundaries.
use qbase::{
    ArcReceiving,
    sid::{Dir, StreamId},
    varint::VarInt,
};

use crate::{ErrorCode, Result, Role};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Cursor {
    /// Exclusive upper bound of admitted streams, initially the first stream in this direction.
    Max(StreamId),
    /// Frozen GOAWAY boundary; no more streams are admitted.
    Gone(StreamId),
}

impl Cursor {
    fn not_goaway(&self) -> Result<()> {
        match self {
            Self::Max(_) => Ok(()),
            Self::Gone(_) => Err(ErrorCode::H3_REQUEST_REJECTED.reason("request rejected")),
        }
    }

    fn accept(&mut self, id: StreamId) -> Result<()> {
        match self {
            Self::Max(boundary) => {
                if id.role() != boundary.role() || id.dir() != Dir::Bi {
                    return Err(ErrorCode::H3_ID_ERROR.reason("invalid stream or push identifier"));
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

/// Directional admission boundaries and their GOAWAY notifications.
pub(crate) struct StreamView {
    local: Cursor,
    remote: Cursor,
    local_goaway: tokio::sync::watch::Sender<Option<StreamId>>,
    remote_goaway: ArcReceiving<()>,
}

impl StreamView {
    pub(crate) fn new(role: Role) -> Self {
        Self {
            local: Cursor::Max(StreamId::new(!role, Dir::Bi, 0)),
            remote: Cursor::Max(StreamId::new(role, Dir::Bi, 0)),
            local_goaway: tokio::sync::watch::channel(None).0,
            remote_goaway: ArcReceiving::default(),
        }
    }

    pub(crate) fn local_not_goaway(&self) -> Result<()> {
        self.local.not_goaway()
    }

    pub(crate) fn remote_not_goway(&self) -> Result<()> {
        self.remote.not_goaway()
    }

    pub(crate) fn accept(&mut self, id: StreamId) -> Result<()> {
        self.local.accept(id)
    }

    pub(crate) fn local_goaway(&mut self) -> StreamId {
        let (Cursor::Max(id) | Cursor::Gone(id)) = self.local;
        self.local = Cursor::Gone(id);
        self.local_goaway.send_if_modified(|boundary| {
            if boundary.is_some() {
                return false;
            }
            *boundary = Some(id);
            true
        });
        id
    }

    pub(crate) fn receive_goaway(&mut self, id: StreamId) {
        self.remote = Cursor::Gone(id);
        self.remote_goaway.obtain(());
    }

    pub(crate) fn local_goaway_notification(&self) -> impl Future<Output = StreamId> + use<> {
        let mut notification = self.local_goaway.subscribe();
        async move {
            notification
                .wait_for(Option::is_some)
                .await
                .expect("stream view lives while the connection is active")
                .unwrap()
        }
    }

    pub(crate) fn remote_goaway_notification(&self) -> ArcReceiving<()> {
        self.remote_goaway.clone()
    }
}
