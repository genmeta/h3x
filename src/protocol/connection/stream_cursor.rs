//! Directional admission boundaries and single-consumer GOAWAY notifications.
use std::sync::Mutex;

use qbase::{
    ArcReceiving,
    sid::{Dir, StreamId},
    varint::VarInt,
};

use crate::{Error, Result, Role};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cursor {
    /// Exclusive upper bound of admitted streams, initially the first peer stream.
    Max(StreamId),
    /// Frozen GOAWAY boundary; no more streams are admitted.
    Gone(StreamId),
    Closed(Error),
}

pub(crate) struct StreamCursor {
    pub(super) local: Mutex<Cursor>,
    pub(super) remote: Mutex<Cursor>,
    local_goaway: ArcReceiving<StreamId>,
    remote_goaway: ArcReceiving<StreamId>,
}

impl StreamCursor {
    pub(super) fn new(role: Role) -> Self {
        Self {
            local: Mutex::new(Cursor::Max(StreamId::new(!role, Dir::Bi, 0))),
            remote: Mutex::new(Cursor::Max(StreamId::new(role, Dir::Bi, 0))),
            local_goaway: ArcReceiving::default(),
            remote_goaway: ArcReceiving::default(),
        }
    }

    pub(crate) fn goaway(&self) -> Result<()> {
        let id = {
            let mut local = self.local.lock().unwrap();
            let (Cursor::Max(id) | Cursor::Gone(id)) = *local else {
                return Ok(());
            };
            *local = Cursor::Gone(id);
            id
        };
        self.local_goaway.obtain(id);
        Ok(())
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
        self.remote_goaway.obtain(id);
    }

    /// Freeze both directions before the connection clears the stream registry.
    pub(super) fn close(&self, error: Error) {
        self.local.lock().unwrap().close(error);
        self.remote.lock().unwrap().close(error);
    }

    pub(crate) async fn local_goaway(&self) -> Result<StreamId> {
        self.local_goaway
            .clone()
            .await
            .map_err(|_| Error::H3_INTERNAL_ERROR)?
            .ok_or(Error::H3_INTERNAL_ERROR)
    }

    pub(crate) async fn peer_goaway(&self) -> Result<StreamId> {
        self.remote_goaway
            .clone()
            .await
            .map_err(|_| Error::H3_INTERNAL_ERROR)?
            .ok_or(Error::H3_INTERNAL_ERROR)
    }
}

impl Cursor {
    pub(super) fn check_admission(&self) -> Result<()> {
        match self {
            Self::Max(_) => Ok(()),
            Self::Gone(_) => Err(Error::H3_REQUEST_REJECTED),
            Self::Closed(error) => Err(*error),
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
                    return Err(Error::H3_ID_ERROR);
                }
                if id >= *boundary {
                    // A GOAWAY boundary must still fit in a QUIC variable integer.
                    let next =
                        VarInt::try_from(u64::from(id) + 4).map_err(|_| Error::H3_ID_ERROR)?;
                    *boundary = StreamId::from(next);
                }
                Ok(())
            }
            Self::Gone(_) => Err(Error::H3_REQUEST_REJECTED),
            Self::Closed(error) => Err(*error),
        }
    }
}
