//! Directional admission boundaries.
use qbase::{
    ArcReceiving,
    sid::{Dir, StreamId},
    varint::VarInt,
};
use tokio::sync::watch;

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
            Self::Gone(_) => Err(ErrorCode::RequestRejected.stream("request rejected")),
        }
    }

    fn accept(&mut self, id: StreamId) -> Result<()> {
        let boundary = match self {
            Self::Max(boundary) | Self::Gone(boundary) => *boundary,
        };
        if id.role() != boundary.role() || id.dir() != Dir::Bi {
            return Err(ErrorCode::InternalError
                .connection("transport returned a non-peer bidirectional stream"));
        }

        match self {
            Self::Max(boundary) => {
                if id >= *boundary {
                    // A GOAWAY boundary must still fit in a QUIC variable integer.
                    let next = VarInt::try_from(u64::from(id) + 4).map_err(|_| {
                        ErrorCode::RequestRejected
                            .stream("request cannot be admitted at the end of stream ID space")
                    })?;
                    *boundary = StreamId::from(next);
                }
                Ok(())
            }
            Self::Gone(_) => Err(ErrorCode::RequestRejected.stream("request rejected")),
        }
    }
}

/// Directional admission boundaries and their GOAWAY notifications.
pub(crate) struct StreamView {
    local: Cursor,
    remote: Cursor,
    local_goaway: watch::Sender<Option<StreamId>>,
    remote_goaway: ArcReceiving<()>,
}

impl StreamView {
    pub(crate) fn new(role: Role) -> Self {
        Self {
            local: Cursor::Max(StreamId::new(!role, Dir::Bi, 0)),
            remote: Cursor::Max(StreamId::new(role, Dir::Bi, 0)),
            local_goaway: watch::channel(None).0,
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

    pub(crate) fn goaway(&mut self) -> StreamId {
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

    pub(crate) fn on_goaway(&mut self, id: StreamId) {
        self.remote = Cursor::Gone(id);
        self.remote_goaway.obtain(());
    }

    pub(crate) fn local_goaway(&self) -> impl Future<Output = StreamId> + use<> {
        let mut notification = self.local_goaway.subscribe();
        async move {
            notification
                .wait_for(Option::is_some)
                .await
                .expect("stream view lives while the connection is active")
                .unwrap()
        }
    }

    pub(crate) fn recv_goway(&self) -> ArcReceiving<()> {
        self.remote_goaway.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn validates_ids_and_freezes_both_goaway_boundaries() {
        let mut view = StreamView::new(Role::Client);
        let wrong_role = StreamId::new(Role::Client, Dir::Bi, 0);
        let wrong_direction = StreamId::new(Role::Server, Dir::Uni, 0);
        assert_eq!(
            view.accept(wrong_role).unwrap_err().code,
            ErrorCode::InternalError
        );
        assert_eq!(
            view.accept(wrong_direction).unwrap_err().code,
            ErrorCode::InternalError
        );

        let largest_server_bi = StreamId::from(VarInt::try_from((1_u64 << 62) - 3).unwrap());
        let error = view.accept(largest_server_bi).unwrap_err();
        assert_eq!(error.code, ErrorCode::RequestRejected);
        assert!(matches!(error, crate::Error::Stream(_)));

        let local = view.goaway();
        assert_eq!(view.goaway(), local);
        assert_eq!(
            view.local_not_goaway().unwrap_err().code,
            ErrorCode::RequestRejected
        );
        assert_eq!(
            view.accept(StreamId::new(Role::Server, Dir::Bi, 0))
                .unwrap_err()
                .code,
            ErrorCode::RequestRejected
        );
        assert_eq!(view.local_goaway().await, local);

        let remote = StreamId::new(Role::Client, Dir::Bi, 1);
        view.on_goaway(remote);
        view.recv_goway().await.unwrap();
        assert_eq!(
            view.remote_not_goway().unwrap_err().code,
            ErrorCode::RequestRejected
        );
    }
}
