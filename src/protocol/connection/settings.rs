//! Local configuration and independently received peer settings.

use std::sync::OnceLock;

use qbase::varint::VarInt;
use tokio::sync::Notify;

use crate::{ErrorCode, Result, protocol::frame};

/// Local settings advertised when constructing an HTTP/3 connection.
/// Extended CONNECT support is always advertised.
#[derive(Clone, Debug)]
pub struct Settings(pub(crate) frame::Settings);

/// Peer settings are published once and borrowed by every waiter.
#[derive(Default)]
pub(crate) struct PeerSettings {
    value: OnceLock<frame::Settings>,
    ready: Notify,
}

impl PeerSettings {
    pub(super) fn obtain(&self, settings: frame::Settings) {
        if self.value.set(settings).is_ok() {
            self.ready.notify_waiters();
        }
    }

    pub(crate) async fn received(&self) -> &frame::Settings {
        loop {
            let ready = self.ready.notified();
            tokio::pin!(ready);
            // Register before checking the value so publication cannot lose a wakeup.
            ready.as_mut().enable();
            if let Some(settings) = self.value.get() {
                return settings;
            }
            ready.await;
        }
    }
}

impl Settings {
    pub fn new(
        max_field_section_size: u64,
        max_table_capacity: u64,
        blocked_streams: u64,
    ) -> Result<Self> {
        let values = [
            (frame::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
            (frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, max_table_capacity),
            (
                frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                max_field_section_size,
            ),
            (frame::SETTINGS_QPACK_BLOCKED_STREAMS, blocked_streams),
        ]
        .into_iter()
        .map(|(id, value)| {
            Ok((
                VarInt::from_u32(id),
                VarInt::try_from(value).map_err(|error| {
                    ErrorCode::H3_SETTINGS_ERROR.with_reason(format!(
                        "SETTINGS value exceeds the QUIC variable-integer range: {error}"
                    ))
                })?,
            ))
        })
        .collect::<Result<_>>()?;
        Ok(Self(frame::Settings { values }))
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new(64 * 1024, 4096, 16).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use qbase::varint::VARINT_MAX;

    use super::*;

    #[tokio::test]
    async fn peer_settings_wake_all_waiters_after_cancellation() {
        use std::{
            future::Future,
            sync::Arc,
            task::{Context, Waker},
            time::Duration,
        };
        let peer = Arc::new(PeerSettings::default());
        let mut cancelled = Box::pin(peer.received());
        assert!(
            cancelled
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(cancelled);
        let mut waiters = Vec::new();
        for _ in 0..8 {
            let peer = peer.clone();
            waiters.push(tokio::spawn(async move {
                let settings = peer.received().await;
                assert!(std::ptr::eq(settings, peer.value.get().unwrap()));
            }));
        }
        tokio::task::yield_now().await;
        peer.obtain(frame::Settings::default());
        tokio::time::timeout(Duration::from_secs(1), async {
            for waiter in waiters {
                waiter.await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(std::ptr::eq(peer.received().await, peer.received().await));
    }

    #[tokio::test]
    async fn peer_settings_arrive_before_waiters_and_cannot_be_overwritten() {
        let peer = PeerSettings::default();
        let expected = frame::Settings::default();
        peer.obtain(expected.clone());
        assert_eq!(peer.received().await, &expected);
        peer.obtain(Settings::default().0);
        assert_eq!(peer.received().await, &expected);
    }

    #[test]
    fn settings_accept_limits_and_reject_unrepresentable_values() {
        let max_fields = VARINT_MAX;
        let max_capacity = VARINT_MAX;
        for (fields, capacity, blocked) in [(0, 0, 0), (max_fields, max_capacity, VARINT_MAX)] {
            let settings = Settings::new(fields, capacity, blocked).unwrap();
            assert_eq!(
                settings.0.get(frame::SETTINGS_ENABLE_CONNECT_PROTOCOL, 0),
                1
            );
            assert_eq!(
                settings.0.get(frame::SETTINGS_MAX_FIELD_SECTION_SIZE, 1),
                fields
            );
            assert_eq!(
                settings.0.get(frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, 1),
                capacity
            );
            assert_eq!(
                settings.0.get(frame::SETTINGS_QPACK_BLOCKED_STREAMS, 1),
                blocked
            );
        }
        for (fields, capacity, blocked) in [
            (max_fields + 1, 0, 0),
            (0, max_capacity + 1, 0),
            (0, 0, VARINT_MAX + 1),
        ] {
            assert!(matches!(
                Settings::new(fields, capacity, blocked),
                Err(h3x::Error {
                    code: ErrorCode::H3_SETTINGS_ERROR,
                    ..
                })
            ));
        }
    }
}
