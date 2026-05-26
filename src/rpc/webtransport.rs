//! RPC forwarding for the WebTransport session layer.
//!
//! Re-exports the RTC trait, generated client/server types, and the
//! [`RemoteWebTransportSession`] convenience wrapper.

mod session;

pub use self::session::{
    RemoteWebTransportSession, WebTransportRpcSessionClient, WebTransportRpcSessionReqReceiver,
    WebTransportRpcSessionServer, WebTransportRpcSessionServerRef,
    WebTransportRpcSessionServerRefMut, WebTransportRpcSessionServerShared,
    WebTransportRpcSessionServerSharedMut,
};
use crate::{quic, webtransport};

impl From<remoc::rtc::CallError> for webtransport::OpenStreamError {
    fn from(error: remoc::rtc::CallError) -> Self {
        webtransport::OpenStreamError::Open {
            source: quic::ConnectionError::from(error),
        }
    }
}

impl From<remoc::rtc::CallError> for webtransport::SessionClosed {
    fn from(_error: remoc::rtc::CallError) -> Self {
        webtransport::SessionClosed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_error_maps_to_open_stream_connection_error() {
        let error = webtransport::OpenStreamError::from(remoc::rtc::CallError::Dropped);
        let webtransport::OpenStreamError::Open { source } = error else {
            panic!("call error should map to open stream connection error");
        };

        assert!(source.is_transport());
    }

    #[test]
    fn call_error_maps_to_session_closed_marker() {
        let closed = webtransport::SessionClosed::from(remoc::rtc::CallError::Dropped);

        assert_eq!(closed, webtransport::SessionClosed);
    }
}
