//! RPC forwarding for the WebTransport session layer.
//!
//! Re-exports the RTC trait, generated client/server types, and the
//! [`RemoteWtSession`] convenience wrapper.

mod session;

pub use self::session::{
    RemoteWtSession, WtSessionClient, WtSessionReqReceiver, WtSessionServer, WtSessionServerRef,
    WtSessionServerRefMut, WtSessionServerShared, WtSessionServerSharedMut,
};
use crate::{quic, webtransport};

impl From<remoc::rtc::CallError> for webtransport::OpenStreamError {
    fn from(error: remoc::rtc::CallError) -> Self {
        webtransport::OpenStreamError::Open {
            source: quic::ConnectionError::from(error),
        }
    }
}

impl From<remoc::rtc::CallError> for webtransport::Closed {
    fn from(_error: remoc::rtc::CallError) -> Self {
        webtransport::Closed
    }
}
