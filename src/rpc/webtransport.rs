//! RPC forwarding for the WebTransport session layer.
//!
//! Re-exports the RTC trait, generated client/server types, and the
//! [`RemoteWtSession`] convenience wrapper.

mod session;

pub use self::session::{
    RemoteWtSession, WtSessionClient, WtSessionReqReceiver, WtSessionServer, WtSessionServerRef,
    WtSessionServerRefMut, WtSessionServerShared, WtSessionServerSharedMut,
};
