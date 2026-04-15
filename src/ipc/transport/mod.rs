//! IPC transport primitives for FD passing and multiplexed channels.
//!
//! - [`fd_channel`] — [`FdChannel`] for passing FDs over `SOCK_SEQPACKET`.
//! - [`mux_channel`] — [`MuxChannel`] multiplexing remoc + FD on a single socket.

pub mod fd_channel;
pub mod mux_channel;

pub use fd_channel::{FdChannel, RecvFdsError, SendFdsError};
pub use mux_channel::{
    FdRegistry, FdSender, MuxChannel, MuxSink, MuxSinkError, MuxStream, MuxStreamError,
    QueueFdsError, RegisterFdsError, SplitError, WaitFdsError,
};
