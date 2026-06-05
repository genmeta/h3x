mod codec;
mod handle;
pub(crate) mod reader;
pub(crate) mod writer;

pub use self::handle::{IpcBiHandle, IpcUniHandle};
