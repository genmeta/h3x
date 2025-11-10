pub mod error;
pub mod util;

mod reader;
mod writer;

pub use reader::{BufStreamReader, FixedLengthReader};
pub use writer::{BufSinkWriter, Feed};
