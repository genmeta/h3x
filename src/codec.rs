pub mod error;
pub mod util;

mod reader;
mod writer;

pub use reader::{FixedLengthReader, StreamReader};
pub use writer::{Feed, SinkWriter};
