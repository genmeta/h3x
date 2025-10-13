use std::{error::Error, io};

use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum StreamError {
    #[snafu(transparent)]
    Connection {
        source: ConnectionError,
    },
    Reset {
        code: u64,
    },
    Unknown {
        source: Box<dyn Error + Send + Sync>,
    },
}

impl From<StreamError> for io::Error {
    fn from(value: StreamError) -> Self {
        match value {
            e @ (StreamError::Connection { .. } | StreamError::Reset { .. }) => {
                io::Error::new(io::ErrorKind::BrokenPipe, e)
            }
            StreamError::Unknown { source } => io::Error::other(source),
        }
    }
}

impl From<io::Error> for StreamError {
    fn from(value: io::Error) -> Self {
        match value.downcast::<Self>() {
            Ok(error) => error,
            Err(error) => StreamError::Unknown {
                source: Box::new(error),
            },
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ConnectionError {
    Transport { reason: String },
    Application { reason: String },
}
