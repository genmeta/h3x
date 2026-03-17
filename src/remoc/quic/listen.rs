use snafu::Snafu;

use super::{connection::ConnectionClient, error::StringError};

#[derive(Debug, Snafu, Clone, serde::Serialize, serde::Deserialize)]
pub enum ListenError {
    #[snafu(transparent)]
    Remote { source: StringError },
    #[snafu(transparent)]
    Call { source: remoc::rtc::CallError },
}

#[remoc::rtc::remote]
pub trait Listen: Send + Sync {
    async fn accept(&self) -> Result<ConnectionClient, ListenError>;
    async fn shutdown(&self) -> Result<(), ListenError>;
}
