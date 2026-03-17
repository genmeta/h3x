use snafu::Snafu;

use super::{connection::ConnectionClient, error::StringError, serde_types::SerdeAuthority};

#[derive(Debug, Snafu, Clone, serde::Serialize, serde::Deserialize)]
pub enum ConnectError {
    #[snafu(transparent)]
    Remote { source: StringError },
    #[snafu(transparent)]
    Call { source: remoc::rtc::CallError },
}

#[remoc::rtc::remote]
pub trait RemoteConnect: Send + Sync {
    async fn connect(&self, server: SerdeAuthority) -> Result<ConnectionClient, ConnectError>;
}
