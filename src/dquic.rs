pub mod binds;
pub mod client;
pub mod common;
mod endpoint;
pub mod identity;
pub mod network;
pub mod server;
pub mod sni;

mod shim;

pub use dquic::*;
pub use endpoint::*;
pub use identity::*;
pub use network::*;

/// dquic parameter types — transport parameters, parameter IDs, value types
pub mod param {
    pub use dquic::qbase::param::{
        ClientParameters, ParameterId, ParameterValue, ParameterValueType, PeerParameters,
        ServerParameters, error::Error as ParamError,
    };

    /// convenience constructors for parameters
    pub mod handy {
        pub use dquic::prelude::handy::{client_parameters, server_parameters};
    }
}

/// dquic token types — address validation tokens
pub mod token {
    pub use dquic::qbase::token::{TokenProvider, TokenSink};

    /// convenience token implementations
    pub mod handy {
        pub use dquic::qbase::token::handy::NoopTokenRegistry;
    }
}

/// dquic TLS / client authentication types
pub mod tls {
    pub use dquic::qconnection::tls::*;

    pub mod handy {
        pub use dquic::qconnection::tls::AcceptAllClientAuther;
    }
}

/// dquic stream concurrency types
pub mod stream {
    pub use dquic::{prelude::VarInt, qbase::sid::*};

    pub mod handy {
        pub use dquic::prelude::handy::ConsistentConcurrency;
    }
}

/// dquic telemetry / logging types
pub mod log {
    pub use dquic::qevent::telemetry::*;

    pub mod handy {
        pub use dquic::prelude::handy::NoopLogger;
    }
}

/// dquic DNS resolution types
pub mod resolver {
    pub use dquic::qresolve::*;

    pub mod handy {
        pub use dquic::prelude::handy::SystemResolver;
    }
}

/// dquic network address / binding types
pub mod net {
    pub use dquic::{
        prelude::{IO, IoExt},
        qbase::{
            cid::ConnectionId,
            net::addr::{BoundAddr, EndpointAddr, SocketEndpointAddr},
        },
        qinterface::{BindInterface, bind_uri::BindUri, device::Devices, io::ProductIO},
    };

    pub mod handy {
        pub use dquic::prelude::handy::DEFAULT_IO_FACTORY;
    }
}

/// dquic certificate utilities
pub mod cert {
    /// convenience certificate helpers
    pub mod handy {
        pub use dquic::prelude::handy::{ToCertificate, ToPrivateKey};
    }
}

/// dquic connection types
pub mod connection {
    pub use dquic::prelude::Connection;
}

/// Type alias for the default `H3Endpoint<QuicEndpoint>`.
pub type H3Endpoint = crate::endpoint::H3Endpoint<QuicEndpoint>;
