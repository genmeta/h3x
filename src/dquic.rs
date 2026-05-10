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

/// dquic transport parameters — client/server/peer parameter sets, IDs, value types
pub mod param {
    pub use dquic::qbase::param::{
        ClientParameters, ParameterId, ParameterValue, ParameterValueType, PeerParameters,
        ServerParameters, error::Error as ParamError, preferred_address::PreferredAddress,
    };

    /// convenience constructors for parameters
    pub mod handy {
        pub use dquic::qbase::param::handy::{client_parameters, server_parameters};
    }
}

/// dquic token types — address validation tokens
pub mod token {
    pub use dquic::qbase::token::{TokenProvider, TokenSink};

    /// convenience token implementations
    pub mod handy {
        pub use dquic::qbase::token::handy::*;
    }
}

/// dquic TLS / client authentication types
pub mod tls {
    pub use dquic::qconnection::tls::{
        AuthClient, ClientAgentVerifyResult, ClientNameVerifyResult, LocalAgent, RemoteAgent,
    };

    pub mod handy {
        pub use dquic::qconnection::tls::AcceptAllClientAuther;
    }
}

/// dquic stream concurrency types
pub mod stream {
    pub use dquic::{
        prelude::VarInt,
        qbase::sid::{
            ControlStreamsConcurrency, Dir, ProductStreamsConcurrencyController, StreamId,
        },
    };

    pub mod handy {
        pub use dquic::qbase::sid::handy::*;
    }
}

/// dquic telemetry / logging types
pub mod log {
    pub use dquic::qevent::telemetry::{ExportEvent, QLog, Span};

    pub mod handy {
        pub use dquic::qevent::telemetry::handy::*;
    }
}

/// dquic DNS resolution types
pub mod resolver {
    pub use dquic::qresolve::{
        Publish, PublishFuture, Record, RecordStream, Resolve, ResolveFuture, ResolveResult, Source,
    };

    pub mod handy {
        pub use dquic::qresolve::SystemResolver;
    }
}

/// dquic network address, binding, interface, and IO types
pub mod net {
    pub use dquic::{
        prelude::{IO, IoExt},
        qbase::{
            cid::ConnectionId,
            net::addr::{BleEndpontAddr, BoundAddr, EndpointAddr, SocketEndpointAddr},
        },
        qinterface::{
            BindInterface,
            bind_uri::{BindUri, ParseBindUriError},
            component::{location::Locations, route::QuicRouter},
            device::Devices,
            io::ProductIO,
            manager::InterfaceManager,
        },
    };

    pub mod handy {
        pub use dquic::qinterface::io::handy::*;
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
