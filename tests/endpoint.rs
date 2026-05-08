//! Phase 1 compilation check for generic `H3Endpoint`.
//!
//! Full integration tests will be restored in follow-up tasks
//! once QuicEndpoint, Network, and serve/get methods are re-added.

use h3x::endpoint::H3Endpoint;

/// Compile-time verification that `H3Endpoint` is now generic over `T: quic::Connect`.
#[test]
fn h3endpoint_is_generic() {
    fn _assert_generic<T: h3x::quic::Connect>(_: &H3Endpoint<T>) {}
}
