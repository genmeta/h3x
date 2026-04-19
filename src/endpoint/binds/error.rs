use http::uri::{Authority, PathAndQuery, Scheme};
use snafu::Snafu;

/// Error indicating that two [`Bind`](super::Bind) patterns expand to the same target
/// (identical IP + port, or identical family + NIC + port) but carry
/// different path-and-query values.
#[derive(Debug, Clone, Snafu)]
#[snafu(display(
    "conflicting bindings exist for bind target `{scheme}://{authority}`: `{e}` vs `{i}`",
    e = existing.as_ref().map_or("/", PathAndQuery::as_str),
    i = incoming.as_ref().map_or("/", PathAndQuery::as_str),
))]
pub struct BindConflictError {
    /// The scheme component of the conflicting bind target.
    pub scheme: Scheme,
    /// The authority component of the conflicting bind target.
    pub authority: Authority,
    /// The first encountered path-and-query.
    pub existing: Option<PathAndQuery>,
    /// The conflicting path-and-query.
    pub incoming: Option<PathAndQuery>,
}
