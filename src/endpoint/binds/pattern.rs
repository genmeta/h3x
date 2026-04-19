use std::{fmt, str::FromStr};

use either::Either;
use http::{
    Uri,
    uri::{Authority, PathAndQuery},
};
use peg::{error::ParseError, str::LineCol};

use super::BindHost;
use crate::dquic::{
    qbase::net::Family,
    qinterface::bind_uri::{BindUri, BindUriScheme},
};

/// A flexible bind pattern parsed from a string.
///
/// See [module documentation](super) for the full syntax description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    /// The resolved scheme (`iface` or `inet`). Always present after parsing.
    pub scheme: BindUriScheme,
    /// Host part — exact name/IP or glob pattern (carries family if applicable).
    pub host: BindHost,
    /// Port number. `None` means default (0 = system-assigned).
    pub port: Option<u16>,
    /// Optional path-and-query suffix carried through to generated URIs,
    /// validated as [`PathAndQuery`] during parsing.
    pub path_and_query: Option<PathAndQuery>,
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl fmt::Display for Bind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.scheme)?;
        if let Some(family) = self.host.family() {
            let tag = match family {
                Family::V4 => "v4",
                Family::V6 => "v6",
            };
            write!(f, "{tag}.")?;
        }
        if self.host.as_ip_addr().is_some_and(|ip| ip.is_ipv6()) {
            write!(f, "[{}]", self.host)?;
        } else {
            write!(f, "{}", self.host)?;
        }
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        if let Some(ref pq) = self.path_and_query {
            write!(f, "{pq}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PEG parser
// ---------------------------------------------------------------------------

peg::parser! {
    grammar bind_parser() for str {
        // -- atoms --

        rule family() -> Family
            = "v4" { Family::V4 }
            / "V4" { Family::V4 }
            / "v6" { Family::V6 }
            / "V6" { Family::V6 }

        /// Scheme prefix like `iface://` or `inet://`.
        rule scheme() -> &'input str
            = s:$(['a'..='z' | 'A'..='Z']+) "://" { s }

        /// Port number after `:`.
        rule port() -> u16
            = ":" n:$(['0'..='9']+) {?
                n.parse().or(Err("valid port number"))
            }

        /// A host character — anything except `:`, `/`, `?`, `#`, `[`, `]`.
        rule host_char() -> char
            = c:[^ ':' | '/' | '?' | '#' | '[' | ']'] { c }

        /// A bracket segment: `[...]` (IPv6 address or glob character class).
        rule bracket_segment()
            = "[" [^ ']']+ "]"

        /// A single host token: bracket segment or plain character.
        rule host_token()
            = bracket_segment()
            / host_char()

        /// Host string — one or more host tokens captured as a single slice.
        rule host_str() -> &'input str
            = s:$(host_token()+) { s }

        /// Path-and-query remainder: everything from `/` or `?` onward.
        rule path_and_query() -> &'input str
            = s:$(['/' | '?'] [_]*) { s }

        // -- composite rules --

        /// `scheme://family.host:port/path?query`  (full form)
        pub rule full() -> Bind
            = s:scheme()
              fam:(f:family() "." { f })?
              h:host_str()
              p:port()?
              pq:path_and_query()?
            {?
                let host = BindHost::classify(h, fam)?;
                let scheme = infer_scheme(Some(s), &host);
                let path_and_query = pq
                    .map(|s| s.parse::<PathAndQuery>())
                    .transpose()
                    .map_err(|_| "valid path-and-query")?;
                Ok(Bind { scheme, host, port: p, path_and_query })
            }

        /// `family.host:port/path?query`  (no scheme)
        pub rule no_scheme() -> Bind
            = fam:(f:family() "." { f })?
              h:host_str()
              p:port()?
              pq:path_and_query()?
            {?
                let host = BindHost::classify(h, fam)?;
                let scheme = infer_scheme(None, &host);
                let path_and_query = pq
                    .map(|s| s.parse::<PathAndQuery>())
                    .transpose()
                    .map_err(|_| "valid path-and-query")?;
                Ok(Bind { scheme, host, port: p, path_and_query })
            }

        /// Top-level entry: bare IP first, then full form, then no-scheme.
        ///
        /// `bare_ip` has highest priority — its `{? ... }` semantic guard
        /// ensures only valid IP addresses match; everything else backtracks.
        pub rule bind() -> Bind
            = b:bare_ip() { b }
            / b:full() { b }
            / b:no_scheme() { b }

        /// Bare IP address: `::1`, `::`, `2001:db8::1`, `127.0.0.1`.
        ///
        /// Captures everything up to `/`, `?`, or `#` (or end of input) and
        /// validates it as an [`IpAddr`].  Falls back via PEG ordered choice
        /// if validation fails.
        rule bare_ip() -> Bind
            = s:$([^ '/' | '?' | '#']+) pq:path_and_query()? {?
                let addr = s.parse::<std::net::IpAddr>().or(Err("valid IP address"))?;
                let path_and_query = pq
                    .map(|s| s.parse::<PathAndQuery>())
                    .transpose()
                    .map_err(|_| "valid path-and-query")?;
                Ok(Bind {
                    scheme: BindUriScheme::Inet,
                    host: BindHost::Ip { addr, repr: s.to_owned() },
                    port: None,
                    path_and_query,
                })
            }
    }
}

// ---------------------------------------------------------------------------
// Scheme inference helper
// ---------------------------------------------------------------------------

/// Infer the bind scheme from an optional explicit scheme string and the host.
fn infer_scheme(explicit: Option<&str>, host: &BindHost) -> BindUriScheme {
    if let Some(s) = explicit {
        return match s.to_ascii_lowercase().as_str() {
            "iface" => BindUriScheme::Iface,
            "inet" => BindUriScheme::Inet,
            _ => BindUriScheme::Iface,
        };
    }
    if host.is_ip_addr() {
        BindUriScheme::Inet
    } else {
        BindUriScheme::Iface
    }
}

// ---------------------------------------------------------------------------
// FromStr
// ---------------------------------------------------------------------------

impl FromStr for Bind {
    type Err = ParseError<LineCol>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bind_parser::bind(s)
    }
}

// ---------------------------------------------------------------------------
// Bind → BindUri expansion
// ---------------------------------------------------------------------------

impl Bind {
    /// Returns the effective port (defaults to 0 when omitted).
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(0)
    }

    /// Returns the path-and-query as a `&str`.
    #[must_use]
    pub fn path_and_query_str(&self) -> Option<&str> {
        self.path_and_query.as_ref().map(|pq| pq.as_str())
    }

    pub(crate) fn bind_uri_template(&self) -> impl Fn(Authority) -> Option<BindUri> + use<> {
        let mut uri_template = Uri::from_static("iface://v4.lo:0/").into_parts();
        uri_template.scheme = Some(self.scheme.into());
        uri_template.path_and_query =
            (self.path_and_query.clone()).or(uri_template.path_and_query.clone());
        let uri_template = Uri::from_parts(uri_template)
            .expect("BUG: bind URI template built from valid scheme and path-and-query");

        let port = self.effective_port();
        move |authority: Authority| {
            let mut uri_parts = uri_template.clone().into_parts();
            uri_parts.authority = Some(authority);

            let mut bind_uri =
                (Uri::from_parts(uri_parts).ok()).and_then(|uri| BindUri::try_from(uri).ok())?;
            if port == 0 {
                bind_uri = bind_uri.alloc_port();
            }
            Some(bind_uri)
        }
    }

    pub(crate) fn bind_hosts_for_interface(
        &self,
        interface: &str,
    ) -> impl Iterator<Item = Authority> {
        match &self.host {
            BindHost::Ip { .. } => Either::Left(std::iter::empty()),
            host if !host.matches(interface) => Either::Left(std::iter::empty()),
            host => Either::Right(host.families().iter().filter_map(move |family| {
                format!("{family}.{interface}:{port}", port = self.effective_port())
                    .parse()
                    .ok()
            })),
        }
    }

    /// Expand this bind pattern into concrete [`BindUri`]s.
    ///
    /// For IP hosts, a single URI is produced directly.
    /// For glob / exact hosts, the `interfaces` list is filtered and each
    /// matching interface is expanded with the applicable IP families.
    pub fn to_bind_uris<'a, I>(
        &'a self,
        interfaces: I,
    ) -> impl Iterator<Item = BindUri> + use<'a, I>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let template = self.bind_uri_template();
        let port = self.effective_port();
        match &self.host {
            BindHost::Ip { addr, .. } => {
                let authority: Authority = if addr.is_ipv6() {
                    format!("[{addr}]:{port}")
                } else {
                    format!("{addr}:{port}")
                }
                .parse()
                .expect("BUG: formatted IP address and port is a valid authority");
                Either::Left(template(authority).into_iter())
            }
            BindHost::Glob { .. } | BindHost::Exact { .. } => Either::Right(
                interfaces
                    .into_iter()
                    .flat_map(move |iface| self.bind_hosts_for_interface(iface))
                    .flat_map(template),
            ),
        }
    }
}
