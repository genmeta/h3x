use std::{fmt, net::IpAddr};

use globset::{Glob, GlobMatcher};

use crate::dquic::qbase::net::Family;

/// The host part of a [`Bind`](super::Bind) — a parsed IP address, a glob pattern, or an exact name.
///
/// Literal host names (e.g. `enp17s0`) are normally represented as
/// [`Glob`](BindHost::Glob) with a literal pattern (globset treats them as exact
/// matches).  [`Exact`](BindHost::Exact) serves as a fallback when `Glob::new`
/// fails for an unusual input.
#[derive(Clone)]
pub enum BindHost {
    /// A parsed IP address (IPv4 or IPv6).
    Ip {
        /// The parsed address.
        addr: IpAddr,
        /// String representation of the address (without brackets).
        repr: String,
    },
    /// A compiled glob pattern (e.g. `en*`, `[ew]*`, `*`, `enp17s0`).
    Glob {
        /// IP family filter, if present.
        family: Option<Family>,
        /// Compiled matcher for efficient matching.
        matcher: GlobMatcher,
    },
    /// Fallback exact match when glob compilation fails.
    Exact {
        /// IP family filter, if present.
        family: Option<Family>,
        /// The exact interface name.
        nic: String,
    },
}

impl BindHost {
    /// Build a [`BindHost`] from a raw host string, automatically classifying
    /// it as [`Ip`](BindHost::Ip), [`Glob`](BindHost::Glob), or
    /// [`Exact`](BindHost::Exact) (fallback).
    ///
    /// `family` is propagated into [`Glob`](BindHost::Glob) and
    /// [`Exact`](BindHost::Exact) variants; it is rejected for IP addresses
    /// (writing `v4.127.0.0.1` makes no sense).
    pub(crate) fn classify(raw: &str, family: Option<Family>) -> Result<Self, &'static str> {
        use std::net::Ipv6Addr;

        // Try direct IP parse (handles plain IPv4 like "127.0.0.1")
        if let Ok(addr) = raw.parse::<IpAddr>() {
            if family.is_some() {
                return Err("family prefix is not valid for IP addresses");
            }
            return Ok(Self::Ip {
                addr,
                repr: raw.to_owned(),
            });
        }

        // Try bracket-stripped IP parse (handles "[::1]")
        if let Some(inner) = raw.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
            && let Ok(addr) = inner.parse::<Ipv6Addr>()
        {
            if family.is_some() {
                return Err("family prefix is not valid for IP addresses");
            }
            return Ok(Self::Ip {
                addr: addr.into(),
                repr: inner.to_owned(),
            });
        }

        // Try glob compilation; fall back to plain string
        match Glob::new(raw) {
            Ok(glob) => Ok(Self::Glob {
                family,
                matcher: glob.compile_matcher(),
            }),
            Err(_) => Ok(Self::Exact {
                family,
                nic: raw.to_owned(),
            }),
        }
    }

    /// Returns `true` if this host contains glob meta-characters (`*`, `[`).
    #[must_use]
    pub fn is_glob(&self) -> bool {
        match self {
            Self::Ip { .. } | Self::Exact { .. } => false,
            Self::Glob { matcher, .. } => {
                let pat = matcher.glob().glob();
                pat.contains('*') || pat.contains('[')
            }
        }
    }

    /// Returns the underlying string regardless of variant.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ip { repr, .. } | Self::Exact { nic: repr, .. } => repr,
            Self::Glob { matcher, .. } => matcher.glob().glob(),
        }
    }

    /// Returns `true` if the host is a parsed IP address.
    #[must_use]
    pub fn is_ip_addr(&self) -> bool {
        matches!(self, Self::Ip { .. })
    }

    /// Returns the parsed [`IpAddr`] if this host is an IP address.
    #[must_use]
    pub fn as_ip_addr(&self) -> Option<IpAddr> {
        match self {
            Self::Ip { addr, .. } => Some(*addr),
            _ => None,
        }
    }

    /// Returns the IP family filter, if set.
    ///
    /// Only [`Glob`](BindHost::Glob) and [`Exact`](BindHost::Exact) carry a
    /// family; [`Ip`](BindHost::Ip) always returns `None`.
    #[must_use]
    pub fn family(&self) -> Option<Family> {
        match self {
            Self::Ip { .. } => None,
            Self::Glob { family, .. } | Self::Exact { family, .. } => *family,
        }
    }

    /// Returns the families this host covers.
    ///
    /// If a specific family is set, returns a single-element slice;
    /// otherwise returns both V4 and V6.
    #[must_use]
    pub fn families(&self) -> &'static [Family] {
        const V4_ONLY: [Family; 1] = [Family::V4];
        const V6_ONLY: [Family; 1] = [Family::V6];
        const BOTH: [Family; 2] = [Family::V4, Family::V6];
        match self.family() {
            Some(Family::V4) => &V4_ONLY,
            Some(Family::V6) => &V6_ONLY,
            None => &BOTH,
        }
    }

    /// Tests whether a concrete interface name matches this host.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        match self {
            Self::Ip { .. } => false,
            Self::Glob { matcher, .. } => matcher.is_match(name),
            Self::Exact { nic, .. } => nic == name,
        }
    }
}

impl PartialEq for BindHost {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ip { repr: a, .. }, Self::Ip { repr: b, .. }) => a == b,
            (
                Self::Glob {
                    family: fa,
                    matcher: ma,
                },
                Self::Glob {
                    family: fb,
                    matcher: mb,
                },
            ) => fa == fb && ma.glob().glob() == mb.glob().glob(),
            (
                Self::Exact {
                    family: fa,
                    nic: na,
                },
                Self::Exact {
                    family: fb,
                    nic: nb,
                },
            ) => fa == fb && na == nb,
            _ => false,
        }
    }
}

impl Eq for BindHost {}

impl fmt::Debug for BindHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip { addr, repr } => f
                .debug_struct("Ip")
                .field("addr", addr)
                .field("repr", repr)
                .finish(),
            Self::Glob { family, matcher } => f
                .debug_struct("Glob")
                .field("family", family)
                .field("pattern", &matcher.glob().glob())
                .finish(),
            Self::Exact { family, nic } => f
                .debug_struct("Exact")
                .field("family", family)
                .field("nic", nic)
                .finish(),
        }
    }
}

impl fmt::Display for BindHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
