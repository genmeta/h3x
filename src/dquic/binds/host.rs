use std::{
    fmt,
    hash::{Hash, Hasher},
    net::IpAddr,
};

use globset::{Glob, GlobMatcher};

use crate::dquic::qbase::net::Family;

/// The host part of a [`BindPattern`](super::BindPattern) — a parsed IP address, a glob pattern, or an exact name.
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

impl Hash for BindHost {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::Ip { repr, .. } => repr.hash(state),
            Self::Glob {
                family, matcher, ..
            } => {
                family.hash(state);
                matcher.glob().glob().hash(state);
            }
            Self::Exact { family, nic, .. } => {
                family.hash(state);
                nic.hash(state);
            }
        }
    }
}

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

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use super::*;
    use crate::dquic::qbase::net::Family;

    fn hash(host: &BindHost) -> u64 {
        let mut hasher = DefaultHasher::new();
        host.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn classify_ip_and_glob_variants() {
        let ipv4 = BindHost::classify("127.0.0.1", None).unwrap();
        assert!(ipv4.is_ip_addr());
        assert!(!ipv4.is_glob());
        assert_eq!(ipv4.as_str(), "127.0.0.1");
        assert_eq!(ipv4.as_ip_addr(), Some("127.0.0.1".parse().unwrap()));

        let ipv6 = BindHost::classify("[::1]", None).unwrap();
        assert!(ipv6.is_ip_addr());
        assert_eq!(ipv6.as_str(), "::1");
        assert_eq!(ipv6.families(), [Family::V4, Family::V6]);

        let glob = BindHost::classify("en*", None).unwrap();
        assert!(!glob.is_ip_addr());
        assert!(glob.is_glob());
        assert_eq!(glob.as_str(), "en*");
        assert_eq!(glob.families(), [Family::V4, Family::V6]);
    }

    #[test]
    fn classify_rejects_family_for_ip_and_falls_back_to_exact_on_bad_glob() {
        let err = BindHost::classify("127.0.0.1", Some(Family::V4))
            .expect_err("family prefix should be rejected for plain IP address");
        assert_eq!(err, "family prefix is not valid for IP addresses");

        let err = BindHost::classify("[::1]", Some(Family::V6))
            .expect_err("family prefix should be rejected for bracketed IPv6");
        assert_eq!(err, "family prefix is not valid for IP addresses");

        let exact = BindHost::classify("[", None).unwrap();
        assert!(matches!(exact, BindHost::Exact { family: None, ref nic } if nic == "["));
        assert!(!exact.is_glob());
        assert_eq!(exact.family(), None);
        assert_eq!(exact.families(), [Family::V4, Family::V6]);
    }

    #[test]
    fn host_matching_and_identity_accessors() {
        let exact = BindHost::classify("enp17s0", Some(Family::V4)).unwrap();
        assert_eq!(exact.family(), Some(Family::V4));
        assert_eq!(exact.as_str(), "enp17s0");
        assert!(!exact.matches("eth0"));
        assert!(exact.matches("enp17s0"));

        let ip = BindHost::classify("192.168.0.1", None).unwrap();
        assert!(ip.is_ip_addr());
        assert_eq!(ip.as_ip_addr().unwrap().to_string(), "192.168.0.1");
        assert!(!ip.matches("192.168.0.1"));
    }

    #[test]
    fn exact_host_with_v6_family_matches_and_compares_by_family() {
        let exact = BindHost::classify("[", Some(Family::V6)).unwrap();
        assert_eq!(exact.family(), Some(Family::V6));
        assert_eq!(exact.families(), [Family::V6]);
        assert!(exact.matches("["));
        assert!(!exact.matches("]"));
        assert_eq!(exact, BindHost::classify("[", Some(Family::V6)).unwrap());
        assert_ne!(exact, BindHost::classify("[", Some(Family::V4)).unwrap());
    }

    #[test]
    fn host_display_debug_and_hash() {
        let literal = BindHost::classify("enp17s0", None).unwrap();
        assert_eq!(format!("{literal}"), "enp17s0");
        assert!(
            matches!(&format!("{literal:?}"), s if s.contains("Glob") && s.contains("pattern"))
        );
        assert_eq!(
            hash(&literal),
            hash(&BindHost::classify("enp17s0", None).unwrap())
        );

        let exact = BindHost::classify("[", None).unwrap();
        assert_eq!(format!("{exact}"), "[");
        assert_eq!(exact.as_str(), "[");
        assert!(matches!(&format!("{exact:?}"), s if s.contains("Exact") && s.contains("nic")));
        assert_eq!(hash(&exact), hash(&BindHost::classify("[", None).unwrap()));

        let ip = BindHost::classify("::1", None).unwrap();
        let ip_debug = format!("{ip:?}");
        assert!(ip_debug.contains("Ip"));
        assert!(ip_debug.contains("addr"));
        assert!(ip_debug.contains("repr"));
        assert_eq!(format!("{ip}"), "::1");
        assert_eq!(hash(&ip), hash(&BindHost::classify("::1", None).unwrap()));
    }

    #[test]
    fn partial_eq_for_all_variants() {
        let exact_a = BindHost::classify("[", None).unwrap();
        let exact_b = BindHost::classify("[", None).unwrap();
        assert_eq!(exact_a, exact_b);

        let exact_c = BindHost::classify("[", Some(Family::V4)).unwrap();
        assert_ne!(exact_a, exact_c);

        let glob_a = BindHost::classify("en*", None).unwrap();
        let glob_b = BindHost::classify("en*", Some(Family::V6)).unwrap();
        assert_ne!(glob_a, glob_b);
        assert_eq!(glob_a, BindHost::classify("en*", None).unwrap());

        let ip_a = BindHost::classify("::1", None).unwrap();
        let ip_b = BindHost::classify("::1", None).unwrap();
        let ipv4 = BindHost::classify("127.0.0.1", None).unwrap();
        assert_eq!(ip_a, ip_b);
        assert_ne!(ip_a, ipv4);
    }
}
