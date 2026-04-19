use std::net::IpAddr;

use http::uri::Scheme;

use super::*;
use crate::dquic::{qbase::net::Family, qinterface::bind_uri::BindUriScheme};

// -- Parsing tests --

#[test]
fn parse_full_iface_with_family() {
    let b: Bind = "iface://v4.enp17s0:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), Some(Family::V4));
    assert_eq!(
        b.host,
        BindHost::classify("enp17s0", Some(Family::V4)).unwrap()
    );
    assert_eq!(b.port, Some(8080));
    assert!(b.path_and_query.is_none());
}

#[test]
fn parse_full_iface_glob() {
    let b: Bind = "iface://v4.en*:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), Some(Family::V4));
    assert!(b.host.is_glob());
    assert_eq!(b.host.as_str(), "en*");
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_iface_no_family() {
    let b: Bind = "iface://enp17s0:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), None);
    assert!(!b.host.is_glob());
    assert_eq!(b.host.as_str(), "enp17s0");
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_iface_no_port() {
    let b: Bind = "iface://v4.enp17s0".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), Some(Family::V4));
    assert_eq!(b.host.as_str(), "enp17s0");
    assert_eq!(b.port, None);
}

#[test]
fn parse_inet() {
    let b: Bind = "inet://127.0.0.1:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert_eq!(b.host.family(), None);
    assert_eq!(b.host.as_str(), "127.0.0.1");
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_no_scheme_ip() {
    let b: Bind = "127.0.0.1:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert_eq!(b.host.as_str(), "127.0.0.1");
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_no_scheme_iface() {
    let b: Bind = "enp17s0:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), None);
    assert_eq!(b.host.as_str(), "enp17s0");
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_no_scheme_with_family() {
    let b: Bind = "v4.enp17s0:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), Some(Family::V4));
    assert_eq!(b.host.as_str(), "enp17s0");
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_glob_no_scheme() {
    let b: Bind = "en*:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), None);
    assert!(b.host.is_glob());
    assert_eq!(b.host.as_str(), "en*");
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_star_only() {
    let b: Bind = "*".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), None);
    assert!(b.host.is_glob());
    assert_eq!(b.host.as_str(), "*");
    assert_eq!(b.port, None);
}

#[test]
fn parse_star_with_port() {
    let b: Bind = "*:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), None);
    assert!(b.host.is_glob());
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_v4_star() {
    let b: Bind = "v4.*".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), Some(Family::V4));
    assert!(b.host.is_glob());
    assert_eq!(b.port, None);
}

#[test]
fn parse_v6_star_with_port() {
    let b: Bind = "v6.*:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), Some(Family::V6));
    assert!(b.host.is_glob());
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_no_scheme_no_port() {
    let b: Bind = "enp17s0".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), None);
    assert_eq!(b.host.as_str(), "enp17s0");
    assert_eq!(b.port, None);
}

#[test]
fn parse_with_path_and_query() {
    let b: Bind = "iface://v4.en*:8080/?stun_server=stun.genmeta.net"
        .parse()
        .unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert_eq!(b.host.family(), Some(Family::V4));
    assert!(b.host.is_glob());
    assert_eq!(b.port, Some(8080));
    assert_eq!(
        b.path_and_query_str(),
        Some("/?stun_server=stun.genmeta.net")
    );
}

#[test]
fn parse_with_query_only() {
    let b: Bind = "iface://v4.enp17s0:8080?stun=true".parse().unwrap();
    assert_eq!(b.path_and_query_str(), Some("?stun=true"));
}

// -- Display round-trip --

#[test]
fn display_full() {
    let b: Bind = "iface://v4.enp17s0:8080".parse().unwrap();
    assert_eq!(b.to_string(), "iface://v4.enp17s0:8080");
}

#[test]
fn display_no_port() {
    let b: Bind = "iface://v4.enp17s0".parse().unwrap();
    assert_eq!(b.to_string(), "iface://v4.enp17s0");
}

#[test]
fn display_no_family() {
    let b: Bind = "iface://enp17s0:8080".parse().unwrap();
    assert_eq!(b.to_string(), "iface://enp17s0:8080");
}

// -- Glob matching --

#[test]
fn glob_exact_match() {
    let host = BindHost::classify("enp17s0", None).unwrap();
    assert!(host.matches("enp17s0"));
    assert!(!host.matches("wlan0"));
}

#[test]
fn glob_star_match() {
    let host = BindHost::classify("en*", None).unwrap();
    assert!(host.matches("enp17s0"));
    assert!(host.matches("eno1"));
    assert!(!host.matches("wlan0"));

    let star = BindHost::classify("*", None).unwrap();
    assert!(star.matches("anything"));
}

#[test]
fn glob_bracket_class() {
    let host = BindHost::classify("[ew]*", None).unwrap();
    assert!(host.is_glob());
    assert!(host.matches("enp17s0"));
    assert!(host.matches("wlan0"));
    assert!(!host.matches("lo"));
}

#[test]
fn glob_bracket_single() {
    let host = BindHost::classify("wlan[01]", None).unwrap();
    assert!(host.is_glob());
    assert!(host.matches("wlan0"));
    assert!(host.matches("wlan1"));
    assert!(!host.matches("wlan2"));
}

// -- Classify --

#[test]
fn classify_ipv4_as_ip() {
    let host = BindHost::classify("127.0.0.1", None).unwrap();
    assert!(host.is_ip_addr());
    assert!(!host.is_glob());
    assert_eq!(host.as_str(), "127.0.0.1");
}

#[test]
fn classify_ipv6_bracket_as_ip() {
    let host = BindHost::classify("[::1]", None).unwrap();
    assert!(host.is_ip_addr());
    assert_eq!(host.as_str(), "::1");
    assert_eq!(host.as_ip_addr().unwrap(), "::1".parse::<IpAddr>().unwrap());
}

#[test]
fn classify_bracket_non_ip_as_glob() {
    let host = BindHost::classify("[ew]", None).unwrap();
    assert!(host.is_glob());
    assert!(!host.is_ip_addr());
}

// -- Families --

#[test]
fn families_both() {
    let b: Bind = "enp17s0:8080".parse().unwrap();
    assert_eq!(b.host.families(), [Family::V4, Family::V6]);
}

#[test]
fn families_v4_only() {
    let b: Bind = "v4.enp17s0:8080".parse().unwrap();
    assert_eq!(b.host.families(), [Family::V4]);
}

// -- BindUri generation (iterators) --

#[test]
fn expand_iface() {
    let b: Bind = "iface://v4.enp17s0:8080".parse().unwrap();
    let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
    assert_eq!(uris, vec!["iface://v4.enp17s0:8080/"]);
}

#[test]
fn expand_both_families() {
    let b: Bind = "iface://enp17s0:8080".parse().unwrap();
    let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
    assert_eq!(
        uris,
        vec!["iface://v4.enp17s0:8080/", "iface://v6.enp17s0:8080/"]
    );
}

#[test]
fn expand_auto_port() {
    let b: Bind = "iface://v4.enp17s0".parse().unwrap();
    let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
    assert_eq!(uris.len(), 1);
    assert!(uris[0].starts_with("iface://v4.enp17s0:0/"));
}

#[test]
fn expand_inet() {
    let b: Bind = "127.0.0.1:8080".parse().unwrap();
    let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
    assert_eq!(uris, vec!["inet://127.0.0.1:8080/"]);
}

#[test]
fn expand_with_interfaces_glob() {
    let b: Bind = "en*:8080".parse().unwrap();
    let interfaces = ["enp17s0", "eno1", "wlan0", "lo"];
    let uris: Vec<_> = b.to_bind_uris(interfaces).collect();
    // en* matches enp17s0 and eno1, each with V4 + V6
    assert_eq!(uris.len(), 4);
}

#[test]
fn expand_with_interfaces_star() {
    let b: Bind = "*:8080".parse().unwrap();
    let interfaces = ["enp17s0", "wlan0"];
    let uris: Vec<_> = b.to_bind_uris(interfaces).collect();
    // * matches all, each with V4 + V6
    assert_eq!(uris.len(), 4);
}

#[test]
fn expand_path_and_query_passthrough() {
    let b: Bind = "iface://v4.en*:8080/?stun_server=stun.genmeta.net"
        .parse()
        .unwrap();
    let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
    assert_eq!(
        uris,
        vec!["iface://v4.enp17s0:8080/?stun_server=stun.genmeta.net"]
    );
}

#[test]
fn path_and_query_is_validated() {
    let b: Bind = "iface://v4.en*:8080/?key=value".parse().unwrap();
    let pq = b.path_and_query.as_ref().unwrap();
    assert_eq!(pq, "/?key=value");
}

// -- Bare IPv6 address tests --

#[test]
fn parse_bare_ipv6_loopback() {
    let b: Bind = "::1".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert!(b.host.is_ip_addr());
    assert_eq!(b.host.as_str(), "::1");
    assert_eq!(b.port, None);
    assert!(b.path_and_query.is_none());
}

#[test]
fn parse_bare_ipv6_any() {
    let b: Bind = "::".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert!(b.host.is_ip_addr());
    assert_eq!(b.host.as_str(), "::");
    assert_eq!(b.port, None);
}

#[test]
fn parse_bare_ipv6_full() {
    let b: Bind = "2001:db8::1".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert!(b.host.is_ip_addr());
    assert_eq!(b.host.as_str(), "2001:db8::1");
    assert_eq!(b.port, None);
}

#[test]
fn parse_bare_ipv4() {
    // Bare IPv4 without port also works via the fast path
    let b: Bind = "192.168.1.1".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert!(b.host.is_ip_addr());
    assert_eq!(b.host.as_str(), "192.168.1.1");
    assert_eq!(b.port, None);
}

#[test]
fn display_bare_ipv6() {
    let b: Bind = "::1".parse().unwrap();
    // Display wraps IPv6 in brackets
    assert_eq!(b.to_string(), "inet://[::1]");
}

#[test]
fn expand_bare_ipv6() {
    let b: Bind = "::1".parse().unwrap();
    let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
    assert_eq!(uris.len(), 1);
    assert!(uris[0].starts_with("inet://[::1]:0/"));
}

// -- Glob bracket parsing --

#[test]
fn parse_glob_bracket_class() {
    let b: Bind = "[ew]*:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Iface);
    assert!(b.host.is_glob());
    assert_eq!(b.host.as_str(), "[ew]*");
    assert_eq!(b.port, Some(8080));
}

// -- IPv6 bracket syntax tests --

#[test]
fn parse_ipv6_full_scheme() {
    let b: Bind = "inet://[::1]:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert_eq!(b.host.family(), None);
    assert_eq!(b.host.as_str(), "::1");
    assert_eq!(b.port, Some(8080));
    assert!(b.host.is_ip_addr());
}

#[test]
fn parse_ipv6_no_scheme() {
    let b: Bind = "[::1]:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert_eq!(b.host.as_str(), "::1");
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_ipv6_full_addr() {
    let b: Bind = "inet://[2001:db8::1]:443".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert_eq!(b.host.as_str(), "2001:db8::1");
    assert_eq!(b.port, Some(443));
    assert!(b.host.is_ip_addr());
}

#[test]
fn parse_ipv6_link_local() {
    let b: Bind = "[fe80::1]:8080".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert_eq!(b.host.as_str(), "fe80::1");
    assert_eq!(b.port, Some(8080));
}

#[test]
fn parse_ipv6_any() {
    let b: Bind = "inet://[::]:0".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert_eq!(b.host.as_str(), "::");
    assert_eq!(b.port, Some(0));
}

#[test]
fn parse_ipv6_no_port() {
    let b: Bind = "[::1]".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert_eq!(b.host.as_str(), "::1");
    assert_eq!(b.port, None);
}

#[test]
fn parse_ipv6_with_path_and_query() {
    let b: Bind = "inet://[::1]:8080/?key=value".parse().unwrap();
    assert_eq!(b.scheme, BindUriScheme::Inet);
    assert_eq!(b.host.as_str(), "::1");
    assert_eq!(b.port, Some(8080));
    assert_eq!(b.path_and_query_str(), Some("/?key=value"));
}

#[test]
fn display_ipv6_roundtrip() {
    let input = "inet://[::1]:8080";
    let b: Bind = input.parse().unwrap();
    assert_eq!(b.to_string(), input);
}

#[test]
fn display_ipv6_full_addr() {
    let b: Bind = "inet://[2001:db8::1]:443".parse().unwrap();
    assert_eq!(b.to_string(), "inet://[2001:db8::1]:443");
}

#[test]
fn expand_ipv6() {
    let b: Bind = "inet://[::1]:8080".parse().unwrap();
    let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
    assert_eq!(uris, vec!["inet://[::1]:8080/"]);
}

#[test]
fn expand_ipv6_auto_port() {
    let b: Bind = "[::1]".parse().unwrap();
    let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
    assert_eq!(uris.len(), 1);
    assert!(uris[0].starts_with("inet://[::1]:0/"));
}

#[test]
fn family_ip_rejected() {
    // v4.127.0.0.1 is not a valid bind pattern
    assert!("v4.127.0.0.1:8080".parse::<Bind>().is_err());
    assert!("inet://v6.[::1]:8080".parse::<Bind>().is_err());
}

#[test]
fn ipv6_host_is_ip_addr() {
    let b: Bind = "[::1]:8080".parse().unwrap();
    assert!(b.host.is_ip_addr());
    assert!(b.host.as_ip_addr().unwrap().is_ipv6());
}

// -- Binds tests --

#[test]
fn binds_new_and_deref() {
    let v = vec![
        "iface://v4.enp17s0:8080".parse::<Bind>().unwrap(),
        "127.0.0.1:443".parse::<Bind>().unwrap(),
    ];
    let binds = Binds::new(v.clone());
    // Deref to &[Bind]
    assert_eq!(binds.len(), 2);
    assert_eq!(&*binds, &v[..]);
}

#[test]
fn binds_deref_mut() {
    let mut binds = Binds::new(vec!["*:8080".parse().unwrap()]);
    binds.push("127.0.0.1:443".parse().unwrap());
    assert_eq!(binds.len(), 2);
}

#[test]
fn binds_from_into_vec() {
    let v = vec!["*:8080".parse::<Bind>().unwrap()];
    let binds: Binds = v.clone().into();
    let out: Vec<Bind> = binds.into();
    assert_eq!(out, v);
}

#[test]
fn binds_to_bind_uris_no_conflict() {
    let binds = Binds::new(vec![
        "iface://v4.enp17s0:8080".parse().unwrap(),
        "127.0.0.1:443".parse().unwrap(),
    ]);
    let uris = binds.to_bind_uris(["enp17s0"]).unwrap();
    assert_eq!(uris.len(), 2);
}

#[test]
fn binds_to_bind_uris_dedup() {
    // Two identical binds should produce only one URI
    let binds = Binds::new(vec![
        "127.0.0.1:8080".parse().unwrap(),
        "inet://127.0.0.1:8080".parse().unwrap(),
    ]);
    let uris = binds.to_bind_uris([]).unwrap();
    assert_eq!(uris.len(), 1);
}

#[test]
fn binds_to_bind_uris_conflict_different_pq() {
    // Same target, different path-and-query → conflict
    let binds = Binds::new(vec![
        "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
        "iface://v4.enp17s0:8080/?stun=false".parse().unwrap(),
    ]);
    let err = binds.to_bind_uris(["enp17s0"]).unwrap_err();
    assert_eq!(err.scheme, "iface".parse::<Scheme>().unwrap());
    assert!(err.to_string().contains("conflicting"));
    assert!(err.to_string().contains("stun=true"));
    assert!(err.to_string().contains("stun=false"));
}

#[test]
fn binds_to_bind_uris_conflict_pq_vs_none() {
    // Same target: one with path-and-query, one without → conflict
    let binds = Binds::new(vec![
        "iface://v4.enp17s0:8080".parse().unwrap(),
        "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
    ]);
    let err = binds.to_bind_uris(["enp17s0"]).unwrap_err();
    assert!(err.to_string().contains("conflicting"));
    assert!(err.existing.is_none());
    assert!(err.incoming.is_some());
}

#[test]
fn binds_to_bind_uris_same_pq_dedup() {
    // Same target, same path-and-query → deduplicated, no conflict
    let binds = Binds::new(vec![
        "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
        "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
    ]);
    let uris = binds.to_bind_uris(["enp17s0"]).unwrap();
    assert_eq!(uris.len(), 1);
}

#[test]
fn binds_to_bind_uris_glob_conflict() {
    // Glob expanding to same interface with different pq
    let binds = Binds::new(vec![
        "v4.en*:8080/?a=1".parse().unwrap(),
        "v4.enp17s0:8080/?a=2".parse().unwrap(),
    ]);
    let err = binds.to_bind_uris(["enp17s0"]).unwrap_err();
    assert!(err.to_string().contains("conflicting"));
}

#[test]
fn binds_to_bind_uris_different_targets_ok() {
    // Different targets with different pq → no conflict
    let binds = Binds::new(vec![
        "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
        "iface://v6.enp17s0:8080/?stun=false".parse().unwrap(),
    ]);
    let uris = binds.to_bind_uris(["enp17s0"]).unwrap();
    assert_eq!(uris.len(), 2);
}

#[test]
fn binds_conflict_error_display() {
    let err = BindConflictError {
        scheme: "iface".parse().unwrap(),
        authority: "v4.enp17s0:8080".parse().unwrap(),
        existing: Some("/?stun=true".parse().unwrap()),
        incoming: Some("/?stun=false".parse().unwrap()),
    };
    assert_eq!(
        err.to_string(),
        "conflicting bindings exist for bind target `iface://v4.enp17s0:8080`: `/?stun=true` vs `/?stun=false`"
    );
}

#[test]
fn binds_conflict_error_display_none_pq() {
    let err = BindConflictError {
        scheme: "inet".parse().unwrap(),
        authority: "127.0.0.1:8080".parse().unwrap(),
        existing: None,
        incoming: Some("/?key=val".parse().unwrap()),
    };
    assert_eq!(
        err.to_string(),
        "conflicting bindings exist for bind target `inet://127.0.0.1:8080`: `/` vs `/?key=val`"
    );
}
