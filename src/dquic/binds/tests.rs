#![allow(clippy::type_complexity)]

use std::net::IpAddr;

use super::*;
use crate::dquic::{
    net::Family,
    qinterface::bind_uri::{BindUri, Scheme},
};

// ============================================================================
// Parsing — core parsing tests (from original "Parsing tests" section +
// glob bracket parsing + path_and_query validation)
// ============================================================================

#[test]
fn parsing_core() {
    let cases: Vec<(&str, Box<dyn Fn(&BindPattern)>)> = vec![
        // parse_full_iface_with_family
        (
            "iface://v4.enp17s0:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), Some(Family::V4));
                assert_eq!(
                    b.host,
                    BindHost::classify("enp17s0", Some(Family::V4)).unwrap()
                );
                assert_eq!(b.port, Some(8080));
                assert!(b.path_and_query.is_none());
            }),
        ),
        // parse_full_iface_glob
        (
            "iface://v4.en*:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), Some(Family::V4));
                assert!(b.host.is_glob());
                assert_eq!(b.host.as_str(), "en*");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_iface_no_family
        (
            "iface://enp17s0:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), None);
                assert!(!b.host.is_glob());
                assert_eq!(b.host.as_str(), "enp17s0");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_iface_no_port
        (
            "iface://v4.enp17s0",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), Some(Family::V4));
                assert_eq!(b.host.as_str(), "enp17s0");
                assert_eq!(b.port, None);
            }),
        ),
        // parse_inet
        (
            "inet://127.0.0.1:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert_eq!(b.host.family(), None);
                assert_eq!(b.host.as_str(), "127.0.0.1");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_no_scheme_ip
        (
            "127.0.0.1:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert_eq!(b.host.as_str(), "127.0.0.1");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_no_scheme_iface
        (
            "enp17s0:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), None);
                assert_eq!(b.host.as_str(), "enp17s0");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_no_scheme_with_family
        (
            "v4.enp17s0:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), Some(Family::V4));
                assert_eq!(b.host.as_str(), "enp17s0");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_glob_no_scheme
        (
            "en*:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), None);
                assert!(b.host.is_glob());
                assert_eq!(b.host.as_str(), "en*");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_star_only
        (
            "*",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), None);
                assert!(b.host.is_glob());
                assert_eq!(b.host.as_str(), "*");
                assert_eq!(b.port, None);
            }),
        ),
        // parse_star_with_port
        (
            "*:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), None);
                assert!(b.host.is_glob());
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_v4_star
        (
            "v4.*",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), Some(Family::V4));
                assert!(b.host.is_glob());
                assert_eq!(b.port, None);
            }),
        ),
        // parse_v6_star_with_port
        (
            "v6.*:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), Some(Family::V6));
                assert!(b.host.is_glob());
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_no_scheme_no_port
        (
            "enp17s0",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), None);
                assert_eq!(b.host.as_str(), "enp17s0");
                assert_eq!(b.port, None);
            }),
        ),
        // parse_with_path_and_query
        (
            "iface://v4.en*:8080/?stun_server=stun.genmeta.net",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert_eq!(b.host.family(), Some(Family::V4));
                assert!(b.host.is_glob());
                assert_eq!(b.port, Some(8080));
                assert_eq!(
                    b.path_and_query_str(),
                    Some("/?stun_server=stun.genmeta.net")
                );
            }),
        ),
        // parse_with_query_only
        (
            "iface://v4.enp17s0:8080?stun=true",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.path_and_query_str(), Some("?stun=true"));
            }),
        ),
        // parse_glob_bracket_class (from "Glob bracket parsing" section)
        (
            "[ew]*:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Iface);
                assert!(b.host.is_glob());
                assert_eq!(b.host.as_str(), "[ew]*");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // path_and_query_is_validated (from "BindUri generation" section)
        (
            "iface://v4.en*:8080/?key=value",
            Box::new(|b: &BindPattern| {
                let pq = b.path_and_query.as_ref().unwrap();
                assert_eq!(pq, "/?key=value");
            }),
        ),
    ];

    for (input, check) in &cases {
        let b: BindPattern = input
            .parse()
            .unwrap_or_else(|e| panic!("failed to parse '{input}': {e}"));
        check(&b);
    }
}

// ============================================================================
// Parsing — IPv6 bracket syntax tests
// ============================================================================

#[test]
fn parsing_ipv6_bracket() {
    let cases: Vec<(&str, Box<dyn Fn(&BindPattern)>)> = vec![
        // parse_ipv6_full_scheme
        (
            "inet://[::1]:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert_eq!(b.host.family(), None);
                assert_eq!(b.host.as_str(), "::1");
                assert_eq!(b.port, Some(8080));
                assert!(b.host.is_ip_addr());
            }),
        ),
        // parse_ipv6_no_scheme
        (
            "[::1]:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert_eq!(b.host.as_str(), "::1");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_ipv6_full_addr
        (
            "inet://[2001:db8::1]:443",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert_eq!(b.host.as_str(), "2001:db8::1");
                assert_eq!(b.port, Some(443));
                assert!(b.host.is_ip_addr());
            }),
        ),
        // parse_ipv6_link_local
        (
            "[fe80::1]:8080",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert_eq!(b.host.as_str(), "fe80::1");
                assert_eq!(b.port, Some(8080));
            }),
        ),
        // parse_ipv6_any
        (
            "inet://[::]:0",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert_eq!(b.host.as_str(), "::");
                assert_eq!(b.port, Some(0));
            }),
        ),
        // parse_ipv6_no_port
        (
            "[::1]",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert_eq!(b.host.as_str(), "::1");
                assert_eq!(b.port, None);
            }),
        ),
        // parse_ipv6_with_path_and_query
        (
            "inet://[::1]:8080/?key=value",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert_eq!(b.host.as_str(), "::1");
                assert_eq!(b.port, Some(8080));
                assert_eq!(b.path_and_query_str(), Some("/?key=value"));
            }),
        ),
        // ipv6_host_is_ip_addr
        (
            "[::1]:8080",
            Box::new(|b: &BindPattern| {
                assert!(b.host.is_ip_addr());
                assert!(b.host.as_ip_addr().unwrap().is_ipv6());
            }),
        ),
    ];

    for (input, check) in &cases {
        let b: BindPattern = input
            .parse()
            .unwrap_or_else(|e| panic!("failed to parse '{input}': {e}"));
        check(&b);
    }
}

// ============================================================================
// Parsing — bare IP address tests
// ============================================================================

#[test]
fn parsing_bare_ip() {
    let cases: Vec<(&str, Box<dyn Fn(&BindPattern)>)> = vec![
        // parse_bare_ipv6_loopback
        (
            "::1",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert!(b.host.is_ip_addr());
                assert_eq!(b.host.as_str(), "::1");
                assert_eq!(b.port, None);
                assert!(b.path_and_query.is_none());
            }),
        ),
        // parse_bare_ipv6_any
        (
            "::",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert!(b.host.is_ip_addr());
                assert_eq!(b.host.as_str(), "::");
                assert_eq!(b.port, None);
            }),
        ),
        // parse_bare_ipv6_full
        (
            "2001:db8::1",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert!(b.host.is_ip_addr());
                assert_eq!(b.host.as_str(), "2001:db8::1");
                assert_eq!(b.port, None);
            }),
        ),
        // parse_bare_ipv4
        (
            "192.168.1.1",
            Box::new(|b: &BindPattern| {
                assert_eq!(b.scheme, Scheme::Inet);
                assert!(b.host.is_ip_addr());
                assert_eq!(b.host.as_str(), "192.168.1.1");
                assert_eq!(b.port, None);
            }),
        ),
    ];

    for (input, check) in &cases {
        let b: BindPattern = input
            .parse()
            .unwrap_or_else(|e| panic!("failed to parse '{input}': {e}"));
        check(&b);
    }
}

// ============================================================================
// Display roundtrip
// ============================================================================

#[test]
fn display_roundtrip() {
    let cases: &[(&str, &str)] = &[
        // display_full
        ("iface://v4.enp17s0:8080", "iface://v4.enp17s0:8080"),
        // display_normalizes_uppercase_family
        (
            "iface://V6.enp17s0:8080?reuse=true",
            "iface://v6.enp17s0:8080/?reuse=true",
        ),
        // display_no_port
        ("iface://v4.enp17s0", "iface://v4.enp17s0"),
        // display_no_family
        ("iface://enp17s0:8080", "iface://enp17s0:8080"),
        // display_bare_ipv6
        ("::1", "inet://[::1]"),
        // display_ipv6_roundtrip
        ("inet://[::1]:8080", "inet://[::1]:8080"),
        // display_ipv6_full_addr
        ("inet://[2001:db8::1]:443", "inet://[2001:db8::1]:443"),
    ];

    for (input, expected) in cases {
        let b: BindPattern = input
            .parse()
            .unwrap_or_else(|e| panic!("failed to parse '{input}': {e}"));
        assert_eq!(b.to_string(), *expected, "display mismatch for '{input}'");
    }
}

// ============================================================================
// Glob matching
// ============================================================================

#[test]
fn glob_matching() {
    // glob_exact_match
    {
        let host = BindHost::classify("enp17s0", None).unwrap();
        assert!(host.matches("enp17s0"));
        assert!(!host.matches("wlan0"));
    }

    // glob_star_match
    {
        let host = BindHost::classify("en*", None).unwrap();
        assert!(host.matches("enp17s0"));
        assert!(host.matches("eno1"));
        assert!(!host.matches("wlan0"));

        let star = BindHost::classify("*", None).unwrap();
        assert!(star.matches("anything"));
    }

    // glob_bracket_class
    {
        let host = BindHost::classify("[ew]*", None).unwrap();
        assert!(host.is_glob());
        assert!(host.matches("enp17s0"));
        assert!(host.matches("wlan0"));
        assert!(!host.matches("lo"));
    }

    // glob_bracket_single
    {
        let host = BindHost::classify("wlan[01]", None).unwrap();
        assert!(host.is_glob());
        assert!(host.matches("wlan0"));
        assert!(host.matches("wlan1"));
        assert!(!host.matches("wlan2"));
    }
}

// ============================================================================
// Classify
// ============================================================================

#[test]
fn classify() {
    // classify_ipv4_as_ip
    {
        let host = BindHost::classify("127.0.0.1", None).unwrap();
        assert!(host.is_ip_addr());
        assert!(!host.is_glob());
        assert_eq!(host.as_str(), "127.0.0.1");
    }

    // classify_ipv6_bracket_as_ip
    {
        let host = BindHost::classify("[::1]", None).unwrap();
        assert!(host.is_ip_addr());
        assert_eq!(host.as_str(), "::1");
        assert_eq!(host.as_ip_addr().unwrap(), "::1".parse::<IpAddr>().unwrap());
    }

    // classify_bracket_non_ip_as_glob
    {
        let host = BindHost::classify("[ew]", None).unwrap();
        assert!(host.is_glob());
        assert!(!host.is_ip_addr());
    }
}

// ============================================================================
// Families
// ============================================================================

#[test]
fn families() {
    // families_both
    {
        let b: BindPattern = "enp17s0:8080".parse().unwrap();
        assert_eq!(b.host.families(), [Family::V4, Family::V6]);
    }

    // families_v4_only
    {
        let b: BindPattern = "v4.enp17s0:8080".parse().unwrap();
        assert_eq!(b.host.families(), [Family::V4]);
    }
}

// ============================================================================
// Expand — basic BindUri generation
// ============================================================================

#[test]
fn expand_basic() {
    // expand_iface
    {
        let b: BindPattern = "iface://v4.enp17s0:8080".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
        assert_eq!(uris, vec!["iface://v4.enp17s0:8080/"]);
    }

    // expand_both_families
    {
        let b: BindPattern = "iface://enp17s0:8080".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
        assert_eq!(
            uris,
            vec!["iface://v4.enp17s0:8080/", "iface://v6.enp17s0:8080/"]
        );
    }

    // expand_auto_port
    {
        let b: BindPattern = "iface://v4.enp17s0".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("iface://v4.enp17s0:0/"));
    }

    // expand_inet
    {
        let b: BindPattern = "127.0.0.1:8080".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
        assert_eq!(uris, vec!["inet://127.0.0.1:8080/"]);
    }

    // expand_path_and_query_passthrough
    {
        let b: BindPattern = "iface://v4.en*:8080/?stun_server=stun.genmeta.net"
            .parse()
            .unwrap();
        let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
        assert_eq!(
            uris,
            vec!["iface://v4.enp17s0:8080/?stun_server=stun.genmeta.net"]
        );
    }
}

// ============================================================================
// Expand — glob patterns
// ============================================================================

#[test]
fn expand_glob() {
    // expand_with_interfaces_glob
    {
        let b: BindPattern = "en*:8080".parse().unwrap();
        let interfaces = ["enp17s0", "eno1", "wlan0", "lo"];
        let uris: Vec<_> = b.to_bind_uris(interfaces).collect();
        // en* matches enp17s0 and eno1, each with V4 + V6
        assert_eq!(uris.len(), 4);
    }

    // expand_with_interfaces_star
    {
        let b: BindPattern = "*:8080".parse().unwrap();
        let interfaces = ["enp17s0", "wlan0"];
        let uris: Vec<_> = b.to_bind_uris(interfaces).collect();
        // * matches all, each with V4 + V6
        assert_eq!(uris.len(), 4);
    }
}

// ============================================================================
// Expand — IPv6
// ============================================================================

#[test]
fn expand_ipv6() {
    // expand_bare_ipv6
    {
        let b: BindPattern = "::1".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("inet://[::1]:0/"));
    }

    // expand_ipv6 (from "IPv6 bracket syntax tests" section)
    {
        let b: BindPattern = "inet://[::1]:8080".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
        assert_eq!(uris, vec!["inet://[::1]:8080/"]);
    }

    // expand_ipv6_auto_port
    {
        let b: BindPattern = "[::1]".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("inet://[::1]:0/"));
    }
}

#[test]
fn ipv6_ip_pattern_matches_generated_bind_uri() {
    let pattern: BindPattern = "inet://[::]:4433".parse().unwrap();
    let bind_uri: BindUri = "inet://[::]:4433".parse().unwrap();

    assert!(pattern.matches(&bind_uri));
}

// ============================================================================
// Errors
// ============================================================================

#[test]
fn parse_errors() {
    // family_ip_rejected
    assert!(
        "v4.127.0.0.1:8080".parse::<BindPattern>().is_err(),
        "family prefix should be rejected for IP addresses"
    );
    assert!(
        "inet://v6.[::1]:8080".parse::<BindPattern>().is_err(),
        "family prefix should be rejected for IP addresses"
    );
    assert!(
        "iface://enp17s0:70000".parse::<BindPattern>().is_err(),
        "ports above u16::MAX should be rejected"
    );
}

#[test]
fn iface_pattern_matches_generated_bind_uri() {
    let pattern: BindPattern = "iface://v4.en*:8080".parse().unwrap();
    let generated = pattern
        .to_bind_uris(["enp17s0"])
        .next()
        .expect("pattern should generate one bind uri");

    assert!(
        pattern.matches(&generated),
        "pattern {pattern} should match generated bind uri {generated}"
    );
}

#[test]
fn iface_pattern_matches_family_interface_and_port_separately() {
    let pattern: BindPattern = "iface://v4.en*:8080".parse().unwrap();

    assert!(pattern.matches(&"iface://v4.enp17s0:8080".parse().unwrap()));
    assert!(!pattern.matches(&"iface://v6.enp17s0:8080".parse().unwrap()));
    assert!(!pattern.matches(&"iface://v4.wlan0:8080".parse().unwrap()));
    assert!(!pattern.matches(&"iface://v4.enp17s0:8081".parse().unwrap()));

    let wildcard_family_and_port: BindPattern = "iface://en*".parse().unwrap();
    assert!(wildcard_family_and_port.matches(&"iface://v6.eno1:4433".parse().unwrap()));
}

#[test]
fn inet_pattern_matches_ip_address_and_port_only() {
    let pattern: BindPattern = "inet://127.0.0.1:8080".parse().unwrap();

    assert!(pattern.matches(&"inet://127.0.0.1:8080".parse().unwrap()));
    assert!(!pattern.matches(&"inet://127.0.0.1:8081".parse().unwrap()));
    assert!(!pattern.matches(&"inet://127.0.0.2:8080".parse().unwrap()));

    let non_ip_pattern: BindPattern = "inet://*:8080".parse().unwrap();
    assert!(!non_ip_pattern.matches(&"inet://127.0.0.1:8080".parse().unwrap()));
}

#[test]
fn wildcard_port_matches_any_actual_port_for_supported_schemes() {
    let iface_pattern: BindPattern = "iface://v4.en*".parse().unwrap();
    assert!(iface_pattern.matches(&"iface://v4.enp17s0:0".parse().unwrap()));
    assert!(iface_pattern.matches(&"iface://v4.enp17s0:4433".parse().unwrap()));

    let inet_pattern: BindPattern = "inet://127.0.0.1".parse().unwrap();
    assert!(inet_pattern.matches(&"inet://127.0.0.1:0".parse().unwrap()));
    assert!(inet_pattern.matches(&"inet://127.0.0.1:4433".parse().unwrap()));
}
