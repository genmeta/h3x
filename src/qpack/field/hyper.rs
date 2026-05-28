use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderName, Request, Response, Uri, Version, request, response};
use snafu::OptionExt;

use super::{
    FieldLine, FieldSection, MalformedHeaderSection, Protocol, PseudoHeaders,
    malformed_header_section,
};

impl From<hyper::ext::Protocol> for FieldLine {
    fn from(protocol: hyper::ext::Protocol) -> Self {
        FieldLine {
            name: Bytes::from_static(PseudoHeaders::PROTOOCL.as_bytes()),
            value: Bytes::from_owner(protocol),
        }
    }
}

pub fn header_map_to_field_lines(headers: http::HeaderMap) -> impl Iterator<Item = FieldLine> {
    headers
        .into_iter()
        .scan(None::<HeaderName>, |last_name, (name, value)| {
            let name = match name {
                Some(name) => {
                    *last_name = Some(name.clone());
                    name
                }
                None => match last_name.clone() {
                    Some(name) => name,
                    None => return Some(None),
                },
            };

            Some(Some(FieldLine {
                name: Bytes::from_owner(name),
                value: Bytes::from_owner(value),
            }))
        })
        .flatten()
}

pub(crate) fn validated_hyper_request_parts_to_field_lines(
    parts: http::request::Parts,
) -> Result<Vec<FieldLine>, MalformedHeaderSection> {
    let section = FieldSection::from(parts);
    section.check_pseudo()?;
    Ok(section.iter().collect())
}

pub fn hyper_response_parts_to_field_lines(
    parts: http::response::Parts,
) -> impl Iterator<Item = FieldLine> {
    let pseudo_headers = [Some(FieldLine::from(parts.status))];

    pseudo_headers
        .into_iter()
        .flatten()
        .chain(header_map_to_field_lines(parts.headers))
}

impl From<request::Parts> for FieldSection {
    fn from(mut request: request::Parts) -> Self {
        let mut pseudo = PseudoHeaders::request(request.method, request.uri);
        if let Some(p) = request.extensions.remove::<Protocol>()
            && let PseudoHeaders::Request { protocol, .. } = &mut pseudo
        {
            protocol.replace(p);
        } else if let Some(p) = request.extensions.remove::<::hyper::ext::Protocol>()
            && let PseudoHeaders::Request { protocol, .. } = &mut pseudo
        {
            protocol.replace(Protocol {
                token: Bytes::from_owner(p),
            });
        }

        Self {
            pseudo_headers: Some(pseudo),
            header_map: Arc::new(request.headers),
        }
    }
}

impl TryFrom<FieldSection> for request::Parts {
    type Error = MalformedHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        value.check_pseudo()?;

        let FieldSection {
            pseudo_headers,
            header_map,
        } = value;
        let PseudoHeaders::Request {
            method,
            scheme,
            authority,
            path,
            protocol,
        } = pseudo_headers
            .context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?
        else {
            return Err(MalformedHeaderSection::ResponsePseudoHeaderInRequest);
        };

        let mut uri = Uri::builder();
        if let Some(scheme) = scheme {
            uri = uri.scheme(scheme);
        }
        if let Some(authority) = authority {
            uri = uri.authority(authority)
        }
        if let Some(path) = path {
            uri = uri.path_and_query(path);
        }
        let uri = uri.build()?;
        let method =
            method.context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?;

        let mut request = Request::builder()
            .uri(uri)
            .method(method)
            .version(Version::HTTP_3)
            .body(())?;
        *request.headers_mut() =
            Arc::try_unwrap(header_map).unwrap_or_else(|header_map| (*header_map).clone());

        if let Some(protocol) = protocol {
            request.extensions_mut().insert(protocol);
        }

        Ok(request.into_parts().0)
    }
}

impl From<response::Parts> for FieldSection {
    fn from(response: response::Parts) -> Self {
        Self {
            pseudo_headers: Some(PseudoHeaders::response(response.status)),
            header_map: Arc::new(response.headers),
        }
    }
}

impl TryFrom<FieldSection> for response::Parts {
    type Error = MalformedHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        let FieldSection {
            pseudo_headers,
            header_map,
        } = value;
        let PseudoHeaders::Response { status } = pseudo_headers
            .context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?
        else {
            return Err(MalformedHeaderSection::RequestPseudoHeaderInResponse);
        };

        let status =
            status.context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?;
        let mut response = Response::builder()
            .status(status)
            .version(Version::HTTP_3)
            .body(())?;
        *response.headers_mut() =
            Arc::try_unwrap(header_map).unwrap_or_else(|header_map| (*header_map).clone());
        Ok(response.into_parts().0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyper_protocol_and_repeated_headers_convert_to_field_lines() {
        let protocol_line = FieldLine::from(::hyper::ext::Protocol::from_static("websocket"));
        assert_eq!(protocol_line.name, Bytes::from_static(b":protocol"));
        assert_eq!(protocol_line.value, Bytes::from_static(b"websocket"));

        let mut headers = http::HeaderMap::new();
        headers.append("x-repeat", http::HeaderValue::from_static("one"));
        headers.append("x-repeat", http::HeaderValue::from_static("two"));
        headers.insert("x-single", http::HeaderValue::from_static("solo"));

        let lines = header_map_to_field_lines(headers).collect::<Vec<_>>();

        assert_eq!(
            lines
                .iter()
                .filter(|line| line.name == Bytes::from_static(b"x-repeat"))
                .map(|line| line.value.clone())
                .collect::<Vec<_>>(),
            vec![Bytes::from_static(b"one"), Bytes::from_static(b"two")]
        );
        assert!(lines.iter().any(|line| {
            line.name == Bytes::from_static(b"x-single")
                && line.value == Bytes::from_static(b"solo")
        }));
    }

    #[test]
    fn request_parts_conversion_preserves_hyper_protocol_extension() {
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/session")
            .body(())
            .unwrap();
        request
            .extensions_mut()
            .insert(::hyper::ext::Protocol::from_static("websocket"));
        let (parts, ()) = request.into_parts();

        let section = FieldSection::from(parts);

        let PseudoHeaders::Request {
            protocol: Some(protocol),
            ..
        } = section.pseudo_headers.expect("request pseudo headers")
        else {
            panic!("expected request protocol pseudo header");
        };
        assert_eq!(protocol, Protocol::new("websocket"));
    }

    #[test]
    fn request_parts_try_from_preserves_authority_protocol_and_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static("ok"));
        let section = FieldSection::header(
            PseudoHeaders::Request {
                method: Some(http::Method::CONNECT),
                scheme: Some(http::uri::Scheme::HTTPS),
                authority: Some("example.test".parse().unwrap()),
                path: Some("/session".parse().unwrap()),
                protocol: Some(Protocol::new("webtransport")),
            },
            headers,
        );

        let parts = http::request::Parts::try_from(section).unwrap();

        assert_eq!(parts.method, http::Method::CONNECT);
        assert_eq!(parts.uri, "https://example.test/session");
        assert_eq!(parts.version, http::Version::HTTP_3);
        assert_eq!(parts.headers.get("x-test").unwrap(), "ok");
        assert_eq!(
            parts.extensions.get::<Protocol>(),
            Some(&Protocol::new("webtransport"))
        );
    }

    #[test]
    fn request_parts_try_from_clones_shared_header_map_and_rejects_trailers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-shared", http::HeaderValue::from_static("ok"));
        let section = FieldSection::header(
            PseudoHeaders::Request {
                method: Some(http::Method::GET),
                scheme: Some(http::uri::Scheme::HTTPS),
                authority: Some("example.test".parse().unwrap()),
                path: Some("/".parse().unwrap()),
                protocol: None,
            },
            headers,
        );
        let _shared = section.clone();

        let parts = http::request::Parts::try_from(section).unwrap();

        assert_eq!(parts.headers.get("x-shared").unwrap(), "ok");

        let error = http::request::Parts::try_from(FieldSection::trailer(http::HeaderMap::new()))
            .unwrap_err();
        assert!(matches!(
            error,
            MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. }
        ));
    }

    #[test]
    fn request_parts_reject_response_pseudo_headers() {
        let section = FieldSection::header(
            PseudoHeaders::response(http::StatusCode::OK),
            http::HeaderMap::new(),
        );

        let error = http::request::Parts::try_from(section).unwrap_err();

        assert!(matches!(
            error,
            MalformedHeaderSection::ResponsePseudoHeaderInRequest
        ));
    }

    #[test]
    fn response_parts_roundtrip_preserves_status_headers_and_rejects_request_pseudo_headers() {
        let response = http::Response::builder()
            .status(http::StatusCode::CREATED)
            .header("x-test", "ok")
            .body(())
            .unwrap();
        let (parts, ()) = response.into_parts();

        let section = FieldSection::from(parts);
        let parts = http::response::Parts::try_from(section).unwrap();

        assert_eq!(parts.status, http::StatusCode::CREATED);
        assert_eq!(parts.version, http::Version::HTTP_3);
        assert_eq!(parts.headers.get("x-test").unwrap(), "ok");

        let request_section = FieldSection::header(
            PseudoHeaders::Request {
                method: Some(http::Method::GET),
                scheme: Some(http::uri::Scheme::HTTPS),
                authority: Some("example.test".parse().unwrap()),
                path: Some("/".parse().unwrap()),
                protocol: None,
            },
            http::HeaderMap::new(),
        );

        let error = http::response::Parts::try_from(request_section).unwrap_err();

        assert!(matches!(
            error,
            MalformedHeaderSection::RequestPseudoHeaderInResponse
        ));
    }

    #[test]
    fn response_parts_try_from_clones_shared_header_map_and_rejects_trailers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-shared", http::HeaderValue::from_static("ok"));
        let section = FieldSection::header(PseudoHeaders::response(http::StatusCode::OK), headers);
        let _shared = section.clone();

        let parts = http::response::Parts::try_from(section).unwrap();

        assert_eq!(parts.headers.get("x-shared").unwrap(), "ok");

        let error = http::response::Parts::try_from(FieldSection::trailer(http::HeaderMap::new()))
            .unwrap_err();
        assert!(matches!(
            error,
            MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. }
        ));
    }

    #[test]
    fn validated_request_parts_success_returns_pseudo_and_regular_fields() {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .header("x-test", "ok")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let lines = validated_hyper_request_parts_to_field_lines(parts).unwrap();

        assert!(lines.iter().any(|line| {
            line.name == Bytes::from_static(b":method") && line.value == Bytes::from_static(b"GET")
        }));
        assert!(lines.iter().any(|line| {
            line.name == Bytes::from_static(b"x-test") && line.value == Bytes::from_static(b"ok")
        }));
    }

    #[test]
    fn hyper_response_parts_to_field_lines_emits_status_and_headers() {
        let response = http::Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .header("x-test", "ok")
            .body(())
            .unwrap();
        let (parts, ()) = response.into_parts();

        let lines = hyper_response_parts_to_field_lines(parts).collect::<Vec<_>>();

        assert_eq!(
            lines[0],
            FieldLine {
                name: Bytes::from_static(b":status"),
                value: Bytes::from_static(b"204"),
            }
        );
        assert!(lines.iter().any(|line| {
            line.name == Bytes::from_static(b"x-test") && line.value == Bytes::from_static(b"ok")
        }));
    }

    #[test]
    fn request_parts_rejects_authority_only_get() {
        let section = FieldSection::header(
            PseudoHeaders::Request {
                method: Some(http::Method::GET),
                scheme: None,
                authority: Some("reimu.pilot.genmeta.net".parse().unwrap()),
                path: None,
                protocol: None,
            },
            http::HeaderMap::new(),
        );

        let error = http::request::Parts::try_from(section).unwrap_err();

        assert!(matches!(
            error,
            MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. }
        ));
    }

    #[test]
    fn request_parts_allows_connect_authority_form() {
        let section = FieldSection::header(
            PseudoHeaders::Request {
                method: Some(http::Method::CONNECT),
                scheme: None,
                authority: Some("example.com:443".parse().unwrap()),
                path: None,
                protocol: None,
            },
            http::HeaderMap::new(),
        );

        let parts = http::request::Parts::try_from(section).unwrap();

        assert_eq!(parts.method, http::Method::CONNECT);
        assert_eq!(parts.uri.authority().unwrap().as_str(), "example.com:443");
    }

    #[test]
    fn validated_request_parts_rejects_authority_only_get() {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("reimu.pilot.genmeta.net")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let error = validated_hyper_request_parts_to_field_lines(parts).unwrap_err();

        assert!(matches!(
            error,
            MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. }
        ));
    }

    #[test]
    fn request_parts_rejects_protocol_on_non_connect() {
        let section = FieldSection::header(
            PseudoHeaders::Request {
                method: Some(http::Method::GET),
                scheme: Some(http::uri::Scheme::HTTPS),
                authority: Some("reimu.pilot.genmeta.net".parse().unwrap()),
                path: Some("/".parse().unwrap()),
                protocol: Some(Protocol::new("webtransport")),
            },
            http::HeaderMap::new(),
        );

        let error = http::request::Parts::try_from(section).unwrap_err();

        assert!(matches!(
            error,
            MalformedHeaderSection::ProtocolInNonConnectRequest
        ));
    }

    #[test]
    fn validated_request_parts_rejects_protocol_on_get() {
        let mut request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://reimu.pilot.genmeta.net/")
            .body(())
            .unwrap();
        request
            .extensions_mut()
            .insert(Protocol::new("webtransport"));
        let (parts, ()) = request.into_parts();

        let error = validated_hyper_request_parts_to_field_lines(parts).unwrap_err();

        assert!(matches!(
            error,
            MalformedHeaderSection::ProtocolInNonConnectRequest
        ));
    }
}
