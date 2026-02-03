use bytes::Bytes;
use http::{HeaderName, Request, Response, Uri, request, response};
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

pub fn hyper_request_parts_to_field_lines(
    mut parts: http::request::Parts,
) -> impl Iterator<Item = FieldLine> {
    let uri_parts = parts.uri.into_parts();
    let pseudo_headers = [
        Some(parts.method.into()),
        uri_parts.scheme.map(FieldLine::from),
        uri_parts.authority.map(FieldLine::from),
        uri_parts.path_and_query.map(FieldLine::from),
    ];

    let protocol = parts
        .extensions
        .remove::<Protocol>()
        .map(FieldLine::from)
        .or_else(|| {
            parts
                .extensions
                .remove::<::hyper::ext::Protocol>()
                .map(FieldLine::from)
        });

    pseudo_headers
        .into_iter()
        .flatten()
        .chain(protocol)
        .chain(header_map_to_field_lines(parts.headers))
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
            header_map: request.headers,
        }
    }
}

impl TryFrom<FieldSection> for request::Parts {
    type Error = MalformedHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        let PseudoHeaders::Request {
            method,
            scheme,
            authority,
            path,
            protocol,
        } = value
            .pseudo_headers
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

        let mut request = Request::builder().uri(uri).method(method).body(())?;
        *request.headers_mut() = value.header_map;

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
            header_map: response.headers,
        }
    }
}

impl TryFrom<FieldSection> for response::Parts {
    type Error = MalformedHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        let PseudoHeaders::Response { status } = value
            .pseudo_headers
            .context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?
        else {
            return Err(MalformedHeaderSection::RequestPseudoHeaderInResponse);
        };

        let status =
            status.context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?;
        let response = Response::builder().status(status).body(())?;
        Ok(response.into_parts().0)
    }
}
