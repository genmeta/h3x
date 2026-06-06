use bytes::Bytes;
use http::{
    Method, StatusCode,
    header::{HeaderName, HeaderValue},
    uri::{Authority, PathAndQuery, Scheme},
};

mod repr;
pub use repr::{EncodedFieldSectionPrefix, FieldLineRepresentation};
mod pseudo;
pub use pseudo::PseudoHeaders;
mod section;
pub use section::{FieldSection, Iter, MalformedHeaderSection, malformed_header_section};

#[cfg(feature = "hyper")]
pub mod hyper;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protocol {
    token: Bytes,
}

impl TryFrom<Bytes> for Protocol {
    type Error = std::str::Utf8Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        str::from_utf8(&value)?;
        Ok(Self { token: value })
    }
}

impl Protocol {
    pub fn new(token: &'static str) -> Self {
        Self {
            token: Bytes::from_static(token.as_bytes()),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.token.as_ref()
    }

    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.token.as_ref()
    }
}

impl AsRef<str> for Protocol {
    fn as_ref(&self) -> &str {
        // Protocol is always constructed from valid UTF-8:
        // - TryFrom<Bytes> validates via str::from_utf8()
        // - Protocol::new() takes &str
        // - hyper integration validates via hyper::ext::Protocol (ASCII token)
        std::str::from_utf8(&self.token).expect("Protocol token is valid UTF-8 by construction")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldLine {
    pub name: Bytes,
    pub value: Bytes,
}

impl FieldLine {
    /// The size of an entry is the sum of its name's length in bytes, its
    /// value's length in bytes, and 32 additional bytes. The size of an
    /// entry is calculated using the length of its name and value without
    /// Huffman encoding applied.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9204#section-3.2.1-2>
    pub fn size(&self) -> u64 {
        self.name.len() as u64 + self.value.len() as u64 + 32
    }
}

struct AsRefStrToAsStrBytes<T: ?Sized>(T);

impl<T: AsRef<str> + ?Sized> AsRef<[u8]> for AsRefStrToAsStrBytes<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().as_bytes()
    }
}

impl From<(HeaderName, HeaderValue)> for FieldLine {
    fn from((name, value): (HeaderName, HeaderValue)) -> Self {
        FieldLine {
            name: Bytes::from_owner(name),
            value: Bytes::from_owner(value),
        }
    }
}

impl From<Method> for FieldLine {
    fn from(method: Method) -> Self {
        FieldLine {
            name: Bytes::from_static(PseudoHeaders::METHOD.as_bytes()),
            value: Bytes::from_owner(AsRefStrToAsStrBytes(method)),
        }
    }
}

impl From<Scheme> for FieldLine {
    fn from(scheme: Scheme) -> Self {
        FieldLine {
            name: Bytes::from_static(PseudoHeaders::SCHEME.as_bytes()),
            value: Bytes::from_owner(AsRefStrToAsStrBytes(scheme)),
        }
    }
}

impl From<Authority> for FieldLine {
    fn from(authority: Authority) -> Self {
        FieldLine {
            name: Bytes::from_static(PseudoHeaders::AUTHORITY.as_bytes()),
            value: Bytes::from_owner(AsRefStrToAsStrBytes(authority)),
        }
    }
}

impl From<PathAndQuery> for FieldLine {
    fn from(path_and_query: PathAndQuery) -> Self {
        FieldLine {
            name: Bytes::from_static(PseudoHeaders::PATH.as_bytes()),
            value: Bytes::copy_from_slice(path_and_query.as_str().as_bytes()),
        }
    }
}

impl From<Protocol> for FieldLine {
    fn from(protocol: Protocol) -> Self {
        FieldLine {
            name: Bytes::from_static(PseudoHeaders::PROTOOCL.as_bytes()),
            value: Bytes::from_owner(protocol),
        }
    }
}

impl From<StatusCode> for FieldLine {
    fn from(status: StatusCode) -> Self {
        FieldLine {
            name: Bytes::from_static(PseudoHeaders::STATUS.as_bytes()),
            value: Bytes::copy_from_slice(status.as_str().as_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{
        Method, StatusCode,
        header::{HeaderName, HeaderValue},
        uri::{Authority, PathAndQuery, Scheme},
    };

    use super::{FieldLine, Protocol, PseudoHeaders};

    #[test]
    fn protocol_validates_utf8_and_exposes_original_token() {
        let protocol = Protocol::try_from(Bytes::from_static(b"webtransport"))
            .expect("ASCII protocol token should be valid");

        assert_eq!(protocol.as_bytes(), b"webtransport");
        assert_eq!(protocol.as_str(), "webtransport");
        assert_eq!(AsRef::<[u8]>::as_ref(&protocol), b"webtransport");
        assert_eq!(AsRef::<str>::as_ref(&protocol), "webtransport");

        let error = Protocol::try_from(Bytes::from_static(b"\xff")).expect_err("invalid UTF-8");
        assert_eq!(error.valid_up_to(), 0);
    }

    #[test]
    fn field_line_from_header_parts_preserves_name_value_and_size() {
        let field = FieldLine::from((
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/dhttp"),
        ));

        assert_eq!(field.name, Bytes::from_static(b"content-type"));
        assert_eq!(field.value, Bytes::from_static(b"application/dhttp"));
        assert_eq!(
            field.size(),
            "content-type".len() as u64 + "application/dhttp".len() as u64 + 32
        );
    }

    #[test]
    fn field_line_from_pseudo_source_types_uses_expected_names_and_values() {
        let method = FieldLine::from(Method::POST);
        assert_eq!(
            method.name,
            Bytes::from_static(PseudoHeaders::METHOD.as_bytes())
        );
        assert_eq!(method.value, Bytes::from_static(b"POST"));

        let scheme = FieldLine::from(Scheme::HTTPS);
        assert_eq!(
            scheme.name,
            Bytes::from_static(PseudoHeaders::SCHEME.as_bytes())
        );
        assert_eq!(scheme.value, Bytes::from_static(b"https"));

        let authority = FieldLine::from(Authority::from_static("example.com:443"));
        assert_eq!(
            authority.name,
            Bytes::from_static(PseudoHeaders::AUTHORITY.as_bytes())
        );
        assert_eq!(authority.value, Bytes::from_static(b"example.com:443"));

        let path = FieldLine::from(PathAndQuery::from_static("/resource?q=1"));
        assert_eq!(
            path.name,
            Bytes::from_static(PseudoHeaders::PATH.as_bytes())
        );
        assert_eq!(path.value, Bytes::from_static(b"/resource?q=1"));

        let protocol = FieldLine::from(Protocol::new("webtransport"));
        assert_eq!(
            protocol.name,
            Bytes::from_static(PseudoHeaders::PROTOOCL.as_bytes())
        );
        assert_eq!(protocol.value, Bytes::from_static(b"webtransport"));

        let status = FieldLine::from(StatusCode::CREATED);
        assert_eq!(
            status.name,
            Bytes::from_static(PseudoHeaders::STATUS.as_bytes())
        );
        assert_eq!(status.value, Bytes::from_static(b"201"));
    }
}
