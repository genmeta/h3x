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
pub(crate) mod hyper;

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
        // SAFETY: Safe because we only construct Protocol from valid UTF-8
        unsafe { std::str::from_utf8_unchecked(&self.token) }
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
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-3.2.1-2
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
