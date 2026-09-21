use std::sync::{Arc, Mutex};

use http::{HeaderMap, HeaderName, HeaderValue};

use crate::{ErrorCode, Result, qpack::Field};

/// Shared HTTP trailer fields.
///
/// Clones refer to the same fields. Outgoing trailers must be set before the
/// message body is shut down; incoming trailers are complete after body EOF.
#[derive(Clone, Debug, Default)]
pub struct Trailers {
    fields: Arc<Mutex<HeaderMap>>,
}

impl Trailers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn headers(&self) -> HeaderMap {
        self.lock().clone()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    pub(crate) fn set(&self, name: HeaderName, value: HeaderValue) {
        self.lock().insert(name, value);
    }

    pub(crate) fn append(&self, name: HeaderName, value: HeaderValue) {
        self.lock().append(name, value);
    }

    pub(crate) fn extend_fields(&self, fields: Vec<Field>) -> Result<()> {
        let mut trailers = self.lock();
        for field in fields {
            if field.name.starts_with(b":") {
                return Err(
                    ErrorCode::MessageError.reason("pseudo-header is not allowed in trailers")
                );
            }
            if field.name.iter().any(u8::is_ascii_uppercase) {
                return Err(ErrorCode::MessageError.reason("uppercase field name"));
            }
            let name = HeaderName::from_lowercase(&field.name)
                .map_err(|_| ErrorCode::MessageError.reason("invalid trailer name"))?;
            let mut value = HeaderValue::from_bytes(&field.value)
                .map_err(|_| ErrorCode::MessageError.reason("invalid trailer value"))?;
            value.set_sensitive(field.never_index);
            trailers.append(name, value);
        }
        Ok(())
    }

    pub(crate) fn fields(&self) -> Vec<Field> {
        self.lock()
            .iter()
            .map(|(name, value)| Field {
                name: bytes::Bytes::copy_from_slice(name.as_str().as_bytes()),
                value: bytes::Bytes::copy_from_slice(value.as_bytes()),
                never_index: value.is_sensitive(),
            })
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HeaderMap> {
        self.fields
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
