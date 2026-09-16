//! Typed HTTP protocol extensions.
use std::sync::Arc;

use crate::{ErrorCode, Result};

/// Validated, case-sensitive Extended CONNECT protocol token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol(Arc<str>);
impl Protocol {
    pub fn new(name: &str) -> Result<Self> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("invalid CONNECT protocol token"));
        }
        Ok(Self(Arc::from(name)))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
