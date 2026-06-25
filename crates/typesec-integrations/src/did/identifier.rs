//! The [`Did`] decentralized-identifier type.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::crypto::hex_encode;
use super::error::DidError;

/// A decentralized identifier string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Did(String);

impl Did {
    /// Parse a DID.
    pub fn parse(value: impl Into<String>) -> Result<Self, DidError> {
        let value = value.into();
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() < 3 || parts.first() != Some(&"did") || parts[1].is_empty() {
            return Err(DidError::InvalidDid(value));
        }
        Ok(Self(value))
    }

    /// Create a deterministic `did:key` identifier from public key material.
    pub fn key(public_key: impl AsRef<[u8]>) -> Self {
        Self(format!("did:key:z{}", hex_encode(public_key.as_ref())))
    }

    /// Create a `did:web` identifier for a host.
    pub fn web(host: impl AsRef<str>) -> Result<Self, DidError> {
        let host = host.as_ref().trim();
        if host.is_empty() || host.contains('/') {
            return Err(DidError::InvalidDid(format!("did:web:{host}")));
        }
        Ok(Self(format!("did:web:{host}")))
    }

    /// Borrow the DID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Did {
    type Error = DidError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<Did> for String {
    fn from(value: Did) -> Self {
        value.0
    }
}
