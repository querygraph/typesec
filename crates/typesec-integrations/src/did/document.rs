//! DID document model and resolver boundary.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::crypto::{hex_decode, hex_encode};
use super::error::DidError;
use super::identifier::Did;

/// A verification method from a DID document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// DID URL for this key.
    pub id: String,
    /// Verification method type.
    #[serde(rename = "type")]
    pub method_type: String,
    /// Controller DID.
    pub controller: Did,
    /// Public key bytes encoded as hex for this local integration.
    pub public_key_hex: String,
    /// Optional local key version for rotation-aware DID documents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_version: Option<u64>,
    /// Optional local rotation status (`active` or `previous`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_status: Option<String>,
}

impl VerificationMethod {
    /// Construct a local Ed25519-like method for examples and tests.
    pub fn local(id: impl Into<String>, controller: Did, public_key: impl AsRef<[u8]>) -> Self {
        Self {
            id: id.into(),
            method_type: "TypesecDemoKey2026".to_owned(),
            controller,
            public_key_hex: hex_encode(public_key.as_ref()),
            key_version: None,
            key_status: None,
        }
    }

    pub(super) fn public_key(&self) -> Result<Vec<u8>, DidError> {
        hex_decode(&self.public_key_hex)
    }
}

/// Service endpoint metadata from a DID document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidService {
    /// DID URL for this service.
    pub id: String,
    /// Service type.
    #[serde(rename = "type")]
    pub service_type: String,
    /// Endpoint URL.
    pub service_endpoint: String,
}

/// Minimal DID document model used by Typesec integrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    /// Subject DID.
    pub id: Did,
    /// Verification methods available for this DID.
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    /// Authentication key references.
    #[serde(default)]
    pub authentication: Vec<String>,
    /// Key-agreement key references.
    #[serde(default)]
    pub key_agreement: Vec<String>,
    /// Service endpoints.
    #[serde(default)]
    pub service: Vec<DidService>,
}

impl DidDocument {
    /// Create a document with one key used for authentication and key agreement.
    pub fn single_key(did: Did, public_key: impl AsRef<[u8]>) -> Self {
        let key_id = format!("{did}#key-1");
        Self {
            id: did.clone(),
            verification_method: vec![VerificationMethod::local(&key_id, did, public_key)],
            authentication: vec![key_id.clone()],
            key_agreement: vec![key_id],
            service: Vec::new(),
        }
    }

    /// Create a document with separate Ed25519 (authentication) and X25519
    /// (key-agreement) keys, as produced by [`Ed25519DidKey`].
    ///
    /// [`Ed25519DidKey`]: super::keystore::Ed25519DidKey
    pub fn with_signing_and_agreement_keys(
        did: Did,
        signing_public: impl AsRef<[u8]>,
        agreement_public: impl AsRef<[u8]>,
    ) -> Self {
        let signing_id = format!("{did}#key-1");
        let agreement_id = format!("{did}#key-2");
        Self {
            id: did.clone(),
            verification_method: vec![
                VerificationMethod {
                    id: signing_id.clone(),
                    method_type: "Ed25519VerificationKey2020".to_owned(),
                    controller: did.clone(),
                    public_key_hex: hex_encode(signing_public.as_ref()),
                    key_version: Some(1),
                    key_status: Some("active".to_owned()),
                },
                VerificationMethod {
                    id: agreement_id.clone(),
                    method_type: "X25519KeyAgreementKey2020".to_owned(),
                    controller: did,
                    public_key_hex: hex_encode(agreement_public.as_ref()),
                    key_version: Some(1),
                    key_status: Some("active".to_owned()),
                },
            ],
            authentication: vec![signing_id],
            key_agreement: vec![agreement_id],
            service: Vec::new(),
        }
    }

    fn method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method
            .iter()
            .find(|method| method.id == id)
    }

    pub(super) fn authentication_key(&self, kid: &str) -> Result<&VerificationMethod, DidError> {
        if !self.authentication.iter().any(|id| id == kid) {
            return Err(DidError::MissingVerificationMethod(kid.to_owned()));
        }
        self.method(kid)
            .ok_or_else(|| DidError::MissingVerificationMethod(kid.to_owned()))
    }

    pub(super) fn key_agreement_key(&self) -> Result<&VerificationMethod, DidError> {
        let kid = self
            .key_agreement
            .first()
            .ok_or(DidError::MissingKeyAgreement)?;
        self.method(kid)
            .ok_or_else(|| DidError::MissingVerificationMethod(kid.clone()))
    }

    pub(super) fn key_agreement_keys(&self) -> Result<Vec<&VerificationMethod>, DidError> {
        if self.key_agreement.is_empty() {
            return Err(DidError::MissingKeyAgreement);
        }

        self.key_agreement
            .iter()
            .map(|kid| {
                self.method(kid)
                    .ok_or_else(|| DidError::MissingVerificationMethod(kid.clone()))
            })
            .collect()
    }
}

/// DID resolver boundary.
pub trait DidResolver: Send + Sync {
    /// Resolve `did` to a DID document.
    fn resolve(&self, did: &Did) -> Result<DidDocument, DidError>;
}

/// In-memory DID resolver for tests and local demos.
#[derive(Debug, Default, Clone)]
pub struct StaticDidResolver {
    documents: HashMap<Did, DidDocument>,
}

impl StaticDidResolver {
    /// Create an empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a DID document.
    pub fn with_document(mut self, document: DidDocument) -> Self {
        self.documents.insert(document.id.clone(), document);
        self
    }
}

impl DidResolver for StaticDidResolver {
    fn resolve(&self, did: &Did) -> Result<DidDocument, DidError> {
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| DidError::Unresolved(did.to_string()))
    }
}
