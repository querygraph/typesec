//! Decentralized identifier messaging helpers for Typesec.
//!
//! This module treats DIDs as identity, key-discovery, and routing handles.
//! Runtime authorization still flows through [`typesec_core::PolicyEngine`]:
//! a verified DID message identifies the subject, and a policy engine decides
//! whether to mint the typed capability required to reveal or use the payload.
//!
//! [`Ed25519DidKeyStore`] is the production key store: Ed25519 signatures,
//! X25519 key agreement, and ChaCha20-Poly1305 payload encryption. The
//! deterministic, **non-cryptographic** `DemoDidKeyStore` is only compiled in
//! tests or behind the `demo-crypto` feature — never enable that feature in
//! production builds. Deployments with stronger requirements should implement
//! [`DidKeyStore`] with JOSE/DIDComm, HPKE, or an HSM/KMS.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use typesec_core::{
    Capability, SecureValue,
    permissions::{AiCanInfer, CanReadSensitive},
    resource::GenericResource,
    secure_value::Secret,
};

use crate::http::{HttpClient, ReqwestHttpClient};

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

    fn public_key(&self) -> Result<Vec<u8>, DidError> {
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

    fn authentication_key(&self, kid: &str) -> Result<&VerificationMethod, DidError> {
        if !self.authentication.iter().any(|id| id == kid) {
            return Err(DidError::MissingVerificationMethod(kid.to_owned()));
        }
        self.method(kid)
            .ok_or_else(|| DidError::MissingVerificationMethod(kid.to_owned()))
    }

    fn key_agreement_key(&self) -> Result<&VerificationMethod, DidError> {
        let kid = self
            .key_agreement
            .first()
            .ok_or(DidError::MissingKeyAgreement)?;
        self.method(kid)
            .ok_or_else(|| DidError::MissingVerificationMethod(kid.clone()))
    }

    fn key_agreement_keys(&self) -> Result<Vec<&VerificationMethod>, DidError> {
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

/// Key-store and envelope crypto boundary.
pub trait DidKeyStore: Send + Sync {
    /// Sign bytes as `signer`.
    fn sign(&self, signer: &Did, message: &[u8]) -> Result<String, DidError>;

    /// Verify a signature with the public key in `method`.
    fn verify(
        &self,
        method: &VerificationMethod,
        message: &[u8],
        signature: &str,
    ) -> Result<(), DidError>;

    /// Encrypt bytes from `sender` to the recipient public key.
    fn encrypt_for(
        &self,
        sender: &Did,
        recipient_public_key: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
    ) -> Result<String, DidError>;

    /// Decrypt bytes addressed to `recipient` from the sender public key.
    fn decrypt_for(
        &self,
        recipient: &Did,
        sender_public_key: &[u8],
        nonce: &[u8],
        ciphertext_hex: &str,
    ) -> Result<Vec<u8>, DidError>;
}

/// Public/private key material for a local DID subject.
///
/// **Not cryptography.** Key derivation is a non-cryptographic hash and the
/// "public" key equals the private key. Tests and demos only.
#[cfg(any(test, feature = "demo-crypto"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoDidKeyPair {
    /// Public key bytes advertised in a DID document.
    pub public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[cfg(any(test, feature = "demo-crypto"))]
impl DemoDidKeyPair {
    /// Create deterministic key material from a seed.
    pub fn from_seed(seed: impl AsRef<[u8]>) -> Self {
        let private_key = derive_bytes(b"typesec-did-private", seed.as_ref(), 32);
        let public_key = private_key.clone();
        Self {
            public_key,
            private_key,
        }
    }
}

/// Local deterministic key store for DID envelope examples and tests.
///
/// **Not cryptography**: signatures are forgeable by anyone holding the public
/// key, and "encryption" is a repeating-key XOR. Only available in tests or
/// behind the `demo-crypto` feature; use [`Ed25519DidKeyStore`] in real code.
#[cfg(any(test, feature = "demo-crypto"))]
#[derive(Debug, Default, Clone)]
pub struct DemoDidKeyStore {
    keys: HashMap<Did, DemoDidKeyPair>,
}

#[cfg(any(test, feature = "demo-crypto"))]
impl DemoDidKeyStore {
    /// Create an empty key store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key pair for a DID.
    pub fn with_key(mut self, did: Did, key: DemoDidKeyPair) -> Self {
        self.keys.insert(did, key);
        self
    }

    fn key(&self, did: &Did) -> Result<&DemoDidKeyPair, DidError> {
        self.keys
            .get(did)
            .ok_or_else(|| DidError::MissingPrivateKey(did.to_string()))
    }
}

#[cfg(any(test, feature = "demo-crypto"))]
impl DidKeyStore for DemoDidKeyStore {
    fn sign(&self, signer: &Did, message: &[u8]) -> Result<String, DidError> {
        let key = self.key(signer)?;
        Ok(hex_encode(&derive_bytes(&key.private_key, message, 32)))
    }

    fn verify(
        &self,
        method: &VerificationMethod,
        message: &[u8],
        signature: &str,
    ) -> Result<(), DidError> {
        let public = method.public_key()?;
        let expected = hex_encode(&derive_bytes(&public, message, 32));
        if constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
            Ok(())
        } else {
            Err(DidError::InvalidSignature)
        }
    }

    fn encrypt_for(
        &self,
        sender: &Did,
        recipient_public_key: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
    ) -> Result<String, DidError> {
        let sender_key = self.key(sender)?;
        let ciphertext = xor_stream(
            plaintext,
            &derive_shared_key(&sender_key.private_key, recipient_public_key, nonce),
        );
        Ok(hex_encode(&ciphertext))
    }

    fn decrypt_for(
        &self,
        recipient: &Did,
        sender_public_key: &[u8],
        nonce: &[u8],
        ciphertext_hex: &str,
    ) -> Result<Vec<u8>, DidError> {
        let recipient_key = self.key(recipient)?;
        let ciphertext = hex_decode(ciphertext_hex)?;
        Ok(xor_stream(
            &ciphertext,
            &derive_shared_key(&recipient_key.private_key, sender_public_key, nonce),
        ))
    }
}

// ── Production key store ──────────────────────────────────────────────────────

/// Real key material for a local DID subject.
///
/// Holds an Ed25519 signing key (advertised as the DID document's
/// authentication key) and an independent X25519 static secret (advertised as
/// the key-agreement key).
#[derive(Clone)]
pub struct Ed25519DidKey {
    signing: ed25519_dalek::SigningKey,
    agreement: x25519_dalek::StaticSecret,
}

impl Ed25519DidKey {
    /// Generate a key pair from the operating system RNG.
    pub fn generate() -> Result<Self, DidError> {
        let mut signing_seed = [0u8; 32];
        let mut agreement_seed = [0u8; 32];
        getrandom::getrandom(&mut signing_seed).map_err(|e| DidError::KeyGen(e.to_string()))?;
        getrandom::getrandom(&mut agreement_seed).map_err(|e| DidError::KeyGen(e.to_string()))?;
        Ok(Self::from_seeds(signing_seed, agreement_seed))
    }

    /// Derive a key pair deterministically from a seed via SHA-256 expansion.
    ///
    /// Only as strong as the seed's entropy — use [`generate`][Self::generate]
    /// unless you need reproducible keys (tests, fixtures).
    pub fn from_seed(seed: impl AsRef<[u8]>) -> Self {
        let signing_seed = sha256_tagged(b"typesec-ed25519-signing", seed.as_ref());
        let agreement_seed = sha256_tagged(b"typesec-x25519-agreement", seed.as_ref());
        Self::from_seeds(signing_seed, agreement_seed)
    }

    fn from_seeds(signing_seed: [u8; 32], agreement_seed: [u8; 32]) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(&signing_seed),
            agreement: x25519_dalek::StaticSecret::from(agreement_seed),
        }
    }

    /// Ed25519 public key bytes (the DID document authentication key).
    pub fn signing_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// X25519 public key bytes (the DID document key-agreement key).
    pub fn agreement_public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.agreement).to_bytes()
    }

    /// Build a DID document advertising this key pair's public halves.
    pub fn document(&self, did: Did) -> DidDocument {
        DidDocument::with_signing_and_agreement_keys(
            did,
            self.signing_public(),
            self.agreement_public(),
        )
    }
}

impl std::fmt::Debug for Ed25519DidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519DidKey")
            .field("signing_public", &hex_encode(&self.signing_public()))
            .field("agreement_public", &hex_encode(&self.agreement_public()))
            .finish_non_exhaustive()
    }
}

/// Production [`DidKeyStore`]: Ed25519 signatures, X25519 ECDH, and
/// ChaCha20-Poly1305 authenticated payload encryption.
#[derive(Debug, Default, Clone)]
pub struct Ed25519DidKeyStore {
    keys: HashMap<Did, Vec<Ed25519DidKeyRecord>>,
    retired_methods: HashSet<String>,
}

#[derive(Debug, Clone)]
struct Ed25519DidKeyRecord {
    version: u64,
    key: Ed25519DidKey,
    retired: bool,
}

impl Ed25519DidKeyStore {
    /// Create an empty key store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key pair for a DID.
    pub fn with_key(mut self, did: Did, key: Ed25519DidKey) -> Self {
        self.keys.insert(
            did,
            vec![Ed25519DidKeyRecord {
                version: 1,
                key,
                retired: false,
            }],
        );
        self
    }

    /// Rotate a DID to a new active key version.
    ///
    /// Existing non-retired versions remain in the DID document for in-flight
    /// envelope verification until explicitly retired.
    pub fn rotate_key(&mut self, did: &Did, key: Ed25519DidKey) -> Result<u64, DidError> {
        let records = self
            .keys
            .get_mut(did)
            .ok_or_else(|| DidError::MissingPrivateKey(did.to_string()))?;
        let next_version = records
            .iter()
            .map(|record| record.version)
            .max()
            .unwrap_or(0)
            + 1;
        records.push(Ed25519DidKeyRecord {
            version: next_version,
            key,
            retired: false,
        });
        Ok(next_version)
    }

    /// Retire an old key version.
    ///
    /// Retired authentication methods are omitted from newly generated DID
    /// documents and are rejected by this store's verifier.
    pub fn retire_key(&mut self, did: &Did, version: u64) -> Result<(), DidError> {
        if self.active_key_version(did)? == version {
            return Err(DidError::CannotRetireActiveKey {
                did: did.to_string(),
                version,
            });
        }

        let records = self
            .keys
            .get_mut(did)
            .ok_or_else(|| DidError::MissingPrivateKey(did.to_string()))?;
        let record = records
            .iter_mut()
            .find(|record| record.version == version)
            .ok_or_else(|| DidError::MissingKeyVersion {
                did: did.to_string(),
                version,
            })?;
        record.retired = true;
        self.retired_methods
            .insert(Self::signing_method_id(did, version));
        self.retired_methods
            .insert(Self::agreement_method_id(did, version));
        Ok(())
    }

    /// Active signing/encryption version for `did`.
    pub fn active_key_version(&self, did: &Did) -> Result<u64, DidError> {
        Ok(self.active_record(did)?.version)
    }

    /// Build a rotation-aware DID document for one local DID.
    pub fn document(&self, did: &Did) -> Result<DidDocument, DidError> {
        let records = self
            .keys
            .get(did)
            .ok_or_else(|| DidError::MissingPrivateKey(did.to_string()))?;
        let active_version = self.active_key_version(did)?;
        let mut verification_method = Vec::new();
        let mut authentication = Vec::new();
        let mut key_agreement = Vec::new();

        for record in records.iter().filter(|record| !record.retired) {
            let status = if record.version == active_version {
                "active"
            } else {
                "previous"
            };
            let signing_id = Self::signing_method_id(did, record.version);
            let agreement_id = Self::agreement_method_id(did, record.version);
            verification_method.push(VerificationMethod {
                id: signing_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.clone(),
                public_key_hex: hex_encode(&record.key.signing_public()),
                key_version: Some(record.version),
                key_status: Some(status.to_owned()),
            });
            verification_method.push(VerificationMethod {
                id: agreement_id.clone(),
                method_type: "X25519KeyAgreementKey2020".to_owned(),
                controller: did.clone(),
                public_key_hex: hex_encode(&record.key.agreement_public()),
                key_version: Some(record.version),
                key_status: Some(status.to_owned()),
            });

            if record.version == active_version {
                authentication.insert(0, signing_id);
                key_agreement.insert(0, agreement_id);
            } else {
                authentication.push(signing_id);
                key_agreement.push(agreement_id);
            }
        }

        Ok(DidDocument {
            id: did.clone(),
            verification_method,
            authentication,
            key_agreement,
            service: Vec::new(),
        })
    }

    fn active_record(&self, did: &Did) -> Result<&Ed25519DidKeyRecord, DidError> {
        self.keys
            .get(did)
            .and_then(|records| {
                records
                    .iter()
                    .filter(|record| !record.retired)
                    .max_by_key(|record| record.version)
            })
            .ok_or_else(|| DidError::MissingPrivateKey(did.to_string()))
    }

    fn signing_method_id(did: &Did, version: u64) -> String {
        if version == 1 {
            format!("{did}#key-1")
        } else {
            format!("{did}#key-signing-v{version}")
        }
    }

    fn agreement_method_id(did: &Did, version: u64) -> String {
        if version == 1 {
            format!("{did}#key-2")
        } else {
            format!("{did}#key-agreement-v{version}")
        }
    }

    fn aead_key(shared_secret: &[u8; 32]) -> chacha20poly1305::Key {
        let digest = sha256_tagged(b"typesec-did-aead", shared_secret);
        chacha20poly1305::Key::from(digest)
    }
}

impl DidKeyStore for Ed25519DidKeyStore {
    fn sign(&self, signer: &Did, message: &[u8]) -> Result<String, DidError> {
        use ed25519_dalek::Signer;
        let record = self.active_record(signer)?;
        Ok(hex_encode(&record.key.signing.sign(message).to_bytes()))
    }

    fn verify(
        &self,
        method: &VerificationMethod,
        message: &[u8],
        signature: &str,
    ) -> Result<(), DidError> {
        use ed25519_dalek::Verifier;
        if self.retired_methods.contains(&method.id) {
            return Err(DidError::RetiredKey(method.id.clone()));
        }
        let public: [u8; 32] = method
            .public_key()?
            .try_into()
            .map_err(|_| DidError::InvalidKey("ed25519 public key must be 32 bytes".into()))?;
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|e| DidError::InvalidKey(e.to_string()))?;
        let signature_bytes: [u8; 64] = hex_decode(signature)?
            .try_into()
            .map_err(|_| DidError::InvalidSignature)?;
        verifying
            .verify(
                message,
                &ed25519_dalek::Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| DidError::InvalidSignature)
    }

    fn encrypt_for(
        &self,
        sender: &Did,
        recipient_public_key: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
    ) -> Result<String, DidError> {
        use chacha20poly1305::KeyInit;
        use chacha20poly1305::aead::Aead;
        let sender_key = &self.active_record(sender)?.key;
        let recipient: [u8; 32] = recipient_public_key
            .try_into()
            .map_err(|_| DidError::InvalidKey("x25519 public key must be 32 bytes".into()))?;
        let shared = sender_key
            .agreement
            .diffie_hellman(&x25519_dalek::PublicKey::from(recipient));
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| DidError::InvalidNonce)?;
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&Self::aead_key(shared.as_bytes()));
        let ciphertext = cipher
            .encrypt(&chacha20poly1305::Nonce::from(nonce), plaintext)
            .map_err(|_| DidError::EncryptionFailed)?;
        Ok(hex_encode(&ciphertext))
    }

    fn decrypt_for(
        &self,
        recipient: &Did,
        sender_public_key: &[u8],
        nonce: &[u8],
        ciphertext_hex: &str,
    ) -> Result<Vec<u8>, DidError> {
        use chacha20poly1305::KeyInit;
        use chacha20poly1305::aead::Aead;
        let sender: [u8; 32] = sender_public_key
            .try_into()
            .map_err(|_| DidError::InvalidKey("x25519 public key must be 32 bytes".into()))?;
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| DidError::InvalidNonce)?;
        let ciphertext = hex_decode(ciphertext_hex)?;
        let records = self
            .keys
            .get(recipient)
            .ok_or_else(|| DidError::MissingPrivateKey(recipient.to_string()))?;

        for record in records.iter().filter(|record| !record.retired) {
            let shared = record
                .key
                .agreement
                .diffie_hellman(&x25519_dalek::PublicKey::from(sender));
            let cipher =
                chacha20poly1305::ChaCha20Poly1305::new(&Self::aead_key(shared.as_bytes()));
            if let Ok(plaintext) =
                cipher.decrypt(&chacha20poly1305::Nonce::from(nonce), ciphertext.as_slice())
            {
                return Ok(plaintext);
            }
        }

        Err(DidError::DecryptionFailed)
    }
}

/// Message metadata that policy engines evaluate before payload use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidMessageBody {
    /// Requested Typesec action, such as `ai:infer`.
    pub action: String,
    /// Resource identifier for policy evaluation.
    pub resource: String,
    /// Payload privacy label, such as `secret`.
    pub privacy: String,
    /// Prompt envelope this message is bound to, for reply envelopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<DidMessageReference>,
}

impl DidMessageBody {
    /// Create a prompt body for AI inference.
    pub fn infer_prompt(resource: impl Into<String>) -> Self {
        Self {
            action: "ai:infer".to_owned(),
            resource: resource.into(),
            privacy: "secret".to_owned(),
            reply_to: None,
        }
    }

    /// Create a reply body that inherits the prompt's policy-visible metadata.
    pub fn reply_to_prompt(prompt: &VerifiedDidPrompt) -> Self {
        Self {
            action: prompt.body.action.clone(),
            resource: prompt.body.resource.clone(),
            privacy: prompt.body.privacy.clone(),
            reply_to: Some(prompt.prompt_ref.clone()),
        }
    }

    /// Create a general agent message body.
    pub fn agent_message(resource: impl Into<String>, privacy: impl Into<String>) -> Self {
        Self {
            action: "agent:message".to_owned(),
            resource: resource.into(),
            privacy: privacy.into(),
            reply_to: None,
        }
    }

    /// Create an agent delegation body.
    pub fn agent_delegate(resource: impl Into<String>, privacy: impl Into<String>) -> Self {
        Self {
            action: "agent:delegate".to_owned(),
            resource: resource.into(),
            privacy: privacy.into(),
            reply_to: None,
        }
    }
}

/// TypeDID delivery mode for an agent message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeDidMode {
    /// Fire-and-forget delivery; no TypeDID reply is required.
    Send,
    /// The receiver is expected to answer with a reply-bound TypeDID envelope.
    RequestReply,
}

/// TypeDID conversation metadata bound into the envelope signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDidConversation {
    /// Stable task, session, room, or thread id from the outer protocol.
    pub conversation_id: String,
    /// Delivery mode.
    pub mode: TypeDidMode,
    /// Negotiated TypeDID profile id.
    pub profile: String,
    /// Outer protocol hint, such as `a2a`, `acp`, `band`, or `https`.
    pub protocol: String,
    /// Optional payload expiry copied from the negotiated profile or caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl TypeDidConversation {
    /// Construct TypeDID conversation metadata.
    pub fn new(
        conversation_id: impl Into<String>,
        mode: TypeDidMode,
        profile: impl Into<String>,
        protocol: impl Into<String>,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            mode,
            profile: profile.into(),
            protocol: protocol.into(),
            expires_at: None,
        }
    }

    /// Attach an absolute unix-seconds expiry to this conversation metadata.
    pub fn with_expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

/// A negotiable TypeDID security profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDidProfile {
    /// Stable profile id.
    pub id: String,
    /// Supported DID methods, such as `did:web` or `did:key`.
    #[serde(default)]
    pub did_methods: Vec<String>,
    /// Supported signing algorithms.
    #[serde(default)]
    pub signing: Vec<String>,
    /// Supported key-agreement algorithms.
    #[serde(default)]
    pub key_agreement: Vec<String>,
    /// Supported encryption profiles.
    #[serde(default)]
    pub encryption: Vec<String>,
    /// Supported outer transport bindings.
    #[serde(default)]
    pub transport_bindings: Vec<String>,
    /// Supported TypeDID send modes.
    #[serde(default)]
    pub modes: Vec<TypeDidMode>,
    /// Optional maximum encrypted payload size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<usize>,
    /// Claims required by the remote boundary.
    #[serde(default)]
    pub required_claims: Vec<String>,
    /// Policy actions this profile is willing to carry.
    #[serde(default)]
    pub policy_actions: Vec<String>,
    /// Retention posture advertised by the receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<String>,
    /// Audit posture advertised by the receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<String>,
}

impl TypeDidProfile {
    /// Default local TypeDID profile backed by the built-in Ed25519/X25519
    /// key store.
    pub fn ed25519_x25519_chacha20() -> Self {
        Self {
            id: "typedid/v1/x25519-chacha20poly1305-ed25519".to_owned(),
            did_methods: vec![
                "did:web".to_owned(),
                "did:key".to_owned(),
                "did:indy".to_owned(),
            ],
            signing: vec!["Ed25519".to_owned()],
            key_agreement: vec!["X25519".to_owned()],
            encryption: vec!["ChaCha20-Poly1305".to_owned()],
            transport_bindings: vec![
                "a2a".to_owned(),
                "acp".to_owned(),
                "band".to_owned(),
                "https".to_owned(),
                "websocket".to_owned(),
            ],
            modes: vec![TypeDidMode::Send, TypeDidMode::RequestReply],
            max_payload_bytes: Some(1024 * 1024),
            required_claims: vec![
                "org".to_owned(),
                "agent_id".to_owned(),
                "purpose".to_owned(),
            ],
            policy_actions: vec![
                "agent:message".to_owned(),
                "agent:delegate".to_owned(),
                "ai:infer".to_owned(),
            ],
            retention: Some("sender-encrypted-payload-only".to_owned()),
            audit: Some("envelope-metadata-and-policy-decision".to_owned()),
        }
    }

    /// Return true when this local profile can safely communicate with `remote`.
    pub fn is_compatible_with(&self, remote: &Self, protocol: &str, mode: TypeDidMode) -> bool {
        self.id == remote.id
            && contains(&self.transport_bindings, protocol)
            && contains(&remote.transport_bindings, protocol)
            && self.modes.contains(&mode)
            && remote.modes.contains(&mode)
            && intersects(&self.did_methods, &remote.did_methods)
            && intersects(&self.signing, &remote.signing)
            && intersects(&self.key_agreement, &remote.key_agreement)
            && intersects(&self.encryption, &remote.encryption)
    }

    /// Select the first local profile compatible with the remote boundary.
    pub fn negotiate<'a>(
        local: &'a [Self],
        remote: &[Self],
        protocol: &str,
        mode: TypeDidMode,
    ) -> Result<&'a Self, DidError> {
        local
            .iter()
            .find(|candidate| {
                remote
                    .iter()
                    .any(|other| candidate.is_compatible_with(other, protocol, mode))
            })
            .ok_or(DidError::NoCompatibleTypeDidProfile)
    }
}

/// Resolves TypeDID profiles for a remote agent or boundary.
pub trait TypeDidProfileResolver: Send + Sync {
    /// Resolve profiles advertised by `target`.
    fn resolve_profiles(&self, target: &str) -> Result<Vec<TypeDidProfile>, DidError>;
}

/// In-memory TypeDID profile resolver for examples and tests.
#[derive(Debug, Default, Clone)]
pub struct StaticTypeDidProfileResolver {
    profiles: HashMap<String, Vec<TypeDidProfile>>,
}

impl StaticTypeDidProfileResolver {
    /// Create an empty profile resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register profiles for a target DID, contact, agent card, or endpoint.
    pub fn with_profiles(
        mut self,
        target: impl Into<String>,
        profiles: Vec<TypeDidProfile>,
    ) -> Self {
        self.profiles.insert(target.into(), profiles);
        self
    }
}

impl TypeDidProfileResolver for StaticTypeDidProfileResolver {
    fn resolve_profiles(&self, target: &str) -> Result<Vec<TypeDidProfile>, DidError> {
        self.profiles
            .get(target)
            .cloned()
            .ok_or_else(|| DidError::Unresolved(target.to_owned()))
    }
}

/// The prompt context a reply envelope is bound to.
#[derive(Debug, Clone)]
pub struct DidReplyBinding {
    /// Policy-visible metadata of the prompt being answered.
    pub prompt_body: DidMessageBody,
    /// Stable reference to the signed prompt envelope.
    pub prompt_ref: DidMessageReference,
}

impl DidReplyBinding {
    /// Bind a reply to a verified prompt.
    pub fn for_prompt(prompt: &VerifiedDidPrompt) -> Self {
        Self {
            prompt_body: prompt.body.clone(),
            prompt_ref: prompt.prompt_ref.clone(),
        }
    }
}

/// Stable reference to a DID message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidMessageReference {
    /// Referenced DID message id.
    pub id: String,
    /// SHA-256 digest of the referenced signed envelope.
    pub digest: String,
}

/// Encrypted DID message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidEnvelope {
    /// Message id.
    pub id: String,
    /// Message type URI.
    #[serde(rename = "type")]
    pub message_type: String,
    /// Sender DID.
    pub from: Did,
    /// Recipient DIDs.
    pub to: Vec<Did>,
    /// Creation time as unix seconds.
    pub created_time: u64,
    /// Expiration time as unix seconds.
    pub expires_time: u64,
    /// Policy-visible message metadata.
    pub body: DidMessageBody,
    /// Optional TypeDID conversation/profile metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typedid: Option<TypeDidConversation>,
    /// Key id used for authentication.
    pub kid: String,
    /// Hex-encoded nonce.
    pub nonce: String,
    /// Hex-encoded ciphertext.
    pub ciphertext: String,
    /// Hex-encoded signature over the envelope signing input.
    pub signature: String,
}

impl DidEnvelope {
    /// Create an encrypted prompt envelope.
    pub fn prompt(
        id: impl Into<String>,
        from: Did,
        to: Did,
        body: DidMessageBody,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let id = id.into();
        let now = unix_time();
        let recipient_document = resolver.resolve(&to)?;
        let recipient_key = recipient_document.key_agreement_key()?;
        let sender_document = resolver.resolve(&from)?;
        let kid = sender_document
            .authentication
            .first()
            .cloned()
            .ok_or(DidError::MissingAuthentication)?;
        let nonce = random_nonce()?;
        let ciphertext = key_store.encrypt_for(
            &from,
            &recipient_key.public_key()?,
            plaintext.as_ref(),
            &nonce,
        )?;
        let mut envelope = Self {
            id,
            message_type: "https://typesec.dev/did/message/v1/prompt".to_owned(),
            from,
            to: vec![to],
            created_time: now,
            expires_time: now + 300,
            body,
            typedid: None,
            kid,
            nonce: hex_encode(&nonce),
            ciphertext,
            signature: String::new(),
        };
        envelope.signature = key_store.sign(&envelope.from, envelope.signing_input().as_bytes())?;
        Ok(envelope)
    }

    /// Create an encrypted reply envelope bound to a verified prompt envelope.
    pub fn reply(
        reply_did: Did,
        from: Did,
        to: Did,
        binding: DidReplyBinding,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let DidReplyBinding {
            prompt_body,
            prompt_ref,
        } = binding;
        let now = unix_time();
        let recipient_document = resolver.resolve(&to)?;
        let recipient_key = recipient_document.key_agreement_key()?;
        let sender_document = resolver.resolve(&from)?;
        let kid = sender_document
            .authentication
            .first()
            .cloned()
            .ok_or(DidError::MissingAuthentication)?;
        let id = reply_did.to_string();
        let nonce = random_nonce()?;
        let ciphertext = key_store.encrypt_for(
            &from,
            &recipient_key.public_key()?,
            plaintext.as_ref(),
            &nonce,
        )?;
        let mut envelope = Self {
            id,
            message_type: "https://typesec.dev/did/message/v1/reply".to_owned(),
            from,
            to: vec![to],
            created_time: now,
            expires_time: now + 300,
            body: DidMessageBody {
                action: prompt_body.action.clone(),
                resource: prompt_body.resource.clone(),
                privacy: prompt_body.privacy.clone(),
                reply_to: Some(prompt_ref),
            },
            typedid: None,
            kid,
            nonce: hex_encode(&nonce),
            ciphertext,
            signature: String::new(),
        };
        envelope.signature = key_store.sign(&envelope.from, envelope.signing_input().as_bytes())?;
        Ok(envelope)
    }

    /// Create an encrypted TypeDID agent-message envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn typedid(
        id: impl Into<String>,
        from: Did,
        to: Did,
        body: DidMessageBody,
        typedid: TypeDidConversation,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let mut envelope = Self::prompt(id, from, to, body, plaintext, resolver, key_store)?;
        envelope.message_type = "https://typesec.dev/did/message/v1/typedid".to_owned();
        envelope.typedid = Some(typedid);
        envelope.signature = key_store.sign(&envelope.from, envelope.signing_input().as_bytes())?;
        Ok(envelope)
    }

    /// Create an encrypted TypeDID reply envelope bound to a verified request.
    pub fn typedid_reply(
        id: impl Into<String>,
        from: Did,
        to: Did,
        request: &VerifiedTypeDidMessage,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let mut body = request.body.clone();
        body.reply_to = Some(request.message_ref.clone());
        let conversation = TypeDidConversation {
            conversation_id: request.conversation.conversation_id.clone(),
            mode: TypeDidMode::RequestReply,
            profile: request.conversation.profile.clone(),
            protocol: request.conversation.protocol.clone(),
            expires_at: request.conversation.expires_at,
        };
        Self::typedid(
            id,
            from,
            to,
            body,
            conversation,
            plaintext,
            resolver,
            key_store,
        )
    }

    /// Stable reference to this signed envelope for reply binding.
    pub fn reference(&self) -> DidMessageReference {
        let seed = format!("{}\n{}", self.signing_input(), self.signature);
        DidMessageReference {
            id: self.id.clone(),
            digest: hex_encode(&sha256_tagged(
                b"typesec-did-envelope-reference",
                seed.as_bytes(),
            )),
        }
    }

    fn signing_input(&self) -> String {
        let reply_to = self
            .body
            .reply_to
            .as_ref()
            .map(|reference| format!("{}\n{}", reference.id, reference.digest))
            .unwrap_or_default();
        let base = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.id,
            self.message_type,
            self.from,
            self.to
                .iter()
                .map(Did::as_str)
                .collect::<Vec<_>>()
                .join(","),
            self.created_time,
            self.expires_time,
            self.body.action,
            self.body.resource,
            self.body.privacy,
            reply_to
        );
        if let Some(typedid) = self.typedid.as_ref() {
            format!(
                "{}\n{}\n{}",
                base,
                canonical_typedid_conversation(typedid),
                self.ciphertext
            )
        } else {
            format!("{}\n{}", base, self.ciphertext)
        }
    }
}

/// Verified and decrypted TypeDID agent message.
#[derive(Debug)]
pub struct VerifiedTypeDidMessage {
    /// Verified DID subject.
    pub subject: Did,
    /// Stable reference to the verified envelope.
    pub message_ref: DidMessageReference,
    /// Policy-visible message metadata.
    pub body: DidMessageBody,
    /// TypeDID conversation/profile metadata.
    pub conversation: TypeDidConversation,
    /// Resource associated with the payload.
    pub resource: GenericResource,
    /// Secret opaque payload bytes.
    pub payload: SecureValue<Secret, Vec<u8>, GenericResource>,
}

/// Verified and decrypted DID prompt.
#[derive(Debug)]
pub struct VerifiedDidPrompt {
    /// Verified DID subject.
    pub subject: Did,
    /// Stable reference to the verified prompt envelope.
    pub prompt_ref: DidMessageReference,
    /// Policy-visible metadata.
    pub body: DidMessageBody,
    /// Resource associated with the payload.
    pub resource: GenericResource,
    /// Secret prompt payload.
    pub prompt: SecureValue<Secret, String, GenericResource>,
}

/// Verifies DID envelopes and converts encrypted payloads into `SecureValue`s.
pub struct DidMessageGateway {
    resolver: Arc<dyn DidResolver>,
    key_store: Arc<dyn DidKeyStore>,
    recipient: Did,
}

impl DidMessageGateway {
    /// Create a gateway for one local recipient DID.
    pub fn new(
        resolver: Arc<dyn DidResolver>,
        key_store: Arc<dyn DidKeyStore>,
        recipient: Did,
    ) -> Self {
        Self {
            resolver,
            key_store,
            recipient,
        }
    }

    /// Verify, decrypt, and protect a DID prompt envelope.
    pub fn open_prompt(&self, envelope: &DidEnvelope) -> Result<VerifiedDidPrompt, DidError> {
        let opened = self.open_bytes(envelope)?;
        let prompt = String::from_utf8(opened.plaintext).map_err(|_| DidError::InvalidUtf8)?;
        Ok(VerifiedDidPrompt {
            subject: opened.subject,
            prompt_ref: opened.message_ref,
            body: opened.body,
            prompt: SecureValue::protect(prompt, &opened.resource),
            resource: opened.resource,
        })
    }

    fn open_bytes(&self, envelope: &DidEnvelope) -> Result<OpenedDidEnvelope, DidError> {
        if !envelope.to.iter().any(|did| did == &self.recipient) {
            return Err(DidError::WrongRecipient(self.recipient.to_string()));
        }
        let now = unix_time();
        if envelope.expires_time < now {
            return Err(DidError::Expired);
        }

        let sender_document = self.resolver.resolve(&envelope.from)?;
        let sender_key = sender_document.authentication_key(&envelope.kid)?;
        self.key_store.verify(
            sender_key,
            envelope.signing_input().as_bytes(),
            &envelope.signature,
        )?;

        // Decryption uses the sender's *key-agreement* key, which may be a
        // different key (X25519) than the authentication key (Ed25519). During
        // key rotation, older in-flight envelopes may have used a previous
        // sender agreement key, so try every non-retired key advertised by the
        // sender document.
        let sender_agreement_keys = sender_document.key_agreement_keys()?;
        let nonce = hex_decode(&envelope.nonce)?;
        let mut plaintext = None;
        for sender_agreement_key in sender_agreement_keys {
            match self.key_store.decrypt_for(
                &self.recipient,
                &sender_agreement_key.public_key()?,
                &nonce,
                &envelope.ciphertext,
            ) {
                Ok(opened) => {
                    plaintext = Some(opened);
                    break;
                }
                Err(DidError::DecryptionFailed) => {}
                Err(err) => return Err(err),
            }
        }
        let plaintext = plaintext.ok_or(DidError::DecryptionFailed)?;
        let resource = GenericResource::new(&envelope.body.resource, "did-prompt");

        Ok(OpenedDidEnvelope {
            subject: envelope.from.clone(),
            message_ref: envelope.reference(),
            body: envelope.body.clone(),
            resource,
            plaintext,
        })
    }
}

#[derive(Debug)]
struct OpenedDidEnvelope {
    subject: Did,
    message_ref: DidMessageReference,
    body: DidMessageBody,
    resource: GenericResource,
    plaintext: Vec<u8>,
}

/// Verifies TypeDID envelopes and protects arbitrary agent payload bytes.
pub struct TypeDidGateway {
    inner: DidMessageGateway,
}

impl TypeDidGateway {
    /// Create a TypeDID gateway for one local recipient DID.
    pub fn new(
        resolver: Arc<dyn DidResolver>,
        key_store: Arc<dyn DidKeyStore>,
        recipient: Did,
    ) -> Self {
        Self {
            inner: DidMessageGateway::new(resolver, key_store, recipient),
        }
    }

    /// Verify, decrypt, and protect a TypeDID message envelope.
    pub fn open_message(&self, envelope: &DidEnvelope) -> Result<VerifiedTypeDidMessage, DidError> {
        let conversation = envelope
            .typedid
            .clone()
            .ok_or(DidError::MissingTypeDidMetadata)?;
        let opened = self.inner.open_bytes(envelope)?;
        Ok(VerifiedTypeDidMessage {
            subject: opened.subject,
            message_ref: opened.message_ref,
            body: opened.body,
            conversation,
            payload: SecureValue::protect(opened.plaintext, &opened.resource),
            resource: opened.resource,
        })
    }
}

/// Common interface for TypeDID secure-envelope transport adapters.
pub trait SecureEnvelopeAdapter {
    /// Adapter protocol name.
    fn protocol(&self) -> &str;

    /// Media type this adapter carries over its outer protocol.
    fn content_type(&self) -> &'static str {
        "application/vnd.typedid.envelope+json"
    }

    /// Wrap a payload in a TypeDID envelope for this adapter's protocol.
    fn wrap(
        &self,
        request: TypeDidWrapRequest<'_>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<DidEnvelope, DidError> {
        let profile = TypeDidProfile::negotiate(
            request.local_profiles,
            request.remote_profiles,
            self.protocol(),
            request.mode,
        )?;
        let conversation = TypeDidConversation::new(
            request.conversation_id,
            request.mode,
            profile.id.clone(),
            self.protocol(),
        );
        DidEnvelope::typedid(
            request.id,
            request.from,
            request.to,
            request.body,
            conversation,
            request.payload,
            resolver,
            key_store,
        )
    }
}

/// Inputs for wrapping a payload in a TypeDID transport adapter.
pub struct TypeDidWrapRequest<'a> {
    /// Envelope id.
    pub id: String,
    /// Sender DID.
    pub from: Did,
    /// Recipient DID.
    pub to: Did,
    /// Outer conversation/task/room/session id.
    pub conversation_id: String,
    /// Send mode.
    pub mode: TypeDidMode,
    /// Policy-visible body.
    pub body: DidMessageBody,
    /// Plaintext payload bytes.
    pub payload: &'a [u8],
    /// Local TypeDID profiles.
    pub local_profiles: &'a [TypeDidProfile],
    /// Remote TypeDID profiles.
    pub remote_profiles: &'a [TypeDidProfile],
}

/// A2A TypeDID content adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct A2aTypeDidAdapter;

impl SecureEnvelopeAdapter for A2aTypeDidAdapter {
    fn protocol(&self) -> &str {
        "a2a"
    }
}

/// ACP TypeDID content adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcpTypeDidAdapter;

impl SecureEnvelopeAdapter for AcpTypeDidAdapter {
    fn protocol(&self) -> &str {
        "acp"
    }
}

/// BAND secure-envelope adapter for TypeDID payloads.
#[derive(Debug, Default, Clone, Copy)]
pub struct BandSecureEnvelopeAdapter;

impl SecureEnvelopeAdapter for BandSecureEnvelopeAdapter {
    fn protocol(&self) -> &str {
        "band"
    }
}

/// Direct HTTPS TypeDID content adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpTypeDidAdapter;

impl SecureEnvelopeAdapter for HttpTypeDidAdapter {
    fn protocol(&self) -> &str {
        "https"
    }
}

/// Ollama client that can send verified DID prompts.
pub struct DidOllamaClient {
    base_url: String,
    model: String,
    http: Arc<dyn HttpClient>,
}

impl DidOllamaClient {
    /// Create an Ollama client using reqwest.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self::with_http(base_url, model, Arc::new(ReqwestHttpClient::new()))
    }

    /// Create an Ollama client with an injected HTTP client.
    pub fn with_http(
        base_url: impl Into<String>,
        model: impl Into<String>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            model: model.into(),
            http,
        }
    }

    /// Reveal a verified prompt under typed authority and send it to Ollama.
    pub fn chat_verified_prompt(
        &self,
        prompt: VerifiedDidPrompt,
        _infer: &Capability<AiCanInfer, GenericResource>,
        read: &Capability<CanReadSensitive, GenericResource>,
    ) -> Result<Value, DidError> {
        let plaintext = prompt.prompt.reveal(read)?;
        let body = json!({
            "model": self.model,
            "stream": false,
            "messages": [{
                "role": "user",
                "content": plaintext
            }]
        });
        self.http
            .post_json(&format!("{}/api/chat", self.base_url), &[], &body)
            .map_err(DidError::Http)
    }

    /// Send a verified prompt to Ollama and bind the assistant reply to it.
    pub fn chat_verified_prompt_bound(
        &self,
        prompt: VerifiedDidPrompt,
        reply_from: Did,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
        _infer: &Capability<AiCanInfer, GenericResource>,
        read: &Capability<CanReadSensitive, GenericResource>,
    ) -> Result<DidEnvelope, DidError> {
        let reply_to = prompt.subject.clone();
        let binding = DidReplyBinding::for_prompt(&prompt);
        let plaintext = prompt.prompt.reveal(read)?;
        let body = json!({
            "model": self.model,
            "stream": false,
            "messages": [{
                "role": "user",
                "content": plaintext
            }]
        });
        let response = self
            .http
            .post_json(&format!("{}/api/chat", self.base_url), &[], &body)
            .map_err(DidError::Http)?;
        let reply = ollama_reply_content(&response)?;
        let reply_did = Did::key(sha256_tagged(
            b"typesec-did-ollama-reply",
            format!("{}\n{}", binding.prompt_ref.digest, reply).as_bytes(),
        ));
        DidEnvelope::reply(
            reply_did, reply_from, reply_to, binding, reply, resolver, key_store,
        )
    }

    /// Forward an already wrapped DID prompt to a DID-aware Ollama fork.
    pub fn chat_wrapped_prompt(&self, envelope: &DidEnvelope) -> Result<Value, DidError> {
        let body = json!({
            "model": self.model,
            "stream": false,
            "did_envelope": envelope
        });
        self.http
            .post_json(&format!("{}/api/chat", self.base_url), &[], &body)
            .map_err(DidError::Http)
    }
}

/// DID integration errors.
#[derive(Debug, thiserror::Error)]
pub enum DidError {
    /// DID syntax is invalid.
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    /// DID could not be resolved.
    #[error("unresolved DID: {0}")]
    Unresolved(String),
    /// No private key is available for a local DID.
    #[error("missing private key for DID: {0}")]
    MissingPrivateKey(String),
    /// DID document did not contain an authentication key.
    #[error("DID document has no authentication key")]
    MissingAuthentication,
    /// DID document did not contain a key agreement key.
    #[error("DID document has no key agreement key")]
    MissingKeyAgreement,
    /// Referenced verification method is absent.
    #[error("missing verification method: {0}")]
    MissingVerificationMethod(String),
    /// Referenced key version is absent.
    #[error("missing key version {version} for DID {did}")]
    MissingKeyVersion {
        /// DID whose key version was requested.
        did: String,
        /// Missing key version.
        version: u64,
    },
    /// Active key versions cannot be retired.
    #[error("cannot retire active key version {version} for DID {did}")]
    CannotRetireActiveKey {
        /// DID whose active key would have been retired.
        did: String,
        /// Active key version.
        version: u64,
    },
    /// Referenced key has been retired.
    #[error("retired verification method: {0}")]
    RetiredKey(String),
    /// Envelope signature did not verify.
    #[error("invalid DID envelope signature")]
    InvalidSignature,
    /// Envelope recipient does not match this gateway.
    #[error("DID envelope was not addressed to {0}")]
    WrongRecipient(String),
    /// Envelope has expired.
    #[error("DID envelope has expired")]
    Expired,
    /// Key material has the wrong size or encoding.
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    /// AEAD nonce must be exactly 12 bytes.
    #[error("invalid nonce: expected 12 bytes")]
    InvalidNonce,
    /// Payload encryption failed.
    #[error("DID payload encryption failed")]
    EncryptionFailed,
    /// Payload decryption or authentication failed.
    #[error("DID payload decryption failed")]
    DecryptionFailed,
    /// Operating system RNG was unavailable.
    #[error("key generation failed: {0}")]
    KeyGen(String),
    /// A typed capability did not cover the protected payload's resource.
    #[error("capability does not cover this payload: {0}")]
    Capability(#[from] typesec_core::secure_value::SecureAccessError),
    /// Hex input is malformed.
    #[error("invalid hex encoding")]
    InvalidHex,
    /// Decrypted payload is not UTF-8.
    #[error("decrypted DID payload is not valid UTF-8")]
    InvalidUtf8,
    /// HTTP request failed.
    #[error("DID HTTP integration failed: {0}")]
    Http(Box<dyn std::error::Error + Send + Sync>),
    /// Ollama response did not contain an assistant message.
    #[error("Ollama response did not contain message.content")]
    MissingOllamaReply,
    /// A TypeDID envelope did not include TypeDID metadata.
    #[error("DID envelope is missing TypeDID metadata")]
    MissingTypeDidMetadata,
    /// Local and remote TypeDID profiles did not overlap.
    #[error("no compatible TypeDID profile")]
    NoCompatibleTypeDidProfile,
}

fn ollama_reply_content(response: &Value) -> Result<&str, DidError> {
    response
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .ok_or(DidError::MissingOllamaReply)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// Domain-separated SHA-256: `SHA-256(domain || 0x00 || data)`.
fn sha256_tagged(domain: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(data);
    hasher.finalize().into()
}

/// A fresh random 12-byte AEAD nonce from the OS RNG.
fn random_nonce() -> Result<[u8; 12], DidError> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| DidError::KeyGen(e.to_string()))?;
    Ok(nonce)
}

fn canonical_typedid_conversation(conversation: &TypeDidConversation) -> String {
    format!(
        "{}\n{:?}\n{}\n{}\n{}",
        conversation.conversation_id,
        conversation.mode,
        conversation.profile,
        conversation.protocol,
        conversation
            .expires_at
            .map(|expires_at| expires_at.to_string())
            .unwrap_or_default()
    )
}

fn contains(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value == needle)
}

fn intersects(left: &[String], right: &[String]) -> bool {
    left.iter().any(|value| right.contains(value))
}

#[cfg(any(test, feature = "demo-crypto"))]
fn derive_shared_key(private_key: &[u8], public_key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(private_key.len() + public_key.len() + nonce.len());
    if private_key <= public_key {
        seed.extend_from_slice(private_key);
        seed.extend_from_slice(public_key);
    } else {
        seed.extend_from_slice(public_key);
        seed.extend_from_slice(private_key);
    }
    seed.extend_from_slice(nonce);
    derive_bytes(b"typesec-did-shared", &seed, 32)
}

/// Non-cryptographic FNV/xorshift expansion — demo key store only.
#[cfg(any(test, feature = "demo-crypto"))]
fn derive_bytes(domain: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u64 = 0xcbf29ce484222325;
    for byte in domain.iter().chain(seed) {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x100000001b3);
    }
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state = state.wrapping_mul(0x2545f4914f6cdd1d);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[cfg(any(test, feature = "demo-crypto"))]
fn xor_stream(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ key[idx % key.len()])
        .collect()
}

#[cfg(any(test, feature = "demo-crypto"))]
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>, DidError> {
    if !value.len().is_multiple_of(2) {
        return Err(DidError::InvalidHex);
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, DidError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DidError::InvalidHex),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use typesec_core::{
        PolicyEngine, Resource, ResourceId, SubjectId,
        permissions::{AiCanInfer, CanReadSensitive},
        policy::{PolicyResult, mint_capability},
    };

    use super::*;
    use crate::http::RecordingHttpClient;

    struct PromptPolicy;

    impl PolicyEngine for PromptPolicy {
        fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
            let subject = subject.as_str();
            let resource = resource.as_str();
            if subject == "did:key:z616c696365"
                && matches!(action, "ai:infer" | "read_sensitive")
                && resource == "prompt/session/123"
            {
                PolicyResult::Allow
            } else {
                PolicyResult::Deny("not allowed".to_owned())
            }
        }
    }

    fn fixture() -> (Did, Did, StaticDidResolver, DemoDidKeyStore) {
        let alice = Did::key(b"alice");
        let agent = Did::key(b"agent");
        let alice_key = DemoDidKeyPair::from_seed(b"alice");
        let agent_key = DemoDidKeyPair::from_seed(b"agent");
        let resolver = StaticDidResolver::new()
            .with_document(DidDocument::single_key(
                alice.clone(),
                alice_key.public_key.clone(),
            ))
            .with_document(DidDocument::single_key(
                agent.clone(),
                agent_key.public_key.clone(),
            ));
        let keys = DemoDidKeyStore::new()
            .with_key(alice.clone(), alice_key)
            .with_key(agent.clone(), agent_key);
        (alice, agent, resolver, keys)
    }

    struct AgentPolicy {
        allowed_subject: String,
    }

    impl PolicyEngine for AgentPolicy {
        fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
            let subject = subject.as_str();
            let resource = resource.as_str();
            if subject == self.allowed_subject
                && matches!(
                    action,
                    "agent:message" | "agent:delegate" | "read_sensitive"
                )
                && resource == "room/acme-support"
            {
                PolicyResult::Allow
            } else {
                PolicyResult::Deny("agent message denied".to_owned())
            }
        }
    }

    #[test]
    fn dids_parse_and_reject_bad_values() {
        assert!(Did::parse("did:web:example.com").is_ok());
        assert!(Did::parse("not-a-did").is_err());
        assert_eq!(
            Did::web("typesec.dev").unwrap().as_str(),
            "did:web:typesec.dev"
        );
    }

    #[test]
    fn encrypted_prompt_opens_as_secret_secure_value() {
        let (alice, agent, resolver, keys) = fixture();
        let envelope = DidEnvelope::prompt(
            "msg-1",
            alice.clone(),
            agent.clone(),
            DidMessageBody::infer_prompt("prompt/session/123"),
            "summarize this confidential record",
            &resolver,
            &keys,
        )
        .expect("envelope");
        assert_ne!(envelope.ciphertext, "summarize this confidential record");

        let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
        let verified = gateway.open_prompt(&envelope).expect("verified prompt");
        assert_eq!(verified.subject, alice);
        assert_eq!(verified.resource.resource_id(), "prompt/session/123");
        assert_eq!(
            SecureValue::<Secret, String, GenericResource>::label_name(),
            "secret"
        );

        let infer = mint_capability::<AiCanInfer, _>(
            &PromptPolicy,
            verified.subject.as_str(),
            &verified.resource,
        )
        .expect("infer cap");
        let read = mint_capability::<CanReadSensitive, _>(
            &PromptPolicy,
            verified.subject.as_str(),
            &verified.resource,
        )
        .expect("read cap");
        assert_eq!(infer.resource_id(), "prompt/session/123");
        assert_eq!(
            verified.prompt.reveal(&read).expect("matching resource"),
            "summarize this confidential record"
        );
    }

    #[test]
    fn did_ollama_client_sends_plaintext_only_after_capabilities() {
        let (alice, agent, resolver, keys) = fixture();
        let envelope = DidEnvelope::prompt(
            "msg-1",
            alice,
            agent.clone(),
            DidMessageBody::infer_prompt("prompt/session/123"),
            "private prompt",
            &resolver,
            &keys,
        )
        .expect("envelope");
        let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
        let verified = gateway.open_prompt(&envelope).expect("verified prompt");
        let infer = mint_capability::<AiCanInfer, _>(
            &PromptPolicy,
            verified.subject.as_str(),
            &verified.resource,
        )
        .expect("infer cap");
        let read = mint_capability::<CanReadSensitive, _>(
            &PromptPolicy,
            verified.subject.as_str(),
            &verified.resource,
        )
        .expect("read cap");

        let http = RecordingHttpClient::new().with_response(
            "http://localhost:11434/api/chat",
            json!({ "message": { "content": "ok" } }),
        );
        let client = DidOllamaClient::with_http(
            "http://localhost:11434",
            "llama3.2",
            Arc::new(http.clone()),
        );
        let response = client
            .chat_verified_prompt(verified, &infer, &read)
            .expect("ollama call");

        assert_eq!(response["message"]["content"], "ok");
        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "http://localhost:11434/api/chat");
        assert_eq!(
            requests[0].body.as_ref().unwrap()["messages"][0]["content"],
            "private prompt"
        );
    }

    #[test]
    fn typedid_profile_negotiates_on_protocol_and_mode() {
        let local = vec![TypeDidProfile::ed25519_x25519_chacha20()];
        let remote = vec![TypeDidProfile::ed25519_x25519_chacha20()];
        let selected = TypeDidProfile::negotiate(&local, &remote, "a2a", TypeDidMode::RequestReply)
            .expect("compatible profile");
        assert_eq!(selected.id, "typedid/v1/x25519-chacha20poly1305-ed25519");

        assert!(matches!(
            TypeDidProfile::negotiate(&local, &remote, "smtp", TypeDidMode::Send),
            Err(DidError::NoCompatibleTypeDidProfile)
        ));
    }

    #[test]
    fn typedid_adapter_wraps_and_gateway_opens_opaque_payload() {
        let (alice, agent, resolver, keys) = fixture();
        let profiles = vec![TypeDidProfile::ed25519_x25519_chacha20()];
        let adapter = A2aTypeDidAdapter;
        let payload =
            br#"{"jsonrpc":"2.0","method":"message/send","params":{"text":"triage case"}}"#;

        let envelope = adapter
            .wrap(
                TypeDidWrapRequest {
                    id: "a2a-msg-1".to_owned(),
                    from: alice.clone(),
                    to: agent.clone(),
                    conversation_id: "task/a2a-123".to_owned(),
                    mode: TypeDidMode::RequestReply,
                    body: DidMessageBody::agent_delegate("room/acme-support", "secret"),
                    payload,
                    local_profiles: &profiles,
                    remote_profiles: &profiles,
                },
                &resolver,
                &keys,
            )
            .expect("wrapped envelope");

        assert_eq!(
            adapter.content_type(),
            "application/vnd.typedid.envelope+json"
        );
        assert_eq!(
            envelope.message_type,
            "https://typesec.dev/did/message/v1/typedid"
        );
        assert_eq!(envelope.typedid.as_ref().unwrap().protocol, "a2a");
        assert_ne!(envelope.ciphertext.as_bytes(), payload);

        let gateway = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent);
        let verified = gateway.open_message(&envelope).expect("verified typedid");
        assert_eq!(verified.subject, alice);
        assert_eq!(verified.conversation.conversation_id, "task/a2a-123");
        assert_eq!(verified.body.action, "agent:delegate");

        let read = mint_capability::<CanReadSensitive, _>(
            &AgentPolicy {
                allowed_subject: verified.subject.to_string(),
            },
            verified.subject.as_str(),
            &verified.resource,
        )
        .expect("read cap");
        assert_eq!(verified.payload.reveal(&read).expect("payload"), payload);
    }

    #[test]
    fn typedid_reply_is_bound_to_request_envelope() {
        let (alice, agent, resolver, keys) = fixture();
        let request = DidEnvelope::typedid(
            "band-room-msg-1",
            alice.clone(),
            agent.clone(),
            DidMessageBody::agent_message("room/acme-support", "secret"),
            TypeDidConversation::new(
                "room/acme-support",
                TypeDidMode::RequestReply,
                TypeDidProfile::ed25519_x25519_chacha20().id,
                "band",
            ),
            b"please coordinate with the support agent",
            &resolver,
            &keys,
        )
        .expect("request envelope");
        let request_ref = request.reference();
        let gateway = TypeDidGateway::new(
            Arc::new(resolver.clone()),
            Arc::new(keys.clone()),
            agent.clone(),
        );
        let verified = gateway.open_message(&request).expect("verified request");
        let reply = DidEnvelope::typedid_reply(
            "band-room-reply-1",
            agent.clone(),
            alice.clone(),
            &verified,
            b"support agent accepted the handoff",
            &resolver,
            &keys,
        )
        .expect("reply envelope");

        assert_eq!(reply.typedid.as_ref().unwrap().protocol, "band");
        assert_eq!(reply.body.reply_to, Some(request_ref));

        let reply_gateway = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), alice);
        let opened_reply = reply_gateway.open_message(&reply).expect("opened reply");
        assert_eq!(opened_reply.subject, agent);
    }

    #[test]
    fn typedid_signature_covers_conversation_metadata() {
        let (alice, agent, resolver, keys) = fixture();
        let mut envelope = DidEnvelope::typedid(
            "acp-session-msg-1",
            alice,
            agent.clone(),
            DidMessageBody::agent_message("room/acme-support", "secret"),
            TypeDidConversation::new(
                "session/editor-1",
                TypeDidMode::Send,
                TypeDidProfile::ed25519_x25519_chacha20().id,
                "acp",
            ),
            b"review this private diff",
            &resolver,
            &keys,
        )
        .expect("typedid envelope");
        envelope.typedid.as_mut().unwrap().protocol = "band".to_owned();

        let gateway = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent);
        assert!(matches!(
            gateway.open_message(&envelope),
            Err(DidError::InvalidSignature)
        ));
    }

    #[test]
    fn bound_ollama_reply_creates_signed_reply_envelope_for_prompt() {
        let (alice, agent, resolver, keys) = fixture();
        let prompt_envelope = DidEnvelope::prompt(
            "msg-1",
            alice.clone(),
            agent.clone(),
            DidMessageBody::infer_prompt("prompt/session/123"),
            "private prompt",
            &resolver,
            &keys,
        )
        .expect("prompt envelope");
        let prompt_ref = prompt_envelope.reference();
        let gateway = DidMessageGateway::new(
            Arc::new(resolver.clone()),
            Arc::new(keys.clone()),
            agent.clone(),
        );
        let verified = gateway
            .open_prompt(&prompt_envelope)
            .expect("verified prompt");
        let infer = mint_capability::<AiCanInfer, _>(
            &PromptPolicy,
            verified.subject.as_str(),
            &verified.resource,
        )
        .expect("infer cap");
        let read = mint_capability::<CanReadSensitive, _>(
            &PromptPolicy,
            verified.subject.as_str(),
            &verified.resource,
        )
        .expect("read cap");

        let http = RecordingHttpClient::new().with_response(
            "http://localhost:11434/api/chat",
            json!({ "message": { "content": "bound reply" } }),
        );
        let client = DidOllamaClient::with_http(
            "http://localhost:11434",
            "llama3.2",
            Arc::new(http.clone()),
        );
        let reply_envelope = client
            .chat_verified_prompt_bound(verified, agent.clone(), &resolver, &keys, &infer, &read)
            .expect("bound reply");

        assert!(reply_envelope.id.starts_with("did:key:z"));
        assert_eq!(
            reply_envelope.message_type,
            "https://typesec.dev/did/message/v1/reply"
        );
        assert_eq!(reply_envelope.from, agent);
        assert_eq!(reply_envelope.to, vec![alice.clone()]);
        assert_eq!(reply_envelope.body.resource, "prompt/session/123");
        assert_eq!(reply_envelope.body.privacy, "secret");
        assert_eq!(reply_envelope.body.reply_to, Some(prompt_ref));
        assert_ne!(reply_envelope.ciphertext, "bound reply");

        let reply_gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), alice);
        let opened_reply = reply_gateway
            .open_prompt(&reply_envelope)
            .expect("verified reply");
        assert_eq!(opened_reply.subject, reply_envelope.from);
        assert_eq!(
            opened_reply
                .prompt
                .reveal(&read)
                .expect("matching resource"),
            "bound reply"
        );
    }

    #[test]
    fn reply_signature_covers_prompt_reference() {
        let (alice, agent, resolver, keys) = fixture();
        let prompt_envelope = DidEnvelope::prompt(
            "msg-1",
            alice.clone(),
            agent.clone(),
            DidMessageBody::infer_prompt("prompt/session/123"),
            "private prompt",
            &resolver,
            &keys,
        )
        .expect("prompt envelope");
        let gateway = DidMessageGateway::new(
            Arc::new(resolver.clone()),
            Arc::new(keys.clone()),
            agent.clone(),
        );
        let verified = gateway
            .open_prompt(&prompt_envelope)
            .expect("verified prompt");
        let mut reply_envelope = DidEnvelope::reply(
            Did::key(b"reply-1"),
            agent,
            alice.clone(),
            DidReplyBinding::for_prompt(&verified),
            "bound reply",
            &resolver,
            &keys,
        )
        .expect("reply envelope");
        reply_envelope
            .body
            .reply_to
            .as_mut()
            .expect("prompt reference")
            .digest = "tampered".to_owned();

        let reply_gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), alice);
        assert!(matches!(
            reply_gateway.open_prompt(&reply_envelope),
            Err(DidError::InvalidSignature)
        ));
    }

    fn ed25519_fixture() -> (Did, Did, StaticDidResolver, Ed25519DidKeyStore) {
        let alice_key = Ed25519DidKey::from_seed(b"alice-ed25519");
        let agent_key = Ed25519DidKey::from_seed(b"agent-ed25519");
        let alice = Did::key(alice_key.signing_public());
        let agent = Did::key(agent_key.signing_public());
        let resolver = StaticDidResolver::new()
            .with_document(alice_key.document(alice.clone()))
            .with_document(agent_key.document(agent.clone()));
        let keys = Ed25519DidKeyStore::new()
            .with_key(alice.clone(), alice_key)
            .with_key(agent.clone(), agent_key);
        (alice, agent, resolver, keys)
    }

    #[test]
    fn ed25519_envelope_roundtrip() {
        let (alice, agent, resolver, keys) = ed25519_fixture();
        let envelope = DidEnvelope::prompt(
            "msg-ed-1",
            alice.clone(),
            agent.clone(),
            DidMessageBody::infer_prompt("prompt/session/ed"),
            "confidential prompt over real crypto",
            &resolver,
            &keys,
        )
        .expect("envelope");
        assert_ne!(envelope.ciphertext, "confidential prompt over real crypto");

        let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
        let verified = gateway.open_prompt(&envelope).expect("verified prompt");
        assert_eq!(verified.subject, alice);

        let cap: typesec_core::Capability<CanReadSensitive, GenericResource> = mint_capability(
            &AllowAllForTest,
            verified.subject.as_str(),
            &verified.resource,
        )
        .expect("read cap");
        assert_eq!(
            verified.prompt.reveal(&cap).expect("matching resource"),
            "confidential prompt over real crypto"
        );
    }

    #[test]
    fn ed25519_rejects_tampered_envelope() {
        let (alice, agent, resolver, keys) = ed25519_fixture();
        let mut envelope = DidEnvelope::prompt(
            "msg-ed-2",
            alice,
            agent.clone(),
            DidMessageBody::infer_prompt("prompt/session/ed"),
            "payload",
            &resolver,
            &keys,
        )
        .expect("envelope");
        envelope.body.resource = "prompt/session/other".to_owned();

        let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
        assert!(matches!(
            gateway.open_prompt(&envelope),
            Err(DidError::InvalidSignature)
        ));
    }

    #[test]
    fn ed25519_signature_is_not_forgeable_from_public_key() {
        // With the demo store, anyone holding the public key could mint a
        // valid signature. The Ed25519 store must not allow that.
        let (alice, _agent, resolver, _keys) = ed25519_fixture();
        let document = resolver.resolve(&alice).expect("document");
        let auth_method = &document.verification_method[0];

        // An attacker key store that does NOT hold alice's private key but
        // knows her public key cannot produce a signature that verifies.
        let attacker_key = Ed25519DidKey::from_seed(b"attacker");
        let attacker_store = Ed25519DidKeyStore::new().with_key(alice.clone(), attacker_key);
        let forged = attacker_store.sign(&alice, b"message").expect("sign");

        let honest_store = Ed25519DidKeyStore::new();
        assert!(matches!(
            honest_store.verify(auth_method, b"message", &forged),
            Err(DidError::InvalidSignature)
        ));
    }

    #[test]
    fn ed25519_rotation_keeps_old_envelopes_until_retired() {
        let alice = Did::web("alice.example").expect("alice did");
        let agent = Did::web("agent.example").expect("agent did");
        let mut keys = Ed25519DidKeyStore::new()
            .with_key(alice.clone(), Ed25519DidKey::from_seed(b"alice-v1"))
            .with_key(agent.clone(), Ed25519DidKey::from_seed(b"agent-v1"));
        let resolver_v1 = StaticDidResolver::new()
            .with_document(keys.document(&alice).expect("alice v1 document"))
            .with_document(keys.document(&agent).expect("agent v1 document"));

        let old_envelope = DidEnvelope::prompt(
            "msg-rot-1",
            alice.clone(),
            agent.clone(),
            DidMessageBody::infer_prompt("prompt/session/rot"),
            "old in-flight payload",
            &resolver_v1,
            &keys,
        )
        .expect("old envelope");
        assert_eq!(old_envelope.kid, format!("{alice}#key-1"));

        assert_eq!(
            keys.rotate_key(&alice, Ed25519DidKey::from_seed(b"alice-v2"))
                .expect("rotate alice"),
            2
        );
        assert_eq!(
            keys.rotate_key(&agent, Ed25519DidKey::from_seed(b"agent-v2"))
                .expect("rotate agent"),
            2
        );
        assert_eq!(keys.active_key_version(&alice).expect("active alice"), 2);

        let resolver_v2 = StaticDidResolver::new()
            .with_document(keys.document(&alice).expect("alice v2 document"))
            .with_document(keys.document(&agent).expect("agent v2 document"));
        let alice_doc = resolver_v2.resolve(&alice).expect("alice document");
        assert_eq!(
            alice_doc.authentication[0],
            format!("{alice}#key-signing-v2")
        );
        assert_eq!(
            alice_doc
                .verification_method
                .iter()
                .find(|method| method.id == old_envelope.kid)
                .and_then(|method| method.key_status.as_deref()),
            Some("previous")
        );

        let gateway =
            DidMessageGateway::new(Arc::new(resolver_v2.clone()), Arc::new(keys.clone()), agent);
        let verified = gateway
            .open_prompt(&old_envelope)
            .expect("old envelope remains valid while previous key is advertised");
        assert_eq!(
            verified.resource.resource_id(),
            "prompt/session/rot",
            "old payload opened after sender and recipient rotation"
        );

        let new_envelope = DidEnvelope::prompt(
            "msg-rot-2",
            alice.clone(),
            Did::web("agent.example").expect("agent did"),
            DidMessageBody::infer_prompt("prompt/session/rot-new"),
            "new payload",
            &resolver_v2,
            &keys,
        )
        .expect("new envelope");
        assert_eq!(new_envelope.kid, format!("{alice}#key-signing-v2"));
    }

    #[test]
    fn ed25519_retired_key_rejects_old_signatures() {
        let alice = Did::web("alice-retired.example").expect("alice did");
        let agent = Did::web("agent-retired.example").expect("agent did");
        let mut keys = Ed25519DidKeyStore::new()
            .with_key(alice.clone(), Ed25519DidKey::from_seed(b"alice-retired-v1"))
            .with_key(agent.clone(), Ed25519DidKey::from_seed(b"agent-retired-v1"));
        let resolver_v1 = StaticDidResolver::new()
            .with_document(keys.document(&alice).expect("alice v1 document"))
            .with_document(keys.document(&agent).expect("agent v1 document"));
        let envelope = DidEnvelope::prompt(
            "msg-retired-1",
            alice.clone(),
            agent.clone(),
            DidMessageBody::infer_prompt("prompt/session/retired"),
            "payload",
            &resolver_v1,
            &keys,
        )
        .expect("envelope");
        let old_method = resolver_v1
            .resolve(&alice)
            .expect("alice document")
            .authentication_key(&envelope.kid)
            .expect("old auth method")
            .clone();

        keys.rotate_key(&alice, Ed25519DidKey::from_seed(b"alice-retired-v2"))
            .expect("rotate alice");
        keys.retire_key(&alice, 1).expect("retire old alice key");

        assert!(matches!(
            keys.verify(&old_method, envelope.signing_input().as_bytes(), &envelope.signature),
            Err(DidError::RetiredKey(method)) if method == old_method.id
        ));
        let rotated_doc = keys.document(&alice).expect("rotated alice document");
        assert!(
            !rotated_doc
                .authentication
                .iter()
                .any(|kid| kid == &envelope.kid)
        );
    }

    struct AllowAllForTest;
    impl PolicyEngine for AllowAllForTest {
        fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
            PolicyResult::Allow
        }
    }

    #[test]
    fn wrapped_prompt_passthrough_keeps_envelope() {
        let (alice, agent, resolver, keys) = fixture();
        let envelope = DidEnvelope::prompt(
            "msg-1",
            alice,
            agent,
            DidMessageBody::infer_prompt("prompt/session/123"),
            "private prompt",
            &resolver,
            &keys,
        )
        .expect("envelope");
        let http = RecordingHttpClient::new().with_response(
            "http://localhost:11434/api/chat",
            json!({ "message": { "content": "ok" } }),
        );
        let client = DidOllamaClient::with_http(
            "http://localhost:11434",
            "codata-did",
            Arc::new(http.clone()),
        );

        client.chat_wrapped_prompt(&envelope).expect("ollama call");

        let requests = http.requests();
        assert_eq!(
            requests[0].body.as_ref().unwrap()["did_envelope"]["ciphertext"],
            envelope.ciphertext
        );
    }
}
