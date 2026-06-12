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
    collections::HashMap,
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
}

impl VerificationMethod {
    /// Construct a local Ed25519-like method for examples and tests.
    pub fn local(id: impl Into<String>, controller: Did, public_key: impl AsRef<[u8]>) -> Self {
        Self {
            id: id.into(),
            method_type: "TypesecDemoKey2026".to_owned(),
            controller,
            public_key_hex: hex_encode(public_key.as_ref()),
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
                },
                VerificationMethod {
                    id: agreement_id.clone(),
                    method_type: "X25519KeyAgreementKey2020".to_owned(),
                    controller: did,
                    public_key_hex: hex_encode(agreement_public.as_ref()),
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
    keys: HashMap<Did, Ed25519DidKey>,
}

impl Ed25519DidKeyStore {
    /// Create an empty key store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key pair for a DID.
    pub fn with_key(mut self, did: Did, key: Ed25519DidKey) -> Self {
        self.keys.insert(did, key);
        self
    }

    fn key(&self, did: &Did) -> Result<&Ed25519DidKey, DidError> {
        self.keys
            .get(did)
            .ok_or_else(|| DidError::MissingPrivateKey(did.to_string()))
    }

    fn aead_key(shared_secret: &[u8; 32]) -> chacha20poly1305::Key {
        let digest = sha256_tagged(b"typesec-did-aead", shared_secret);
        chacha20poly1305::Key::from(digest)
    }
}

impl DidKeyStore for Ed25519DidKeyStore {
    fn sign(&self, signer: &Did, message: &[u8]) -> Result<String, DidError> {
        use ed25519_dalek::Signer;
        let key = self.key(signer)?;
        Ok(hex_encode(&key.signing.sign(message).to_bytes()))
    }

    fn verify(
        &self,
        method: &VerificationMethod,
        message: &[u8],
        signature: &str,
    ) -> Result<(), DidError> {
        use ed25519_dalek::Verifier;
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
        let sender_key = self.key(sender)?;
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
        let recipient_key = self.key(recipient)?;
        let sender: [u8; 32] = sender_public_key
            .try_into()
            .map_err(|_| DidError::InvalidKey("x25519 public key must be 32 bytes".into()))?;
        let shared = recipient_key
            .agreement
            .diffie_hellman(&x25519_dalek::PublicKey::from(sender));
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| DidError::InvalidNonce)?;
        let ciphertext = hex_decode(ciphertext_hex)?;
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&Self::aead_key(shared.as_bytes()));
        cipher
            .decrypt(&chacha20poly1305::Nonce::from(nonce), ciphertext.as_slice())
            .map_err(|_| DidError::DecryptionFailed)
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
            kid,
            nonce: hex_encode(&nonce),
            ciphertext,
            signature: String::new(),
        };
        envelope.signature = key_store.sign(&envelope.from, envelope.signing_input().as_bytes())?;
        Ok(envelope)
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
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
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
            reply_to,
            self.ciphertext
        )
    }
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
        // different key (X25519) than the authentication key (Ed25519).
        let sender_agreement_key = sender_document.key_agreement_key()?;
        let nonce = hex_decode(&envelope.nonce)?;
        let plaintext = self.key_store.decrypt_for(
            &self.recipient,
            &sender_agreement_key.public_key()?,
            &nonce,
            &envelope.ciphertext,
        )?;
        let prompt = String::from_utf8(plaintext).map_err(|_| DidError::InvalidUtf8)?;
        let resource = GenericResource::new(&envelope.body.resource, "did-prompt");

        Ok(VerifiedDidPrompt {
            subject: envelope.from.clone(),
            prompt_ref: envelope.reference(),
            body: envelope.body.clone(),
            prompt: SecureValue::protect(prompt, &resource),
            resource,
        })
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
        PolicyEngine, Resource,
        permissions::{AiCanInfer, CanReadSensitive},
        policy::{PolicyResult, mint_capability},
    };

    use super::*;
    use crate::http::RecordingHttpClient;

    struct PromptPolicy;

    impl PolicyEngine for PromptPolicy {
        fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
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

    struct AllowAllForTest;
    impl PolicyEngine for AllowAllForTest {
        fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
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
