//! Key-store and envelope crypto boundary, plus the production Ed25519/X25519
//! key store.

use std::collections::{HashMap, HashSet};

use super::crypto::{hex_decode, hex_encode, sha256_tagged};
use super::document::{DidDocument, VerificationMethod};
use super::error::DidError;
use super::identifier::Did;

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
