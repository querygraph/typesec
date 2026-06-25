//! DID integration error type.

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
