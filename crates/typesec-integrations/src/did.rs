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

mod crypto;
mod document;
mod envelope;
mod error;
mod gateway;
mod identifier;
mod keystore;
#[cfg(any(test, feature = "demo-crypto"))]
mod keystore_demo;
mod ollama;
mod typedid;

pub use document::{DidDocument, DidResolver, DidService, StaticDidResolver, VerificationMethod};
pub use envelope::{DidEnvelope, DidMessageBody, DidMessageReference, DidReplyBinding};
pub use error::DidError;
pub use gateway::{
    DidMessageGateway, TypeDidAttestation, TypeDidGateway, VerifiedDidPrompt,
    VerifiedTypeDidMessage,
};
pub use identifier::Did;
pub use keystore::{DidKeyStore, Ed25519DidKey, Ed25519DidKeyStore};
#[cfg(any(test, feature = "demo-crypto"))]
pub use keystore_demo::{DemoDidKeyPair, DemoDidKeyStore};
pub use ollama::DidOllamaClient;
pub use typedid::{
    A2aTypeDidAdapter, AcpTypeDidAdapter, BandSecureEnvelopeAdapter, HttpTypeDidAdapter,
    SecureEnvelopeAdapter, StaticTypeDidProfileResolver, TypeDidConversation, TypeDidMode,
    TypeDidProfile, TypeDidProfileResolver, TypeDidWrapRequest,
};

#[cfg(test)]
mod tests;
