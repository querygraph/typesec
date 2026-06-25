//! Provider integrations for using Typesec behind external identity systems.
//!
//! This crate keeps external identity and authorization services at the edge of
//! the system while preserving the core Typesec invariant: provider decisions
//! become typed capabilities only through [`typesec_core::mint_capability`].

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod arcade;
pub mod did;
pub mod http;
pub mod jwt;
mod provider;
pub mod pydantic_ai;
pub mod workos;

pub use arcade::{ArcadeToolAuthEngine, ArcadeToolAuthRequest};
pub use did::{
    A2aTypeDidAdapter, AcpTypeDidAdapter, BandSecureEnvelopeAdapter, Did, DidDocument, DidEnvelope,
    DidError, DidKeyStore, DidMessageBody, DidMessageGateway, DidMessageReference, DidOllamaClient,
    DidReplyBinding, DidResolver, DidService, Ed25519DidKey, Ed25519DidKeyStore,
    HttpTypeDidAdapter, SecureEnvelopeAdapter, StaticDidResolver, StaticTypeDidProfileResolver,
    TypeDidAttestation, TypeDidConversation, TypeDidGateway, TypeDidMode, TypeDidProfile,
    TypeDidProfileResolver, TypeDidWrapRequest, VerificationMethod, VerifiedDidPrompt,
    VerifiedTypeDidMessage,
};
#[cfg(feature = "demo-crypto")]
pub use did::{DemoDidKeyPair, DemoDidKeyStore};
pub use http::{HttpClient, ReqwestHttpClient};
pub use jwt::{JwtAuthenticator, JwtClaims, JwtClaimsEngine, OidcConfig, VerifiedSubject};
pub use pydantic_ai::{PydanticAiCapability, PydanticAiToolCapability};
pub use workos::{WorkOsFgaEngine, WorkOsFgaRequest, WorkOsResource};
