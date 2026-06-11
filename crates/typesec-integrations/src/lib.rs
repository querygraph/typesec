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
pub mod workos;

pub use arcade::{ArcadeToolAuthEngine, ArcadeToolAuthRequest};
pub use did::{
    DemoDidKeyPair, DemoDidKeyStore, Did, DidDocument, DidEnvelope, DidError, DidKeyStore,
    DidMessageBody, DidMessageGateway, DidOllamaClient, DidResolver, DidService, StaticDidResolver,
    VerificationMethod, VerifiedDidPrompt,
};
pub use http::{HttpClient, ReqwestHttpClient};
pub use jwt::{JwtAuthenticator, JwtClaims, JwtClaimsEngine, OidcConfig, VerifiedSubject};
pub use workos::{WorkOsFgaEngine, WorkOsFgaRequest, WorkOsResource};
