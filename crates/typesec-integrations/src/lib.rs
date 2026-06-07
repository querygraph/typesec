//! Provider integrations for using Typesec behind OAuth/OIDC systems.
//!
//! This crate keeps external identity and authorization services at the edge of
//! the system while preserving the core Typesec invariant: provider decisions
//! become typed capabilities only through [`typesec_core::mint_capability`].

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod arcade;
pub mod http;
pub mod jwt;
pub mod workos;

pub use arcade::{ArcadeToolAuthEngine, ArcadeToolAuthRequest};
pub use http::{HttpClient, ReqwestHttpClient};
pub use jwt::{JwtAuthenticator, JwtClaims, JwtClaimsEngine, OidcConfig, VerifiedSubject};
pub use workos::{WorkOsFgaEngine, WorkOsFgaRequest, WorkOsResource};
