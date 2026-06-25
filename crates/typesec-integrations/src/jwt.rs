//! JWT/OIDC authentication helpers and a fast claims-backed policy engine.

mod authenticator;
mod claims;
mod config;
mod engine;

pub use authenticator::{JwtAuthError, JwtAuthenticator};
pub use claims::{Audience, JwtClaims, VerifiedSubject};
pub use config::OidcConfig;
pub use engine::JwtClaimsEngine;

#[cfg(test)]
mod tests;
