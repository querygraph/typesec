//! OIDC validation settings.

use std::time::Duration;

use jsonwebtoken::Algorithm;

/// OIDC validation settings.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Expected issuer claim.
    pub issuer: String,
    /// Expected audience claim.
    pub audience: String,
    /// JWKS endpoint used to resolve signing keys.
    pub jwks_url: String,
    /// Accepted signing algorithms.
    pub algorithms: Vec<Algorithm>,
    /// How long fetched JWKS keys are cached before re-fetching.
    ///
    /// The cache is also refreshed eagerly when a token references an unknown
    /// `kid`, so key rotation at the IdP is picked up without a restart.
    pub jwks_ttl: Duration,
}

impl OidcConfig {
    /// Create a config using RS256, the common AuthKit/OIDC default.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_url: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            jwks_url: jwks_url.into(),
            algorithms: vec![Algorithm::RS256],
            jwks_ttl: Duration::from_secs(300),
        }
    }
}
