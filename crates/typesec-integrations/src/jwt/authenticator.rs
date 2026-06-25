//! JWT authenticator that verifies tokens against a JWKS endpoint.

use std::sync::{Arc, RwLock};
use std::time::Instant;

use jsonwebtoken::{
    DecodingKey, TokenData, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet},
};
use typesec_core::typestate::{AgentError, Authenticator, Credentials};

use crate::http::{HttpClient, ReqwestHttpClient};

use super::claims::{JwtClaims, VerifiedSubject};
use super::config::OidcConfig;

/// JWT authenticator that verifies tokens against a JWKS endpoint.
pub struct JwtAuthenticator {
    config: OidcConfig,
    http: Arc<dyn HttpClient>,
    jwks: RwLock<Option<CachedJwks>>,
}

#[derive(Clone)]
struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
}

impl JwtAuthenticator {
    /// Create an authenticator using the default reqwest HTTP client.
    pub fn new(config: OidcConfig) -> Self {
        Self::with_http(config, Arc::new(ReqwestHttpClient::new()))
    }

    /// Create an authenticator with an injected HTTP client.
    pub fn with_http(config: OidcConfig, http: Arc<dyn HttpClient>) -> Self {
        Self {
            config,
            http,
            jwks: RwLock::new(None),
        }
    }

    /// Verify a bearer token and return its Typesec subject model.
    pub fn verify(&self, token: &str) -> Result<VerifiedSubject, JwtAuthError> {
        let data = self.decode_claims(token)?;
        if !data.claims.aud.contains(&self.config.audience) {
            return Err(JwtAuthError::InvalidAudience);
        }
        Ok(data.claims.into())
    }

    fn decode_claims(&self, token: &str) -> Result<TokenData<JwtClaims>, JwtAuthError> {
        let header = decode_header(token)?;
        let key = self.resolve_key(header.kid.as_deref())?;

        let mut validation = Validation::new(header.alg);
        validation.algorithms = self.config.algorithms.clone();
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);

        Ok(decode::<JwtClaims>(
            token,
            &DecodingKey::from_jwk(&key)?,
            &validation,
        )?)
    }

    /// Resolve the signing key for a token header.
    ///
    /// - With a `kid`: look it up in the cached JWKS; on a miss, re-fetch the
    ///   JWKS once (the IdP may have rotated keys) before failing.
    /// - Without a `kid`: only unambiguous key sets are accepted — if the JWKS
    ///   holds more than one key, the token is rejected rather than verified
    ///   against an arbitrary key.
    fn resolve_key(&self, kid: Option<&str>) -> Result<Jwk, JwtAuthError> {
        let jwks = self.jwks(false)?;
        match kid {
            Some(kid) => {
                if let Some(key) = jwks.find(kid) {
                    return Ok(key.clone());
                }
                // Unknown kid — refresh the JWKS once in case of key rotation.
                let jwks = self.jwks(true)?;
                jwks.find(kid).cloned().ok_or(JwtAuthError::MissingKey)
            }
            None => match jwks.keys.as_slice() {
                [only] => Ok(only.clone()),
                [] => Err(JwtAuthError::MissingKey),
                _ => Err(JwtAuthError::MissingKid),
            },
        }
    }

    fn jwks(&self, force_refresh: bool) -> Result<JwkSet, JwtAuthError> {
        if !force_refresh
            && let Some(cached) = self.jwks.read().expect("jwks lock poisoned").as_ref()
            && cached.fetched_at.elapsed() < self.config.jwks_ttl
        {
            return Ok(cached.keys.clone());
        }

        let value = self.http.get_json(&self.config.jwks_url, &[])?;
        let keys: JwkSet = serde_json::from_value(value)?;
        *self.jwks.write().expect("jwks lock poisoned") = Some(CachedJwks {
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });
        Ok(keys)
    }
}

impl Authenticator for JwtAuthenticator {
    /// Verify the credential token as a JWT and return the *verified* subject.
    ///
    /// If the credentials claim a subject, it must match the token's `sub`
    /// claim — a caller cannot authenticate as someone else's identity by
    /// pairing a valid token with a different claimed subject.
    fn verify_credentials(&self, credentials: &Credentials) -> Result<String, AgentError> {
        let verified =
            self.verify(credentials.token.expose())
                .map_err(|e| AgentError::AuthFailed {
                    reason: format!("jwt verification failed: {e}"),
                })?;
        if !credentials.subject.is_empty() && credentials.subject != verified.subject {
            return Err(AgentError::AuthFailed {
                reason: format!(
                    "claimed subject '{}' does not match verified token subject '{}'",
                    credentials.subject, verified.subject
                ),
            });
        }
        Ok(verified.subject)
    }
}

/// Errors returned by [`JwtAuthenticator`].
#[derive(Debug, thiserror::Error)]
pub enum JwtAuthError {
    /// Token validation failed.
    #[error("jwt validation failed: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    /// JWKS fetch failed.
    #[error("jwks fetch failed: {0}")]
    Http(#[from] Box<dyn std::error::Error + Send + Sync>),
    /// JWKS JSON could not be parsed.
    #[error("jwks parse failed: {0}")]
    Json(#[from] serde_json::Error),
    /// No matching signing key was found.
    #[error("no matching signing key found in JWKS")]
    MissingKey,
    /// The token has no `kid` and the JWKS holds multiple keys.
    #[error("token has no kid but JWKS is ambiguous (multiple keys)")]
    MissingKid,
    /// Token audience did not match the configured audience.
    #[error("token audience did not match expected audience")]
    InvalidAudience,
}
