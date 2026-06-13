//! JWT/OIDC authentication helpers and a fast claims-backed policy engine.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;
use typesec_core::policy::{PolicyEngine, PolicyResult};
use typesec_core::typestate::{AgentError, Authenticator, Credentials};

use crate::http::{HttpClient, ReqwestHttpClient};

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

/// Claims Typesec cares about from an access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject identifier.
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience. Some providers encode this as a string, others as a list.
    pub aud: Audience,
    /// Expiration timestamp.
    pub exp: usize,
    /// Optional organization identifier.
    #[serde(default)]
    pub org_id: Option<String>,
    /// Optional organization membership identifier.
    #[serde(default)]
    pub organization_membership_id: Option<String>,
    /// Optional role.
    #[serde(default)]
    pub role: Option<String>,
    /// Optional permission list.
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// JWT audience represented as either a string or list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// Single audience.
    Single(String),
    /// Multiple audiences.
    Multiple(Vec<String>),
}

impl Audience {
    fn contains(&self, needle: &str) -> bool {
        match self {
            Self::Single(value) => value == needle,
            Self::Multiple(values) => values.iter().any(|value| value == needle),
        }
    }
}

/// Verified identity extracted from an OIDC/JWT access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSubject {
    /// Subject identifier.
    pub subject: String,
    /// Optional organization identifier.
    pub org_id: Option<String>,
    /// Optional organization membership identifier.
    pub organization_membership_id: Option<String>,
    /// Role names carried by the token.
    pub roles: Vec<String>,
    /// Permission names carried by the token.
    pub permissions: Vec<String>,
}

impl VerifiedSubject {
    /// Return the best subject identifier for WorkOS FGA checks.
    pub fn workos_membership_subject(&self) -> &str {
        self.organization_membership_id
            .as_deref()
            .unwrap_or(&self.subject)
    }
}

impl From<JwtClaims> for VerifiedSubject {
    fn from(claims: JwtClaims) -> Self {
        Self {
            subject: claims.sub,
            org_id: claims.org_id,
            organization_membership_id: claims.organization_membership_id,
            roles: claims.role.into_iter().collect(),
            permissions: claims.permissions,
        }
    }
}

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

/// Policy engine backed by verified JWT permission claims.
///
/// This is intended as the fast first layer in a composed engine: allow obvious
/// org-wide permissions from the token and delegate resource-specific decisions
/// to RBAC, ODRL, WorkOS FGA, or another precise engine.
pub struct JwtClaimsEngine {
    subject: String,
    permissions: HashSet<String>,
    org_id: Option<String>,
}

impl JwtClaimsEngine {
    /// Build an engine from a verified subject.
    pub fn new(subject: VerifiedSubject) -> Self {
        Self {
            subject: subject.subject,
            permissions: subject.permissions.into_iter().collect(),
            org_id: subject.org_id,
        }
    }

    /// Build an engine from raw permission strings.
    pub fn from_permissions(
        subject: impl Into<String>,
        permissions: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            permissions: permissions.into_iter().collect(),
            org_id: None,
        }
    }

    fn permission_matches(&self, action: &str, resource: &str) -> bool {
        if self.permissions.contains(action) {
            return true;
        }

        let resource_type = resource.split(['/', ':']).next().unwrap_or(resource);
        self.permissions
            .contains(&format!("{resource_type}:{action}"))
    }
}

impl PolicyEngine for JwtClaimsEngine {
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        debug!(subject, action, resource, org_id = ?self.org_id, "jwt claims check");

        if subject != self.subject {
            return PolicyResult::delegate(
                "jwt",
                format!("jwt claims are for '{}', not '{subject}'", self.subject),
            );
        }

        if self.permission_matches(action, resource) {
            PolicyResult::Allow
        } else {
            PolicyResult::delegate(
                "jwt",
                format!("permission '{action}' not present in jwt claims"),
            )
        }
    }
}

#[allow(dead_code)]
fn _assert_value_send_sync(_: Value) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::StaticHttpClient;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    #[test]
    fn jwt_claims_engine_allows_direct_permission() {
        let engine = JwtClaimsEngine::from_permissions("user_1", ["read".to_string()]);
        assert_eq!(
            engine.check("user_1", "read", "project/123"),
            PolicyResult::Allow
        );
    }

    #[test]
    fn jwt_claims_engine_allows_resource_type_permission() {
        let engine = JwtClaimsEngine::from_permissions("user_1", ["project:edit".to_string()]);
        assert_eq!(
            engine.check("user_1", "edit", "project/123"),
            PolicyResult::Allow
        );
    }

    #[test]
    fn jwt_claims_engine_delegates_missing_permission() {
        let engine = JwtClaimsEngine::from_permissions("user_1", ["read".to_string()]);
        assert!(matches!(
            engine.check("user_1", "write", "project/123"),
            PolicyResult::Delegate(_)
        ));
    }

    #[test]
    fn jwt_authenticator_verifies_hs256_token_from_jwks() {
        let jwks_url = "https://issuer.example/.well-known/jwks.json";
        let http = StaticHttpClient::new().with_response(
            jwks_url,
            json!({
                "keys": [{
                    "kty": "oct",
                    "kid": "test-key",
                    "alg": "HS256",
                    "k": "c2VjcmV0"
                }]
            }),
        );
        let mut config = OidcConfig::new("https://issuer.example", "typesec-test", jwks_url);
        config.algorithms = vec![Algorithm::HS256];
        let auth = JwtAuthenticator::with_http(config, Arc::new(http));

        let claims = JwtClaims {
            sub: "user_123".to_string(),
            iss: "https://issuer.example".to_string(),
            aud: Audience::Single("typesec-test".to_string()),
            exp: (Utc::now() + Duration::minutes(10)).timestamp() as usize,
            org_id: Some("org_123".to_string()),
            organization_membership_id: Some("om_123".to_string()),
            role: Some("org_member".to_string()),
            permissions: vec!["org:view".to_string(), "project:read".to_string()],
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".to_string());
        let token = encode(&header, &claims, &EncodingKey::from_secret(b"secret"))
            .expect("token should encode");

        let verified = auth.verify(&token).expect("token should verify");
        assert_eq!(verified.subject, "user_123");
        assert_eq!(verified.workos_membership_subject(), "om_123");
        assert_eq!(verified.permissions, vec!["org:view", "project:read"]);
    }

    #[test]
    fn jwt_authenticator_rejects_wrong_audience() {
        let jwks_url = "https://issuer.example/.well-known/jwks.json";
        let http = StaticHttpClient::new().with_response(
            jwks_url,
            json!({
                "keys": [{
                    "kty": "oct",
                    "kid": "test-key",
                    "alg": "HS256",
                    "k": "c2VjcmV0"
                }]
            }),
        );
        let mut config = OidcConfig::new("https://issuer.example", "typesec-test", jwks_url);
        config.algorithms = vec![Algorithm::HS256];
        let auth = JwtAuthenticator::with_http(config, Arc::new(http));

        let claims = JwtClaims {
            sub: "user_123".to_string(),
            iss: "https://issuer.example".to_string(),
            aud: Audience::Single("other-audience".to_string()),
            exp: (Utc::now() + Duration::minutes(10)).timestamp() as usize,
            org_id: None,
            organization_membership_id: None,
            role: None,
            permissions: vec![],
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".to_string());
        let token = encode(&header, &claims, &EncodingKey::from_secret(b"secret"))
            .expect("token should encode");

        assert!(auth.verify(&token).is_err());
    }

    fn hs256_config_and_jwks(jwks_url: &str) -> (OidcConfig, serde_json::Value) {
        let mut config = OidcConfig::new("https://issuer.example", "typesec-test", jwks_url);
        config.algorithms = vec![Algorithm::HS256];
        let jwks = json!({
            "keys": [{
                "kty": "oct",
                "kid": "test-key",
                "alg": "HS256",
                "k": "c2VjcmV0"
            }]
        });
        (config, jwks)
    }

    fn hs256_token(kid: Option<&str>) -> String {
        let claims = JwtClaims {
            sub: "user_123".to_string(),
            iss: "https://issuer.example".to_string(),
            aud: Audience::Single("typesec-test".to_string()),
            exp: (Utc::now() + Duration::minutes(10)).timestamp() as usize,
            org_id: None,
            organization_membership_id: None,
            role: None,
            permissions: vec![],
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = kid.map(str::to_owned);
        encode(&header, &claims, &EncodingKey::from_secret(b"secret")).expect("token encodes")
    }

    #[test]
    fn unknown_kid_triggers_one_jwks_refetch() {
        use crate::http::RecordingHttpClient;
        let jwks_url = "https://issuer.example/.well-known/jwks.json";
        let (config, jwks) = hs256_config_and_jwks(jwks_url);
        let http = RecordingHttpClient::new().with_response(jwks_url, jwks);
        let auth = JwtAuthenticator::with_http(config, Arc::new(http.clone()));

        let token = hs256_token(Some("rotated-away-key"));
        let result = auth.verify(&token);

        assert!(matches!(result, Err(JwtAuthError::MissingKey)));
        // Initial fetch + one rotation-driven refetch, no more.
        assert_eq!(http.requests().len(), 2);
    }

    #[test]
    fn missing_kid_with_multiple_keys_is_rejected() {
        let jwks_url = "https://issuer.example/.well-known/jwks.json";
        let (config, _) = hs256_config_and_jwks(jwks_url);
        let http = StaticHttpClient::new().with_response(
            jwks_url,
            json!({
                "keys": [
                    { "kty": "oct", "kid": "a", "alg": "HS256", "k": "c2VjcmV0" },
                    { "kty": "oct", "kid": "b", "alg": "HS256", "k": "b3RoZXI" }
                ]
            }),
        );
        let auth = JwtAuthenticator::with_http(config, Arc::new(http));

        let token = hs256_token(None);
        assert!(matches!(auth.verify(&token), Err(JwtAuthError::MissingKid)));
    }

    #[test]
    fn authenticator_rejects_mismatched_claimed_subject() {
        let jwks_url = "https://issuer.example/.well-known/jwks.json";
        let (config, jwks) = hs256_config_and_jwks(jwks_url);
        let http = StaticHttpClient::new().with_response(jwks_url, jwks);
        let auth = JwtAuthenticator::with_http(config, Arc::new(http));
        let token = hs256_token(Some("test-key"));

        // Claiming someone else's identity with a valid token must fail.
        let mismatched = Credentials::new("user_999", token.clone());
        assert!(auth.verify_credentials(&mismatched).is_err());

        // The verified subject wins; an empty claimed subject is allowed.
        let unclaimed = Credentials::new("", token);
        assert_eq!(
            auth.verify_credentials(&unclaimed).expect("verifies"),
            "user_123"
        );
    }
}
