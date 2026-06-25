use std::sync::Arc;

use jsonwebtoken::Algorithm;
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult},
};

use super::*;
use crate::http::StaticHttpClient;
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use typesec_core::typestate::{Authenticator, Credentials};

fn check(engine: &JwtClaimsEngine, subject: &str, action: &str, resource: &str) -> PolicyResult {
    engine.check(
        &SubjectId::from(subject),
        action,
        &ResourceId::from(resource),
    )
}

#[test]
fn jwt_claims_engine_allows_direct_permission() {
    let engine = JwtClaimsEngine::from_permissions("user_1", ["read".to_string()]);
    assert_eq!(
        check(&engine, "user_1", "read", "project/123"),
        PolicyResult::Allow
    );
}

#[test]
fn jwt_claims_engine_allows_resource_type_permission() {
    let engine = JwtClaimsEngine::from_permissions("user_1", ["project:edit".to_string()]);
    assert_eq!(
        check(&engine, "user_1", "edit", "project/123"),
        PolicyResult::Allow
    );
}

#[test]
fn jwt_claims_engine_delegates_missing_permission() {
    let engine = JwtClaimsEngine::from_permissions("user_1", ["read".to_string()]);
    assert!(matches!(
        check(&engine, "user_1", "write", "project/123"),
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
