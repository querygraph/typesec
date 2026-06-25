//! Shared HTTP plumbing for provider-backed [`PolicyEngine`]s.
//!
//! WorkOS FGA and Arcade tool-auth are both thin `Bearer`-token shells over the
//! same `post_json` → parse-typed-response flow. This module factors out that
//! shared shell so each engine only owns its resource mapping and decision
//! logic.
//!
//! [`PolicyEngine`]: typesec_core::policy::PolicyEngine

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::http::{HttpClient, ReqwestHttpClient};

/// A `Bearer`-token JSON HTTP shell shared by provider policy engines.
///
/// Holds the API key, a normalized base URL (trailing `/` trimmed), and the
/// HTTP client, and performs authenticated `POST` requests that deserialize the
/// JSON response into a typed value.
pub(crate) struct ProviderHttpEngine {
    api_key: String,
    base_url: String,
    http: Arc<dyn HttpClient>,
}

impl ProviderHttpEngine {
    /// Create an engine with the production reqwest HTTP client.
    pub(crate) fn new(api_key: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self::with_http(api_key, base_url, Arc::new(ReqwestHttpClient::new()))
    }

    /// Create an engine with an injected HTTP client.
    pub(crate) fn with_http(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    /// The normalized base URL (no trailing slash).
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    /// POST `body` to `url` with a `Bearer` authorization header and decode the
    /// JSON response into `Resp`.
    ///
    /// Transport and deserialization failures are distinguished via
    /// [`ProviderHttpError`] so callers can keep their existing, provider-named
    /// error messages.
    pub(crate) fn bearer_post<Resp: DeserializeOwned>(
        &self,
        url: &str,
        body: &Value,
    ) -> Result<Resp, ProviderHttpError> {
        let headers = [("Authorization", format!("Bearer {}", self.api_key))];
        let value = self
            .http
            .post_json(url, &headers, body)
            .map_err(|err| ProviderHttpError::Transport(err.to_string()))?;
        serde_json::from_value(value).map_err(|err| ProviderHttpError::Parse(err.to_string()))
    }
}

/// Failure mode of a [`ProviderHttpEngine::bearer_post`] call.
pub(crate) enum ProviderHttpError {
    /// The HTTP request itself failed.
    Transport(String),
    /// The JSON response could not be deserialized into the expected type.
    Parse(String),
}
