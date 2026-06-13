//! Arcade-style tool authorization integration.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;
use typesec_core::policy::{PolicyEngine, PolicyResult};

use crate::http::{HttpClient, ReqwestHttpClient};

/// Request body used to ask Arcade whether a tool is authorized for a user.
#[derive(Debug, Clone, Serialize)]
pub struct ArcadeToolAuthRequest {
    /// Arcade tool name, for example `Gmail.ListEmails`.
    pub tool_name: String,
    /// End-user identifier known to Arcade.
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
struct ArcadeToolAuthResponse {
    status: String,
    #[serde(default)]
    url: Option<String>,
}

/// Policy engine that checks whether a user has authorized an external tool.
///
/// The engine maps Typesec resource ids to Arcade tool names. A resource id may
/// either be present in the explicit mapping or already look like an Arcade tool
/// name such as `Gmail.ListEmails`.
pub struct ArcadeToolAuthEngine {
    api_key: String,
    base_url: String,
    tool_map: HashMap<String, String>,
    http: Arc<dyn HttpClient>,
}

impl ArcadeToolAuthEngine {
    /// Create an engine using `https://api.arcade.dev`.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_http(
            api_key,
            "https://api.arcade.dev",
            Arc::new(ReqwestHttpClient::new()),
        )
    }

    /// Create an engine with custom base URL and HTTP client.
    pub fn with_http(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            tool_map: HashMap::new(),
            http,
        }
    }

    /// Map a Typesec resource id to an Arcade tool name.
    pub fn with_tool_mapping(
        mut self,
        resource: impl Into<String>,
        tool: impl Into<String>,
    ) -> Self {
        self.tool_map.insert(resource.into(), tool.into());
        self
    }

    fn tool_name_for<'a>(&'a self, resource: &'a str) -> Option<&'a str> {
        self.tool_map
            .get(resource)
            .map(String::as_str)
            .or_else(|| resource.contains('.').then_some(resource))
    }
}

impl PolicyEngine for ArcadeToolAuthEngine {
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        debug!(subject, action, resource, "arcade tool authorization check");

        if action != "execute" && action != "read" && action != "write" {
            return PolicyResult::delegate(
                "arcade",
                format!("Arcade tool auth does not handle action '{action}'"),
            );
        }

        let Some(tool_name) = self.tool_name_for(resource) else {
            return PolicyResult::delegate(
                "arcade",
                format!("no Arcade tool mapping for resource '{resource}'"),
            );
        };

        let url = format!("{}/v1/tools/authorize", self.base_url);
        let body = json!({
            "tool_name": tool_name,
            "user_id": subject,
        });
        let headers = [("Authorization", format!("Bearer {}", self.api_key))];

        match self.http.post_json(&url, &headers, &body) {
            Ok(value) => match serde_json::from_value::<ArcadeToolAuthResponse>(value) {
                Ok(response) if response.status == "completed" => PolicyResult::Allow,
                Ok(response) => {
                    let url = response
                        .url
                        .map(|url| format!("; authorize at {url}"))
                        .unwrap_or_default();
                    PolicyResult::Deny(format!(
                        "Arcade authorization for tool '{tool_name}' is '{}'{}",
                        response.status, url
                    ))
                }
                Err(err) => PolicyResult::Deny(format!("Arcade response parse error: {err}")),
            },
            Err(err) => PolicyResult::Deny(format!("Arcade authorization check failed: {err}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::StaticHttpClient;
    use serde_json::json;

    #[test]
    fn allows_completed_authorization() {
        let http = StaticHttpClient::new().with_response(
            "https://api.arcade.test/v1/tools/authorize",
            json!({ "status": "completed" }),
        );
        let engine =
            ArcadeToolAuthEngine::with_http("arc_test", "https://api.arcade.test", Arc::new(http))
                .with_tool_mapping("gmail/list", "Gmail.ListEmails");

        assert_eq!(
            engine.check("user@example.com", "execute", "gmail/list"),
            PolicyResult::Allow
        );
    }

    #[test]
    fn denies_pending_authorization_with_url() {
        let http = StaticHttpClient::new().with_response(
            "https://api.arcade.test/v1/tools/authorize",
            json!({ "status": "pending", "url": "https://authorize.example" }),
        );
        let engine =
            ArcadeToolAuthEngine::with_http("arc_test", "https://api.arcade.test", Arc::new(http))
                .with_tool_mapping("gmail/list", "Gmail.ListEmails");

        let result = engine.check("user@example.com", "execute", "gmail/list");
        assert!(matches!(result, PolicyResult::Deny(reason) if reason.contains("authorize")));
    }
}
