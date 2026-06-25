//! Arcade-style tool authorization integration.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult},
};

use crate::http::HttpClient;
use crate::provider::{ProviderHttpEngine, ProviderHttpError};

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
    engine: ProviderHttpEngine,
    tool_map: HashMap<String, String>,
}

impl ArcadeToolAuthEngine {
    /// Create an engine using `https://api.arcade.dev`.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            engine: ProviderHttpEngine::new(api_key, "https://api.arcade.dev"),
            tool_map: HashMap::new(),
        }
    }

    /// Create an engine with custom base URL and HTTP client.
    pub fn with_http(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            engine: ProviderHttpEngine::with_http(api_key, base_url, http),
            tool_map: HashMap::new(),
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
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
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

        let url = format!("{}/v1/tools/authorize", self.engine.base_url());
        let body = json!({
            "tool_name": tool_name,
            "user_id": subject,
        });

        match self
            .engine
            .bearer_post::<ArcadeToolAuthResponse>(&url, &body)
        {
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
            Err(ProviderHttpError::Parse(err)) => {
                PolicyResult::Deny(format!("Arcade response parse error: {err}"))
            }
            Err(ProviderHttpError::Transport(err)) => {
                PolicyResult::Deny(format!("Arcade authorization check failed: {err}"))
            }
        }
    }
}

#[cfg(test)]
mod tests;
