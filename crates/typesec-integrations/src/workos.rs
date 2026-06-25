//! WorkOS Fine-Grained Authorization integration.

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

/// A WorkOS resource identifier parsed from a Typesec resource id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkOsResource {
    /// WorkOS resource type slug, for example `project`.
    pub resource_type_slug: String,
    /// Application-level external resource id.
    pub resource_external_id: String,
}

impl WorkOsResource {
    /// Parse `type/id` or `type:id` into a WorkOS resource reference.
    pub fn parse(resource: &str) -> Option<Self> {
        let (resource_type_slug, resource_external_id) = resource
            .split_once('/')
            .or_else(|| resource.split_once(':'))?;
        if resource_type_slug.is_empty() || resource_external_id.is_empty() {
            return None;
        }
        Some(Self {
            resource_type_slug: resource_type_slug.to_string(),
            resource_external_id: resource_external_id.to_string(),
        })
    }
}

/// JSON body sent to the WorkOS authorization check endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct WorkOsFgaRequest {
    /// Permission slug to check.
    pub permission_slug: String,
    /// Resource type slug.
    pub resource_type_slug: String,
    /// External resource id.
    pub resource_external_id: String,
}

#[derive(Debug, Deserialize)]
struct WorkOsFgaResponse {
    authorized: bool,
}

/// Policy engine that delegates resource checks to WorkOS FGA.
pub struct WorkOsFgaEngine {
    engine: ProviderHttpEngine,
}

impl WorkOsFgaEngine {
    /// Create an engine using `https://api.workos.com`.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            engine: ProviderHttpEngine::new(api_key, "https://api.workos.com"),
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
        }
    }

    fn request_for(&self, action: &str, resource: &str) -> Result<WorkOsFgaRequest, String> {
        let resource = WorkOsResource::parse(resource)
            .ok_or_else(|| format!("resource '{resource}' is not formatted as type/id"))?;
        Ok(WorkOsFgaRequest {
            permission_slug: permission_slug(action, &resource.resource_type_slug),
            resource_type_slug: resource.resource_type_slug,
            resource_external_id: resource.resource_external_id,
        })
    }
}

impl PolicyEngine for WorkOsFgaEngine {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
        debug!(subject, action, resource, "workos fga check");

        let request = match self.request_for(action, resource) {
            Ok(request) => request,
            Err(reason) => return PolicyResult::delegate("workos", reason),
        };

        let url = format!(
            "{}/authorization/organization_memberships/{}/check",
            self.engine.base_url(),
            subject
        );
        let body = json!({
            "permission_slug": request.permission_slug,
            "resource_type_slug": request.resource_type_slug,
            "resource_external_id": request.resource_external_id,
        });

        match self.engine.bearer_post::<WorkOsFgaResponse>(&url, &body) {
            Ok(response) if response.authorized => PolicyResult::Allow,
            Ok(_) => PolicyResult::Deny(format!(
                "WorkOS denied '{subject}' permission '{action}' on '{resource}'"
            )),
            Err(ProviderHttpError::Parse(err)) => {
                PolicyResult::Deny(format!("WorkOS response parse error: {err}"))
            }
            Err(ProviderHttpError::Transport(err)) => {
                PolicyResult::Deny(format!("WorkOS FGA check failed: {err}"))
            }
        }
    }
}

fn permission_slug(action: &str, resource_type: &str) -> String {
    if action.contains(':') {
        action.to_string()
    } else {
        format!("{resource_type}:{action}")
    }
}

#[cfg(test)]
mod tests;
