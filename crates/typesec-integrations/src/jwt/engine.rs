//! Policy engine backed by verified JWT permission claims.

use std::collections::HashSet;

use serde_json::Value;
use tracing::debug;
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult},
};

use super::claims::VerifiedSubject;

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
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
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
