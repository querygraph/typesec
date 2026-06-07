//! RBAC policy engine — implements [`PolicyEngine`] for [`RbacPolicy`].

use std::collections::{HashMap, HashSet};

use glob::Pattern;
use tracing::debug;
use typesec_core::policy::{PolicyEngine, PolicyResult};

use crate::model::RbacPolicy;

/// A compiled, fast-lookup RBAC engine.
///
/// After construction from an [`RbacPolicy`], the engine pre-computes:
/// - Effective permissions per role (with inheritance flattened).
/// - Subject → role mappings.
///
/// Every `check()` call does O(roles × patterns) work — fast enough for
/// the sizes of policies used in AI agent deployments.
pub struct RbacEngine {
    /// Subject → set of effective (permission, resource_pattern) pairs.
    subject_grants: HashMap<String, Vec<Grant>>,
}

#[derive(Debug, Clone)]
struct Grant {
    permission: String,
    resource_patterns: Vec<String>,
}

impl RbacEngine {
    /// Build an engine from a validated [`RbacPolicy`].
    ///
    /// Returns an error if the policy fails validation.
    pub fn new(policy: RbacPolicy) -> Result<Self, String> {
        policy.validate()?;

        // Step 1: flatten role inheritance into effective (permission, resources) pairs.
        let effective_roles: HashMap<String, Vec<Grant>> = {
            let mut map = HashMap::new();
            for role in &policy.roles {
                let grants = flatten_role(&role.name, &policy);
                map.insert(role.name.clone(), grants);
            }
            map
        };

        // Step 2: build subject → grants mapping.
        let mut subject_grants: HashMap<String, Vec<Grant>> = HashMap::new();
        for assignment in &policy.assignments {
            let mut all_grants: Vec<Grant> = Vec::new();
            for role_name in &assignment.roles {
                if let Some(grants) = effective_roles.get(role_name) {
                    all_grants.extend(grants.iter().cloned());
                }
            }
            subject_grants
                .entry(assignment.subject.clone())
                .or_default()
                .extend(all_grants);
        }

        Ok(Self { subject_grants })
    }

    /// Load an engine directly from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let policy = RbacPolicy::from_yaml(yaml).map_err(|e| format!("YAML parse error: {e}"))?;
        Self::new(policy)
    }
}

impl PolicyEngine for RbacEngine {
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        debug!(subject, action, resource, "rbac check");

        let grants = match self.subject_grants.get(subject) {
            Some(g) => g,
            None => {
                return PolicyResult::Deny(format!("no role assignments for subject '{subject}'"));
            }
        };

        for grant in grants {
            if grant.permission == action {
                for pattern in &grant.resource_patterns {
                    if matches_glob(pattern, resource) {
                        return PolicyResult::Allow;
                    }
                }
            }
        }

        PolicyResult::Deny(format!(
            "no rule grants '{subject}' permission '{action}' on '{resource}'"
        ))
    }
}

/// Recursively flatten a role's permissions by resolving inheritance.
fn flatten_role(role_name: &str, policy: &RbacPolicy) -> Vec<Grant> {
    let mut seen = HashSet::new();
    flatten_role_inner(role_name, policy, &mut seen)
}

fn flatten_role_inner(
    role_name: &str,
    policy: &RbacPolicy,
    seen: &mut HashSet<String>,
) -> Vec<Grant> {
    if !seen.insert(role_name.to_owned()) {
        return vec![]; // cycle guard (already validated, but be safe)
    }

    let role = match policy.roles.iter().find(|r| r.name == role_name) {
        Some(r) => r,
        None => return vec![],
    };

    let mut grants: Vec<Grant> = Vec::new();

    // Own permissions.
    for perm in &role.permissions {
        grants.push(Grant {
            permission: perm.clone(),
            resource_patterns: role.resources.clone(),
        });
    }

    // Inherited permissions (recursive).
    for parent_name in &role.inherits {
        let inherited = flatten_role_inner(parent_name, policy, seen);
        grants.extend(inherited);
    }

    grants
}

/// Match a resource string against a glob pattern.
/// Uses the `glob` crate — patterns like `"reports/*"` or `"*"`.
fn matches_glob(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    Pattern::new(pattern).is_ok_and(|p| p.matches(resource))
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
roles:
  - name: analyst
    permissions: [read, read_sensitive]
    resources: ["reports/*", "metrics/*"]
  - name: engineer
    permissions: [read, write, execute]
    resources: ["code/*", "infra/*"]
  - name: admin
    inherits: [analyst, engineer]
    permissions: [delete, delegate]
    resources: ["*"]

assignments:
  - subject: "agent:data-pipeline"
    roles: [analyst]
  - subject: "agent:deploy-bot"
    roles: [engineer]
  - subject: "agent:superuser"
    roles: [admin]
"#;

    fn engine() -> RbacEngine {
        RbacEngine::from_yaml(YAML).expect("engine build should succeed")
    }

    #[test]
    fn analyst_can_read_reports() {
        let e = engine();
        assert_eq!(
            e.check("agent:data-pipeline", "read", "reports/q1"),
            PolicyResult::Allow
        );
    }

    #[test]
    fn analyst_cannot_write() {
        let e = engine();
        assert!(matches!(
            e.check("agent:data-pipeline", "write", "reports/q1"),
            PolicyResult::Deny(_)
        ));
    }

    #[test]
    fn engineer_can_write_code() {
        let e = engine();
        assert_eq!(
            e.check("agent:deploy-bot", "write", "code/main.rs"),
            PolicyResult::Allow
        );
    }

    #[test]
    fn engineer_cannot_access_reports() {
        let e = engine();
        assert!(matches!(
            e.check("agent:deploy-bot", "read", "reports/q1"),
            PolicyResult::Deny(_)
        ));
    }

    #[test]
    fn admin_inherits_analyst_and_engineer() {
        let e = engine();
        // Inherited from analyst:
        assert_eq!(
            e.check("agent:superuser", "read_sensitive", "reports/q1"),
            PolicyResult::Allow
        );
        // Inherited from engineer:
        assert_eq!(
            e.check("agent:superuser", "execute", "code/deploy.sh"),
            PolicyResult::Allow
        );
        // Own permissions:
        assert_eq!(
            e.check("agent:superuser", "delete", "anything"),
            PolicyResult::Allow
        );
    }

    #[test]
    fn unknown_subject_is_denied() {
        let e = engine();
        assert!(matches!(
            e.check("agent:ghost", "read", "reports/q1"),
            PolicyResult::Deny(_)
        ));
    }
}
