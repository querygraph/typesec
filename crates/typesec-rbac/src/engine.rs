//! RBAC policy engine — implements [`PolicyEngine`] for [`RbacPolicy`].

mod flatten;

use std::collections::HashMap;

use tracing::debug;
use typesec_core::{
    ResourceId, SubjectId,
    glob::{GlobPattern, is_glob_pattern},
    policy::{PolicyEngine, PolicyResult},
};

use crate::model::RbacPolicy;
use flatten::flatten_role;

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
    subject_grants: HashMap<String, Vec<CompiledGrant>>,
    /// Glob subject pattern → set of effective grants.
    wildcard_subject_grants: Vec<(GlobPattern, Vec<CompiledGrant>)>,
}

/// A grant with its glob patterns validated and compiled once at load time.
///
/// Compiling here (rather than per `check()`) both surfaces pattern typos as
/// load errors — a malformed pattern would otherwise silently never match,
/// i.e. silently deny — and avoids re-parsing the glob on every check.
#[derive(Debug, Clone)]
struct CompiledGrant {
    permission: String,
    resource_patterns: Vec<GlobPattern>,
}

impl RbacEngine {
    /// Build an engine from a validated [`RbacPolicy`].
    ///
    /// Returns an error if the policy fails validation.
    pub fn new(policy: RbacPolicy) -> Result<Self, String> {
        policy.validate()?;

        // Step 1: flatten role inheritance into effective (permission, resources) pairs.
        let effective_roles: HashMap<String, Vec<flatten::Grant>> = {
            let mut map = HashMap::new();
            for role in &policy.roles {
                let grants = flatten_role(&role.name, &policy);
                map.insert(role.name.clone(), grants);
            }
            map
        };

        // Step 2: build subject → grants mapping, compiling patterns up front
        // so invalid globs fail the policy load instead of silently denying.
        let mut subject_grants: HashMap<String, Vec<CompiledGrant>> = HashMap::new();
        let mut wildcard_subject_grants: Vec<(GlobPattern, Vec<CompiledGrant>)> = Vec::new();
        for assignment in &policy.assignments {
            let mut all_grants: Vec<CompiledGrant> = Vec::new();
            for role_name in &assignment.roles {
                if let Some(grants) = effective_roles.get(role_name) {
                    for grant in grants {
                        all_grants.push(CompiledGrant {
                            permission: grant.permission.clone(),
                            resource_patterns: grant
                                .resource_patterns
                                .iter()
                                .map(|p| GlobPattern::compile(p, "resource"))
                                .collect::<Result<_, _>>()?,
                        });
                    }
                }
            }
            if is_glob_pattern(&assignment.subject) {
                wildcard_subject_grants.push((
                    GlobPattern::compile(&assignment.subject, "subject")?,
                    all_grants,
                ));
            } else {
                subject_grants
                    .entry(assignment.subject.clone())
                    .or_default()
                    .extend(all_grants);
            }
        }

        Ok(Self {
            subject_grants,
            wildcard_subject_grants,
        })
    }

    /// Load an engine directly from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let policy = RbacPolicy::from_yaml(yaml).map_err(|e| format!("YAML parse error: {e}"))?;
        Self::new(policy)
    }
}

impl PolicyEngine for RbacEngine {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
        debug!(subject, action, resource, "rbac check");

        let exact_grants = self.subject_grants.get(subject).into_iter().flatten();
        let wildcard_grants = self
            .wildcard_subject_grants
            .iter()
            .filter(|(pattern, _)| pattern.matches(subject))
            .flat_map(|(_, grants)| grants);

        let mut matched_subject = false;
        for grant in exact_grants.chain(wildcard_grants) {
            matched_subject = true;
            if grant.permission == action {
                for pattern in &grant.resource_patterns {
                    if pattern.matches(resource) {
                        return PolicyResult::Allow;
                    }
                }
            }
        }

        if !matched_subject {
            return PolicyResult::Deny(format!("no role assignments for subject '{subject}'"));
        }

        PolicyResult::Deny(format!(
            "no rule grants '{subject}' permission '{action}' on '{resource}'"
        ))
    }
}

#[cfg(test)]
mod tests;
