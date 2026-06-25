//! Serde data model for RBAC YAML policies.

use serde::{Deserialize, Serialize};

/// The root of an RBAC policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacPolicy {
    /// Role definitions.
    pub roles: Vec<RoleDefinition>,
    /// Subject → role assignments.
    #[serde(default)]
    pub assignments: Vec<Assignment>,
}

/// A role with its permission set and resource patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// The role's canonical name.
    pub name: String,
    /// Permissions granted by this role (must match `Permission::name()` values).
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Glob patterns for resources this role applies to.
    #[serde(default)]
    pub resources: Vec<String>,
    /// Roles whose permissions this role inherits.
    #[serde(default)]
    pub inherits: Vec<String>,
}

/// Maps a subject to one or more roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    /// The subject identifier (e.g., `"agent:data-pipeline"`).
    pub subject: String,
    /// The roles assigned to this subject.
    pub roles: Vec<String>,
}

impl RbacPolicy {
    /// Parse an RBAC policy from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Validate the policy: check that `inherits` references valid role names,
    /// and that there are no circular inheritance chains.
    pub fn validate(&self) -> Result<(), String> {
        let names: std::collections::HashSet<&str> =
            self.roles.iter().map(|r| r.name.as_str()).collect();

        for role in &self.roles {
            for parent in &role.inherits {
                if !names.contains(parent.as_str()) {
                    return Err(format!(
                        "role '{}' inherits from unknown role '{}'",
                        role.name, parent
                    ));
                }
            }
        }

        // Detect cycles via DFS. `walk_inheritance` surfaces a circular chain as
        // an error; the visitor is a no-op because we only care about the walk
        // completing without a cycle.
        for role in &self.roles {
            walk_inheritance(&role.name, self, &mut |_| {})?;
        }

        Ok(())
    }
}

/// Depth-first walk over a role's inheritance closure.
///
/// Starting at `start`, this visits the role itself and then each role it
/// transitively `inherits`, in declaration order, calling `visit` exactly once
/// per reachable role. Roles are found by linear scan; an `inherits` entry that
/// names no known role is silently skipped (unknown-parent validation lives in
/// [`RbacPolicy::validate`]).
///
/// A circular inheritance chain is reported as
/// `"circular inheritance detected for role '<name>'"`, naming the role at which
/// the back-edge closes the cycle. Callers that run after
/// [`RbacPolicy::validate`] has already rejected cycles can ignore the result.
pub(crate) fn walk_inheritance(
    start: &str,
    policy: &RbacPolicy,
    visit: &mut impl FnMut(&RoleDefinition),
) -> Result<(), String> {
    let mut visited = std::collections::HashSet::new();
    let mut path = std::collections::HashSet::new();
    walk_inheritance_inner(start, policy, &mut visited, &mut path, visit)
}

fn walk_inheritance_inner(
    role_name: &str,
    policy: &RbacPolicy,
    visited: &mut std::collections::HashSet<String>,
    path: &mut std::collections::HashSet<String>,
    visit: &mut impl FnMut(&RoleDefinition),
) -> Result<(), String> {
    if path.contains(role_name) {
        return Err(format!(
            "circular inheritance detected for role '{role_name}'"
        ));
    }
    if !visited.insert(role_name.to_owned()) {
        return Ok(());
    }

    let Some(role) = policy.roles.iter().find(|r| r.name == role_name) else {
        return Ok(());
    };

    path.insert(role_name.to_owned());
    visit(role);
    for parent in &role.inherits {
        walk_inheritance_inner(parent, policy, visited, path, visit)?;
    }
    path.remove(role_name);
    Ok(())
}

#[cfg(test)]
mod tests;
