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

        // Detect cycles via DFS.
        let mut visiting = std::collections::HashSet::new();
        for role in &self.roles {
            self.check_cycle(&role.name, &mut visiting, &std::collections::HashSet::new())?;
        }

        Ok(())
    }

    fn check_cycle(
        &self,
        role_name: &str,
        visited: &mut std::collections::HashSet<String>,
        ancestors: &std::collections::HashSet<String>,
    ) -> Result<(), String> {
        if ancestors.contains(role_name) {
            return Err(format!(
                "circular inheritance detected for role '{role_name}'"
            ));
        }
        if visited.contains(role_name) {
            return Ok(());
        }

        let mut ancestors = ancestors.clone();
        ancestors.insert(role_name.to_owned());

        if let Some(role) = self.roles.iter().find(|r| r.name == role_name) {
            for parent in &role.inherits {
                self.check_cycle(parent, visited, &ancestors)?;
            }
        }

        visited.insert(role_name.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_YAML: &str = r#"
roles:
  - name: analyst
    permissions: [read, read_sensitive]
    resources: ["reports/*"]
  - name: admin
    inherits: [analyst]
    permissions: [write, delete]
    resources: ["*"]

assignments:
  - subject: "agent:pipeline"
    roles: [analyst]
"#;

    #[test]
    fn parses_valid_yaml() {
        let policy = RbacPolicy::from_yaml(VALID_YAML).expect("parse should succeed");
        assert_eq!(policy.roles.len(), 2);
        assert_eq!(policy.assignments.len(), 1);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn detects_unknown_parent() {
        let yaml = r#"
roles:
  - name: engineer
    inherits: [nonexistent]
assignments: []
"#;
        let policy = RbacPolicy::from_yaml(yaml).expect("parse ok");
        assert!(policy.validate().is_err());
    }

    #[test]
    fn detects_cycle() {
        let yaml = r#"
roles:
  - name: a
    inherits: [b]
  - name: b
    inherits: [a]
assignments: []
"#;
        let policy = RbacPolicy::from_yaml(yaml).expect("parse ok");
        assert!(policy.validate().is_err());
    }
}
