//! Flattening role inheritance into concrete grants.

use crate::model::{RbacPolicy, walk_inheritance};

/// A single `(permission, resource_patterns)` grant, with patterns still in
/// their raw string form (compiled later by the engine).
#[derive(Debug, Clone)]
pub(super) struct Grant {
    pub(super) permission: String,
    pub(super) resource_patterns: Vec<String>,
}

/// Flatten a role's permissions by resolving inheritance.
///
/// Walks the role's inheritance closure (own role first, then inherited roles
/// in declaration order) and emits one [`Grant`] per `(permission, resources)`
/// pair. The cycle guard inside [`walk_inheritance`] makes this safe even though
/// cycles are already rejected by [`RbacPolicy::validate`].
pub(super) fn flatten_role(role_name: &str, policy: &RbacPolicy) -> Vec<Grant> {
    let mut grants: Vec<Grant> = Vec::new();
    let _ = walk_inheritance(role_name, policy, &mut |role| {
        for perm in &role.permissions {
            grants.push(Grant {
                permission: perm.clone(),
                resource_patterns: role.resources.clone(),
            });
        }
    });
    grants
}
