//! Role abstraction — a named collection of permissions.

/// A role is a named collection of permissions.
///
/// Roles are assigned to agents. An agent with role `Engineer` has the
/// permissions that role grants on the resources it covers.
///
/// This trait is implemented by both handwritten role structs and by types
/// generated via `#[derive(TypesecRole)]` in `typesec-macro`.
pub trait Role: Send + Sync + 'static {
    /// The canonical role name (e.g., `"admin"`, `"analyst"`).
    fn name() -> &'static str;

    /// The permission names this role grants (e.g., `["read", "write"]`).
    ///
    /// These strings must match the values returned by [`Permission::name()`][crate::Permission::name].
    fn permission_names() -> &'static [&'static str];

    /// The resource glob patterns this role applies to (e.g., `["reports/*"]`).
    fn resource_patterns() -> &'static [&'static str];
}
