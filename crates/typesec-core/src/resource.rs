//! Resource trait — the thing a capability grants access to.

use crate::string_id::string_newtype;

string_newtype! {
    /// Stable identifier for one protected resource instance.
    ResourceId
}

/// A resource that can be protected by a [`Capability`][crate::Capability].
///
/// Resources are typed: `Report`, `CodeFile`, `InfraConfig`, etc. The type
/// parameter on `Capability<P, R>` binds the capability to a *specific resource
/// type*, preventing a write-cap on `Report` from being used on `CodeFile`.
///
/// Implementors provide:
/// - `resource_id()` — a runtime identifier (URI, path, UUID) for audit logs.
/// - `resource_type()` — a static type name for error messages.
pub trait Resource: Send + Sync + 'static {
    /// Runtime identifier for this resource instance (e.g. `"reports/q1-2025"`).
    fn resource_id(&self) -> &str;

    /// Static type name (e.g. `"Report"`). Used in error messages and codegen.
    fn resource_type() -> &'static str
    where
        Self: Sized;
}

/// A generic, string-keyed resource for use in tests and the CLI simulator.
///
/// Production code should define domain-specific resource types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericResource {
    id: ResourceId,
    kind: String,
}

impl GenericResource {
    /// Create a new generic resource with a given id and kind.
    pub fn new(id: impl Into<String>, kind: impl Into<String>) -> Self {
        let id: String = id.into();
        Self {
            id: ResourceId::from(id),
            kind: kind.into(),
        }
    }
}

impl Resource for GenericResource {
    fn resource_id(&self) -> &str {
        self.id.as_str()
    }

    fn resource_type() -> &'static str {
        "GenericResource"
    }
}

impl std::fmt::Display for GenericResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.kind, self.id)
    }
}
