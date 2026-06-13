//! Resource trait — the thing a capability grants access to.

use std::fmt;
use std::ops::Deref;

/// Stable identifier for one protected resource instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceId(String);

impl ResourceId {
    /// Borrow this identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ResourceId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for ResourceId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl AsRef<str> for ResourceId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq<str> for ResourceId {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ResourceId {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl Deref for ResourceId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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
