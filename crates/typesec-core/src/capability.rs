//! # Capability — the unforgeable proof token
//!
//! A [`Capability<P, R>`] is proof that the holder has been granted permission `P`
//! on resource `R`. It can only be constructed by a [`PolicyEngine`][crate::PolicyEngine]
//! after a successful policy check.
//!
//! ## Why is it unforgeable?
//!
//! 1. The struct fields are private — you can't write `Capability { ... }` directly.
//! 2. The only public constructor is [`Capability::new_unchecked`], which is marked
//!    `pub(crate)`. Code outside `typesec-core` cannot call it.
//! 3. The sealing on [`Permission`][crate::Permission] means you can't create a
//!    new permission type that bypasses the engine.
//!
//! Together, these invariants mean: *if you have a `Capability<P, R>` in scope,
//! the policy engine must have approved it.*
//!
//! ## Phantom types carry the proof
//!
//! `Capability<CanRead, Report>` and `Capability<CanWrite, Report>` are *different
//! types* even though they share the same struct layout (which is, at runtime, just
//! a subject string and a resource identifier). The type parameters `P` and `R` are
//! [`PhantomData`] — zero-cost at runtime, but forcing the compiler to distinguish
//! read-caps from write-caps at every call site.
//!
//! ```rust,ignore
//! fn write_report(cap: Capability<CanWrite, Report>, report: Report) { ... }
//!
//! let read_cap: Capability<CanRead, Report> = engine.check(...).unwrap();
//! write_report(read_cap, report); // ← compile error: wrong capability type
//! ```

use std::marker::PhantomData;

use crate::{Permission, Resource};

/// An unforgeable proof that subject `subject` holds permission `P` on resource `R`.
///
/// Construct via [`PolicyEngine::mint_capability`][crate::PolicyEngine].
/// The phantom parameters `P` and `R` are erased at runtime but enforced at compile time.
pub struct Capability<P: Permission, R: Resource> {
    /// The subject (agent identity) that was granted this capability.
    subject: String,
    /// The resource identifier (path, URI, etc.) this capability covers.
    resource_id: String,
    /// Zero-cost phantom binding to the permission type.
    _permission: PhantomData<fn() -> P>,
    /// Zero-cost phantom binding to the resource type.
    _resource: PhantomData<fn() -> R>,
}

impl<P: Permission, R: Resource> Capability<P, R> {
    /// Internal constructor — only callable from within `typesec-core`.
    ///
    /// External crates cannot mint capabilities; they must go through a
    /// [`PolicyEngine`][crate::PolicyEngine], which performs the policy check.
    pub(crate) fn new_unchecked(
        subject: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            resource_id: resource_id.into(),
            _permission: PhantomData,
            _resource: PhantomData,
        }
    }

    /// The subject that holds this capability.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The resource identifier this capability covers.
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// The permission name (from the type parameter).
    pub fn permission_name() -> &'static str {
        P::name()
    }
}

impl<P: Permission, R: Resource> std::fmt::Debug for Capability<P, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capability")
            .field("permission", &P::name())
            .field("subject", &self.subject)
            .field("resource_id", &self.resource_id)
            .finish()
    }
}

impl<P: Permission, R: Resource> std::fmt::Display for Capability<P, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Capability({} {} on {})",
            self.subject,
            P::name(),
            self.resource_id
        )
    }
}

// Capabilities are intentionally NOT Clone — having one is a privilege,
// not something that should propagate by accident. If you need to share
// a capability, pass a reference.
//
// Send + Sync are auto-derived: `String` is Send+Sync, `PhantomData<fn() -> P>`
// is Send+Sync (function pointers are always Send+Sync). No unsafe needed.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{CanRead, CanWrite};

    // A minimal test resource.
    #[derive(Debug)]
    struct TestResource;
    impl Resource for TestResource {
        fn resource_id(&self) -> &str {
            "test://resource"
        }
        fn resource_type() -> &'static str {
            "TestResource"
        }
    }

    #[test]
    fn capability_fields_are_correct() {
        let cap: Capability<CanRead, TestResource> =
            Capability::new_unchecked("agent:test", "test://resource");
        assert_eq!(cap.subject(), "agent:test");
        assert_eq!(cap.resource_id(), "test://resource");
        assert_eq!(
            Capability::<CanRead, TestResource>::permission_name(),
            "read"
        );
    }

    #[test]
    fn read_and_write_caps_are_different_types() {
        // This test is really a compile-time check, but we can demonstrate
        // the Debug output differs.
        let read: Capability<CanRead, TestResource> =
            Capability::new_unchecked("agent:test", "test://resource");
        let write: Capability<CanWrite, TestResource> =
            Capability::new_unchecked("agent:test", "test://resource");
        assert!(format!("{read:?}").contains("read"));
        assert!(format!("{write:?}").contains("write"));
    }
}
