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
use std::time::{Duration, SystemTime};

use crate::{Permission, Resource};

/// Default lease duration for minted capabilities.
///
/// A capability is a cached policy decision, not a permanent credential. The
/// default lease bounds the time between policy approval and protected use;
/// callers that need longer access should re-request the capability so policy
/// changes and revocations have a chance to take effect.
pub const DEFAULT_CAPABILITY_TTL: Duration = Duration::from_secs(300);

/// Error returned when a capability is no longer valid for use.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityUseError {
    /// The capability lease has expired.
    #[error("capability expired (issued_at={issued_at:?}, expires_at={expires_at:?})")]
    Expired {
        /// When the capability was minted.
        issued_at: SystemTime,
        /// When the capability lease ended.
        expires_at: SystemTime,
    },
}

/// An unforgeable proof that subject `subject` holds permission `P` on resource `R`.
///
/// Construct via [`PolicyEngine::mint_capability`][crate::PolicyEngine].
/// The phantom parameters `P` and `R` are erased at runtime but enforced at compile time.
pub struct Capability<P: Permission, R: Resource> {
    /// The subject (agent identity) that was granted this capability.
    subject: String,
    /// The resource identifier (path, URI, etc.) this capability covers.
    resource_id: String,
    /// When the policy engine minted this capability.
    issued_at: SystemTime,
    /// When this cached policy decision expires.
    expires_at: SystemTime,
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
        Self::new_with_issued_at(subject, resource_id, SystemTime::now())
    }

    /// Internal constructor preserving an existing issue time (used by `coerce`).
    pub(crate) fn new_with_issued_at(
        subject: impl Into<String>,
        resource_id: impl Into<String>,
        issued_at: SystemTime,
    ) -> Self {
        let expires_at = issued_at
            .checked_add(DEFAULT_CAPABILITY_TTL)
            .unwrap_or(issued_at);
        Self {
            subject: subject.into(),
            resource_id: resource_id.into(),
            issued_at,
            expires_at,
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

    /// When the policy engine minted this capability.
    ///
    /// A capability is a point-in-time decision: policy changes after this
    /// instant are *not* reflected in the token. Long-lived holders should
    /// re-request rather than cache, or gate use on [`is_fresh`][Self::is_fresh].
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// When this capability expires.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Whether this capability was minted within the last `max_age`.
    ///
    /// Use this to bound the window between the policy check and the action
    /// (TOCTOU): `cap.is_fresh(Duration::from_secs(60))`.
    pub fn is_fresh(&self, max_age: Duration) -> bool {
        self.issued_at
            .elapsed()
            .map(|age| age <= max_age)
            .unwrap_or(false)
    }

    /// Whether this capability's lease has expired.
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    /// Validate that this capability can still be used.
    pub fn ensure_active(&self) -> Result<(), CapabilityUseError> {
        if self.is_expired() {
            Err(CapabilityUseError::Expired {
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            })
        } else {
            Ok(())
        }
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
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
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
    use std::time::Duration;

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

    #[test]
    fn capability_expires_after_default_ttl() {
        let issued_at = SystemTime::now()
            .checked_sub(DEFAULT_CAPABILITY_TTL + Duration::from_secs(1))
            .expect("time subtraction");
        let cap: Capability<CanRead, TestResource> =
            Capability::new_with_issued_at("agent:test", "test://resource", issued_at);

        assert!(cap.is_expired());
        assert!(matches!(
            cap.ensure_active(),
            Err(CapabilityUseError::Expired { .. })
        ));
    }

    #[test]
    fn new_capability_is_active() {
        let cap: Capability<CanRead, TestResource> =
            Capability::new_unchecked("agent:test", "test://resource");

        assert!(!cap.is_expired());
        cap.ensure_active().expect("new capability is active");
    }
}
