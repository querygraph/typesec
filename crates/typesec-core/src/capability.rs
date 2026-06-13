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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use crate::{Permission, Resource};

/// Default lease duration for minted capabilities.
///
/// A capability is a cached policy decision, not a permanent credential. The
/// default lease bounds the time between policy approval and protected use;
/// callers that need longer access should re-request the capability so policy
/// changes and revocations have a chance to take effect. Use
/// [`MintOptions`][crate::policy::MintOptions] to mint with a different TTL —
/// e.g. seconds for `CanDeclassify`, longer for low-risk reads.
pub const DEFAULT_CAPABILITY_TTL: Duration = Duration::from_secs(300);

/// A shared revocation epoch for live capability invalidation.
///
/// TTLs bound how long a stale policy decision can be used, but they cannot
/// kill an already-minted capability when policy changes mid-lease. A
/// `RevocationEpoch` closes that gap: capabilities minted with one (via
/// [`MintOptions::revocation`][crate::policy::MintOptions]) record the epoch
/// counter at mint time, and [`Capability::ensure_active`] fails with
/// [`CapabilityUseError::Revoked`] once [`revoke_all`][Self::revoke_all] has
/// bumped the counter past it.
///
/// Cloning is cheap (an `Arc` clone) and all clones share the same counter.
#[derive(Clone, Debug, Default)]
pub struct RevocationEpoch(Arc<AtomicU64>);

impl RevocationEpoch {
    /// Create a new epoch counter starting at 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke every capability minted against this epoch before this call.
    ///
    /// Capabilities minted *after* this call remain valid (until the next bump
    /// or their TTL, whichever comes first).
    pub fn revoke_all(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    /// The current epoch value.
    pub fn current(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

/// Error returned when a capability is no longer valid for use.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CapabilityUseError {
    /// The capability lease has expired.
    #[error("capability expired (issued_at={issued_at:?}, expires_at={expires_at:?})")]
    Expired {
        /// When the capability was minted.
        issued_at: SystemTime,
        /// When the capability lease ended.
        expires_at: SystemTime,
    },
    /// The capability was revoked via its [`RevocationEpoch`].
    #[error("capability revoked (minted at epoch {minted_epoch}, current epoch {current_epoch})")]
    Revoked {
        /// Epoch counter value when the capability was minted.
        minted_epoch: u64,
        /// Epoch counter value now.
        current_epoch: u64,
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
    /// Revocation binding: the shared epoch handle and its value at mint time.
    /// `None` for capabilities minted without a [`RevocationEpoch`].
    revocation: Option<(RevocationEpoch, u64)>,
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
    /// Production minting goes through [`new_minted`][Self::new_minted]; this
    /// shorthand remains for in-crate tests.
    #[cfg(test)]
    pub(crate) fn new_unchecked(
        subject: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        Self::new_with_issued_at(subject, resource_id, SystemTime::now())
    }

    /// Internal constructor preserving an existing issue time (used by tests).
    #[cfg(test)]
    pub(crate) fn new_with_issued_at(
        subject: impl Into<String>,
        resource_id: impl Into<String>,
        issued_at: SystemTime,
    ) -> Self {
        Self::new_minted(
            subject,
            resource_id,
            issued_at,
            DEFAULT_CAPABILITY_TTL,
            None,
        )
    }

    /// Internal constructor with full lease parameters (used by minting).
    pub(crate) fn new_minted(
        subject: impl Into<String>,
        resource_id: impl Into<String>,
        issued_at: SystemTime,
        ttl: Duration,
        revocation: Option<RevocationEpoch>,
    ) -> Self {
        let expires_at = issued_at.checked_add(ttl).unwrap_or(issued_at);
        Self {
            subject: subject.into(),
            resource_id: resource_id.into(),
            issued_at,
            expires_at,
            revocation: revocation.map(|epoch| {
                let minted = epoch.current();
                (epoch, minted)
            }),
            _permission: PhantomData,
            _resource: PhantomData,
        }
    }

    /// Internal: derive a capability with a different permission parameter,
    /// preserving the full lease (issue time, expiry, revocation binding).
    /// Used by `coerce`/`coerce_ref` — a derived capability must never be
    /// "fresher" or longer-lived than its source.
    pub(crate) fn derive<Q: Permission>(&self) -> Capability<Q, R> {
        Capability {
            subject: self.subject.clone(),
            resource_id: self.resource_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revocation: self.revocation.clone(),
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

    /// Whether this capability was revoked via its [`RevocationEpoch`].
    ///
    /// Always `false` for capabilities minted without a revocation binding.
    pub fn is_revoked(&self) -> bool {
        self.revocation
            .as_ref()
            .is_some_and(|(epoch, minted)| epoch.current() > *minted)
    }

    /// Validate that this capability can still be used (not expired, not revoked).
    #[must_use = "capability use must stop when this returns an error"]
    pub fn ensure_active(&self) -> Result<(), CapabilityUseError> {
        if self.is_expired() {
            return Err(CapabilityUseError::Expired {
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            });
        }
        if let Some((epoch, minted)) = &self.revocation {
            let current = epoch.current();
            if current > *minted {
                return Err(CapabilityUseError::Revoked {
                    minted_epoch: *minted,
                    current_epoch: current,
                });
            }
        }
        Ok(())
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
    fn revocation_epoch_invalidates_minted_capability() {
        let epoch = RevocationEpoch::new();
        let cap: Capability<CanRead, TestResource> = Capability::new_minted(
            "agent:test",
            "test://resource",
            SystemTime::now(),
            DEFAULT_CAPABILITY_TTL,
            Some(epoch.clone()),
        );

        cap.ensure_active().expect("active before revocation");
        epoch.revoke_all();
        assert!(cap.is_revoked());
        assert!(matches!(
            cap.ensure_active(),
            Err(CapabilityUseError::Revoked { .. })
        ));
    }

    #[test]
    fn capability_without_revocation_binding_is_never_revoked() {
        let cap: Capability<CanRead, TestResource> =
            Capability::new_unchecked("agent:test", "test://resource");
        assert!(!cap.is_revoked());
    }

    #[test]
    fn custom_ttl_bounds_the_lease() {
        let cap: Capability<CanRead, TestResource> = Capability::new_minted(
            "agent:test",
            "test://resource",
            SystemTime::now() - Duration::from_secs(2),
            Duration::from_secs(1),
            None,
        );
        assert!(cap.is_expired());
    }

    #[test]
    fn new_capability_is_active() {
        let cap: Capability<CanRead, TestResource> =
            Capability::new_unchecked("agent:test", "test://resource");

        assert!(!cap.is_expired());
        cap.ensure_active().expect("new capability is active");
    }
}
