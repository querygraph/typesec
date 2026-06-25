//! # Capability — the unforgeable proof token
//!
//! A [`Capability<P, R>`] is proof that the holder has been granted permission `P`
//! on resource `R`. It can only be constructed by a [`PolicyEngine`][crate::PolicyEngine]
//! after a successful policy check.
//!
//! ## Why is it unforgeable?
//!
//! 1. The struct fields are private — you can't write `Capability { ... }` directly.
//! 2. There is no public constructor. Capabilities are minted only by the
//!    `pub(crate)` `new_minted` path, which the [`mint_capability`][crate::mint_capability]
//!    functions call after a successful policy check. Code outside `typesec-core`
//!    cannot construct one.
//! 3. The sealing on [`Permission`] means you can't create a
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

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use crate::{Permission, Resource, ResourceId, SubjectId};

mod revocation;
pub use revocation::{CapabilityRevocationList, CapabilityUseError, RevocationEpoch};

/// Default lease duration for minted capabilities.
///
/// A capability is a cached policy decision, not a permanent credential. The
/// default lease bounds the time between policy approval and protected use;
/// callers that need longer access should re-request the capability so policy
/// changes and revocations have a chance to take effect. Use
/// [`MintOptions`][crate::policy::MintOptions] to mint with a different TTL —
/// e.g. seconds for `CanDeclassify`, longer for low-risk reads.
pub const DEFAULT_CAPABILITY_TTL: Duration = Duration::from_secs(300);

static NEXT_CAPABILITY_ID: AtomicU64 = AtomicU64::new(1);

/// Stable identity for one minted capability within this process.
///
/// A `CapabilityId` names the individual proof, not merely a subject/resource
/// pair. Revoking this id invalidates exactly the matching capability while
/// leaving other capabilities for the same subject or resource untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityId(u64);

impl CapabilityId {
    fn next() -> Self {
        Self(NEXT_CAPABILITY_ID.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cap-{}", self.0)
    }
}

/// An unforgeable proof that subject `subject` holds permission `P` on resource `R`.
///
/// Construct via the [`mint_capability`][crate::mint_capability] family, which
/// runs a [`PolicyEngine`][crate::PolicyEngine] check first.
/// The phantom parameters `P` and `R` are erased at runtime but enforced at compile time.
pub struct Capability<P: Permission, R: Resource> {
    /// Unique id for this minted proof.
    id: CapabilityId,
    /// The subject (agent identity) that was granted this capability.
    subject: SubjectId,
    /// The resource identifier (path, URI, etc.) this capability covers.
    resource_id: ResourceId,
    /// When the policy engine minted this capability.
    issued_at: SystemTime,
    /// When this cached policy decision expires.
    expires_at: SystemTime,
    /// Revocation binding: the shared epoch handle and its value at mint time.
    /// `None` for capabilities minted without a [`RevocationEpoch`].
    revocation: Option<(RevocationEpoch, u64)>,
    /// Optional per-capability revocation list.
    revocation_list: Option<Arc<CapabilityRevocationList>>,
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
        subject: impl Into<SubjectId>,
        resource_id: impl Into<ResourceId>,
    ) -> Self {
        Self::new_with_issued_at(subject, resource_id, SystemTime::now())
    }

    /// Internal constructor preserving an existing issue time (used by tests).
    #[cfg(test)]
    pub(crate) fn new_with_issued_at(
        subject: impl Into<SubjectId>,
        resource_id: impl Into<ResourceId>,
        issued_at: SystemTime,
    ) -> Self {
        Self::new_minted(
            subject,
            resource_id,
            issued_at,
            DEFAULT_CAPABILITY_TTL,
            None,
            None,
        )
    }

    /// Internal constructor with full lease parameters (used by minting).
    pub(crate) fn new_minted(
        subject: impl Into<SubjectId>,
        resource_id: impl Into<ResourceId>,
        issued_at: SystemTime,
        ttl: Duration,
        revocation: Option<RevocationEpoch>,
        revocation_list: Option<Arc<CapabilityRevocationList>>,
    ) -> Self {
        let expires_at = issued_at.checked_add(ttl).unwrap_or(issued_at);
        Self {
            id: CapabilityId::next(),
            subject: subject.into(),
            resource_id: resource_id.into(),
            issued_at,
            expires_at,
            revocation: revocation.map(|epoch| {
                let minted = epoch.current();
                (epoch, minted)
            }),
            revocation_list,
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
            id: self.id,
            subject: self.subject.clone(),
            resource_id: self.resource_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revocation: self.revocation.clone(),
            revocation_list: self.revocation_list.clone(),
            _permission: PhantomData,
            _resource: PhantomData,
        }
    }

    /// Unique id for this minted proof.
    pub fn id(&self) -> CapabilityId {
        self.id
    }

    /// The subject that holds this capability.
    pub fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// The resource identifier this capability covers.
    pub fn resource_id(&self) -> &ResourceId {
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
            || self
                .revocation_list
                .as_ref()
                .is_some_and(|list| list.is_revoked(self.id))
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
        if self
            .revocation_list
            .as_ref()
            .is_some_and(|list| list.is_revoked(self.id))
        {
            return Err(CapabilityUseError::RevokedById { id: self.id });
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
            .field("id", &self.id)
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
mod tests;
