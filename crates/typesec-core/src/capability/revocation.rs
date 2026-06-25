//! Live revocation primitives for capabilities.
//!
//! TTLs (see [`DEFAULT_CAPABILITY_TTL`][super::DEFAULT_CAPABILITY_TTL]) bound how
//! long a stale policy decision can be used, but they cannot kill an
//! already-minted capability when policy changes mid-lease. These two mechanisms
//! close that gap and are consulted by [`Capability::ensure_active`][super::Capability::ensure_active]:
//!
//! - [`RevocationEpoch`] — a shared counter; bumping it revokes every capability
//!   minted against it before the bump.
//! - [`CapabilityRevocationList`] — a set of individual [`CapabilityId`]s, for
//!   revoking one minted proof without affecting other holders.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock};
use std::time::SystemTime;

use super::CapabilityId;

/// A shared revocation epoch for live capability invalidation.
///
/// TTLs bound how long a stale policy decision can be used, but they cannot
/// kill an already-minted capability when policy changes mid-lease. A
/// `RevocationEpoch` closes that gap: capabilities minted with one (via
/// [`MintOptions::revocation`][crate::policy::MintOptions]) record the epoch
/// counter at mint time, and [`Capability::ensure_active`][super::Capability::ensure_active]
/// fails with [`CapabilityUseError::Revoked`] once [`revoke_all`][Self::revoke_all]
/// has bumped the counter past it.
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

/// Per-capability revocation list.
///
/// Pair this with [`MintOptions::with_revocation_list`][crate::policy::MintOptions::with_revocation_list]
/// when incident response needs to revoke one minted proof without bumping a
/// shared [`RevocationEpoch`] for every holder.
#[derive(Debug, Default)]
pub struct CapabilityRevocationList {
    revoked: RwLock<HashSet<CapabilityId>>,
}

impl CapabilityRevocationList {
    /// Create an empty capability revocation list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke one minted capability id.
    pub fn revoke(&self, id: CapabilityId) {
        let mut revoked = self.revoked.write().unwrap_or_else(PoisonError::into_inner);
        revoked.insert(id);
    }

    /// Whether this list contains the capability id.
    pub fn is_revoked(&self, id: CapabilityId) -> bool {
        let revoked = self.revoked.read().unwrap_or_else(PoisonError::into_inner);
        revoked.contains(&id)
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
    /// The capability id was revoked via a [`CapabilityRevocationList`].
    #[error("capability revoked by id ({id})")]
    RevokedById {
        /// The revoked capability id.
        id: CapabilityId,
    },
}
