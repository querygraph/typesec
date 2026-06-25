//! # Capability Lattice
//!
//! Permission implication relationships encoded in Rust's type system.
//!
//! Higher permissions "imply" lower ones: holding `CanWrite` automatically
//! satisfies a `CanRead` requirement. This is expressed as a blanket of
//! `impl Implies<CanRead> for CanWrite {}` statements.
//!
//! ## Lattice Structure
//!
//! ```text
//! CanWriteSensitive ──► CanWrite ─────────────► CanRead
//!         │                                      ▲
//!         └──► CanReadSensitive ──► CanReadInternal
//!                         │              │
//!                         └──────────────┘
//!
//! CanDelete ──────────────────────────► CanRead
//! CanDelegate ────────────────────────► CanRead
//!
//! AiCanTrain ──────► AiCanInfer ──────► (implied via AiCanTrain → CanRead)
//!         └──────────────────────────── CanRead
//!
//! AiCanExfiltrate ──► AiCanInfer
//!         └──────────────────────────── CanRead
//! ```
//!
//! ## Runtime lattice promotion
//!
//! [`LatticeEngine`] wraps any [`PolicyEngine`] and promotes a denied request
//! if the agent holds a strictly higher permission that implies the requested one.
//! This allows RBAC policies to grant `write` and have `read` satisfied
//! automatically without requiring an explicit `read` grant.

use std::sync::Arc;

use tracing::{debug, info};

use crate::{
    Permission, Resource, ResourceId, SubjectId,
    capability::Capability,
    permissions::{
        AiCanExfiltrate, AiCanInfer, AiCanTrain, CanDeclassify, CanDelegate, CanDelete, CanRead,
        CanReadInternal, CanReadSensitive, CanWrite, CanWriteSensitive,
    },
    policy::{PolicyEngine, PolicyResult, RequestContext},
};

// ── Implies<Q> trait ──────────────────────────────────────────────────────────

/// Trait encoding the permission lattice.
///
/// `impl Implies<CanRead> for CanWrite {}` means: any agent holding `CanWrite`
/// automatically satisfies a requirement for `CanRead`.
///
/// This is a compile-time relationship — no runtime state is involved.
/// Use [`Capability::coerce`] to convert a higher-privilege capability into a
/// lower-privilege one under this guarantee.
pub trait Implies<Q: Permission>: Permission {}

// ── Implication relationships ─────────────────────────────────────────────────

/// Single source of truth for the lattice.
///
/// Each `Higher => Lower` entry generates *both* the compile-time
/// `impl Implies<Lower> for Higher` and a runtime table entry used by
/// [`LatticeEngine`]. Keeping them in one macro invocation means the typed
/// lattice and the string-based promotion logic cannot drift apart.
///
/// Entries must list the transitive closure explicitly (e.g. `CanWriteSensitive`
/// lists `CanRead` directly, not just `CanWrite`).
macro_rules! lattice {
    ($($higher:ty => $lower:ty),* $(,)?) => {
        $(impl Implies<$lower> for $higher {})*

        /// `(higher_name, lower_name)` pairs mirroring every `Implies` impl.
        ///
        /// Function pointers are used because `Permission::name()` is not `const`.
        static IMPLICATIONS: &[(fn() -> &'static str, fn() -> &'static str)] = &[
            $((<$higher as Permission>::name, <$lower as Permission>::name)),*
        ];
    };
}

lattice! {
    // CanWrite → CanRead
    CanWrite => CanRead,
    // CanDelete → CanRead
    CanDelete => CanRead,
    // CanDelegate → CanRead
    CanDelegate => CanRead,
    // CanReadInternal → CanRead
    CanReadInternal => CanRead,
    // CanReadSensitive → CanReadInternal, CanRead
    CanReadSensitive => CanReadInternal,
    CanReadSensitive => CanRead,
    // CanWriteSensitive → CanWrite, CanReadSensitive, CanReadInternal, CanRead
    CanWriteSensitive => CanWrite,
    CanWriteSensitive => CanReadSensitive,
    CanWriteSensitive => CanReadInternal,
    CanWriteSensitive => CanRead,
    // CanDeclassify → CanReadSensitive, CanReadInternal, CanRead
    CanDeclassify => CanReadSensitive,
    CanDeclassify => CanReadInternal,
    CanDeclassify => CanRead,
    // AiCanTrain → AiCanInfer, CanRead
    AiCanTrain => AiCanInfer,
    AiCanTrain => CanRead,
    // AiCanExfiltrate → AiCanInfer, CanRead
    AiCanExfiltrate => AiCanInfer,
    AiCanExfiltrate => CanRead,
}

// ── coerce() on Capability ────────────────────────────────────────────────────

impl<P: Permission, R: Resource> Capability<P, R> {
    /// Downcast this capability to a less-privileged one.
    ///
    /// Only callable when `P: Implies<Q>` — the compiler enforces the lattice.
    /// This is a zero-cost operation: subject and resource are preserved;
    /// only the permission type parameter changes.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let write_cap: Capability<CanWrite, Report> =
    ///     agent.request_capability(&report).await?;
    /// // CanWrite → CanRead is a valid lattice relationship:
    /// let read_cap: Capability<CanRead, Report> = write_cap.coerce();
    /// ```
    pub fn coerce<Q: Permission>(self) -> Capability<Q, R>
    where
        P: Implies<Q>,
    {
        self.coerce_ref()
    }

    /// Like [`coerce`][Self::coerce], but borrows — the original (higher)
    /// capability is retained.
    ///
    /// This is safe for the same reason `coerce` is: `P: Implies<Q>` means the
    /// holder of `P` already has every right `Q` grants, so deriving a `Q`
    /// token grants nothing new.
    pub fn coerce_ref<Q: Permission>(&self) -> Capability<Q, R>
    where
        P: Implies<Q>,
    {
        // The safety guarantee is maintained by the type bound: `P: Implies<Q>`
        // ensures Q is strictly ≤ P in the lattice. The full lease (issue time,
        // expiry, revocation binding) is preserved so a derived capability is
        // never fresher or longer-lived than its source.
        self.derive()
    }
}

// ── LatticeEngine ──────────────────────────────────────────────────────────────

/// Runtime lattice engine wrapper.
///
/// Wraps any [`PolicyEngine`] and promotes denied requests when the subject
/// holds a higher permission that implies the requested one.
///
/// For example, if the inner engine grants `write` but not `read`, a request
/// for `read` is promoted to `Allow` because `CanWrite` implies `CanRead`.
/// Wrapping a remote or otherwise slow engine can amplify call volume: a direct
/// denial is followed by checks for each higher permission returned by
/// [`implied_by`]. The engine short-circuits on the first successful promotion.
///
/// # Audit trail
///
/// The inner engine emits its own audit events. When a promotion occurs,
/// an additional `info!` event is emitted with `lattice_promotion=true`.
pub struct LatticeEngine {
    inner: Arc<dyn PolicyEngine>,
}

impl LatticeEngine {
    /// Wrap an existing engine with lattice promotion.
    pub fn new(inner: Arc<dyn PolicyEngine>) -> Self {
        Self { inner }
    }
}

impl PolicyEngine for LatticeEngine {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        self.check_with_context(subject, action, resource, &RequestContext::default())
    }

    fn check_with_context(
        &self,
        subject: &SubjectId,
        action: &str,
        resource: &ResourceId,
        ctx: &RequestContext,
    ) -> PolicyResult {
        debug!(subject = %subject, action, resource = %resource, "lattice engine check");

        // First try the direct request.
        match self
            .inner
            .check_with_context(subject, action, resource, ctx)
        {
            PolicyResult::Allow => PolicyResult::Allow,
            original => {
                // Try every permission that implies `action` in the lattice.
                for higher in implied_by(action) {
                    debug!(
                        subject = %subject,
                        action, higher, resource = %resource, "testing lattice promotion"
                    );
                    if self
                        .inner
                        .check_with_context(subject, higher, resource, ctx)
                        == PolicyResult::Allow
                    {
                        info!(
                            subject = %subject,
                            action,
                            via = higher,
                            resource = %resource,
                            lattice_promotion = true,
                            "access granted via lattice promotion"
                        );
                        return PolicyResult::Allow;
                    }
                }
                original
            }
        }
    }
}

/// Returns the permission names that imply `permission` in the lattice.
///
/// These are the "upward covers" — permissions strictly higher in the partial
/// order that directly or transitively imply the given one. Derived from the
/// same `lattice!` table as the typed `Implies` impls, so the two cannot drift.
pub fn implied_by(permission: &str) -> impl Iterator<Item = &'static str> + '_ {
    IMPLICATIONS
        .iter()
        .filter(move |(_, lower)| lower() == permission)
        .map(|(higher, _)| higher())
}

/// Return all explicit `(higher, lower)` implication pairs.
pub fn implication_pairs() -> impl Iterator<Item = (&'static str, &'static str)> {
    IMPLICATIONS
        .iter()
        .map(|(higher, lower)| (higher(), lower()))
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
