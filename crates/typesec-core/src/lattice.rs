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
//! CanWriteSensitive ──► CanWrite ──► CanRead
//!         │                          ▲
//!         └──► CanReadSensitive ─────┘
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
    Permission, Resource,
    capability::Capability,
    permissions::{
        AiCanExfiltrate, AiCanInfer, AiCanTrain, CanDeclassify, CanDelegate, CanDelete, CanRead,
        CanReadSensitive, CanWrite, CanWriteSensitive,
    },
    policy::{PolicyEngine, PolicyResult},
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
    // CanReadSensitive → CanRead
    CanReadSensitive => CanRead,
    // CanWriteSensitive → CanWrite, CanReadSensitive, CanRead
    CanWriteSensitive => CanWrite,
    CanWriteSensitive => CanReadSensitive,
    CanWriteSensitive => CanRead,
    // CanDeclassify → CanReadSensitive, CanRead
    CanDeclassify => CanReadSensitive,
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
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        debug!(subject, action, resource, "lattice engine check");

        // First try the direct request.
        match self.inner.check(subject, action, resource) {
            PolicyResult::Allow => PolicyResult::Allow,
            original => {
                // Try every permission that implies `action` in the lattice.
                for higher in implied_by(action) {
                    debug!(
                        subject,
                        action, higher, resource, "testing lattice promotion"
                    );
                    if self.inner.check(subject, higher, resource) == PolicyResult::Allow {
                        info!(
                            subject,
                            action,
                            via = higher,
                            resource,
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
fn implied_by(permission: &str) -> impl Iterator<Item = &'static str> + '_ {
    IMPLICATIONS
        .iter()
        .filter(move |(_, lower)| lower() == permission)
        .map(|(higher, _)| higher())
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        permissions::{CanRead, CanWrite, CanWriteSensitive},
        policy::PolicyResult,
        resource::GenericResource,
    };
    use std::sync::Arc;

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// An engine that grants a fixed (subject, action, resource) triple.
    struct GrantOnly {
        subject: &'static str,
        action: &'static str,
        resource: &'static str,
    }
    impl PolicyEngine for GrantOnly {
        fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
            if subject == self.subject && action == self.action && resource == self.resource {
                PolicyResult::Allow
            } else {
                PolicyResult::Deny(format!(
                    "GrantOnly: no match for {subject}/{action}/{resource}"
                ))
            }
        }
    }

    // ── coerce() tests ─────────────────────────────────────────────────────────

    #[test]
    fn coerce_write_to_read() {
        let write_cap: Capability<CanWrite, GenericResource> =
            Capability::new_unchecked("agent:test", "data/file");
        let read_cap: Capability<CanRead, GenericResource> = write_cap.coerce();
        assert_eq!(read_cap.subject(), "agent:test");
        assert_eq!(read_cap.resource_id(), "data/file");
        assert_eq!(
            Capability::<CanRead, GenericResource>::permission_name(),
            "read"
        );
    }

    #[test]
    fn coerce_write_sensitive_to_write() {
        let ws_cap: Capability<CanWriteSensitive, GenericResource> =
            Capability::new_unchecked("agent:admin", "sensitive/data");
        let w_cap: Capability<CanWrite, GenericResource> = ws_cap.coerce();
        assert_eq!(
            Capability::<CanWrite, GenericResource>::permission_name(),
            "write"
        );
        assert_eq!(w_cap.subject(), "agent:admin");
    }

    #[test]
    fn coerce_write_sensitive_to_read() {
        // CanWriteSensitive → CanRead is a direct impl
        let ws_cap: Capability<CanWriteSensitive, GenericResource> =
            Capability::new_unchecked("agent:admin", "sensitive/data");
        let r_cap: Capability<CanRead, GenericResource> = ws_cap.coerce();
        assert_eq!(
            Capability::<CanRead, GenericResource>::permission_name(),
            "read"
        );
        assert_eq!(r_cap.subject(), "agent:admin");
    }

    // ── LatticeEngine tests ────────────────────────────────────────────────────

    #[test]
    fn lattice_promotes_write_to_read() {
        // Engine grants "write" but not "read" directly.
        let inner: Arc<dyn PolicyEngine> = Arc::new(GrantOnly {
            subject: "agent:test",
            action: "write",
            resource: "reports/q1",
        });
        let engine = LatticeEngine::new(inner);

        // Direct read → denied by inner
        // Lattice: implied_by("read") includes "write" → inner.check("write") → Allow → promote
        let result = engine.check("agent:test", "read", "reports/q1");
        assert_eq!(
            result,
            PolicyResult::Allow,
            "lattice should promote write→read"
        );
    }

    #[test]
    fn lattice_does_not_promote_upward() {
        // Engine only grants "read" — does NOT have write.
        let inner: Arc<dyn PolicyEngine> = Arc::new(GrantOnly {
            subject: "agent:test",
            action: "read",
            resource: "reports/q1",
        });
        let engine = LatticeEngine::new(inner);

        // Request "write" — no permission in the lattice implies write from read.
        let result = engine.check("agent:test", "write", "reports/q1");
        assert!(
            matches!(result, PolicyResult::Deny(_)),
            "should not be able to promote read→write"
        );
    }

    #[test]
    fn lattice_passes_through_allow() {
        let inner: Arc<dyn PolicyEngine> = Arc::new(GrantOnly {
            subject: "agent:test",
            action: "read",
            resource: "data",
        });
        let engine = LatticeEngine::new(inner);
        let result = engine.check("agent:test", "read", "data");
        assert_eq!(result, PolicyResult::Allow);
    }
}
