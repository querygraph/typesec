//! # Permission marker traits
//!
//! Each permission is a *zero-sized type* (ZST) that implements the [`Permission`]
//! marker trait. ZSTs have no runtime cost — they exist purely at the type level.
//!
//! ## Why marker traits?
//!
//! Marker traits are Rust's mechanism for attaching semantic meaning to a type
//! without carrying data. `CanRead` is literally just:
//!
//! ```text
//! pub struct CanRead;
//! impl Permission for CanRead {}
//! ```
//!
//! The *type parameter* on [`Capability<P, R>`][crate::Capability] carries this
//! information at zero cost. The compiler erases it completely after monomorphisation.
//!
//! ## Composability
//!
//! Because permissions are types, combining them is just adding more type parameters
//! or trait bounds. A function requiring both read and write can say:
//!
//! ```rust,ignore
//! fn transform<R>(
//!     read_cap: &Capability<CanRead, R>,
//!     write_cap: &Capability<CanWrite, R>,
//! ) { ... }
//! ```
//!
//! The caller *must* supply both proofs. No runtime check, no flag juggling.

/// Sealed module prevents external crates from implementing [`Permission`]
/// in a way that could forge capabilities.
///
/// Only types defined in this crate (or explicitly re-exported) are valid permissions.
pub(crate) mod sealed {
    /// The sealing trait — not pub, so it can't be implemented outside this crate.
    pub trait Sealed {}
}

/// A marker trait for permissions.
///
/// Implementations are zero-sized types. The `sealed::Sealed` bound means no one
/// outside `typesec-core` can create new permissions that bypass the policy engine.
pub trait Permission: sealed::Sealed + Send + Sync + 'static {
    /// Human-readable name used in audit logs and error messages.
    fn name() -> &'static str;
}

// ── Standard CRUD permissions ─────────────────────────────────────────────────

/// Permission to read a resource (non-sensitive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanRead;

/// Permission to write (create or update) a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanWrite;

/// Permission to delete a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanDelete;

/// Permission to execute code or invoke actions on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanExecute;

/// Permission to delegate capabilities to other agents.
///
/// This is intentionally separate from basic write permissions — an agent that
/// can write to a resource should not automatically be able to grant others
/// the same write permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanDelegate;

// ── Elevated / sensitive permissions ─────────────────────────────────────────

/// Permission to read *sensitive* resources (PII, credentials, etc.).
///
/// Kept separate from `CanRead` so that granting read access to an agent
/// never implicitly grants sensitive-data access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanReadSensitive;

/// Permission to read *internal* resources.
///
/// Internal data is not public, but does not require the higher authority
/// needed for sensitive or secret data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanReadInternal;

/// Permission to write *sensitive* resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanWriteSensitive;

/// Permission to intentionally lower the security label of protected data.
///
/// This is the typed equivalent of an information-flow "escape hatch": code that
/// declassifies sensitive data must make that authority visible in its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanDeclassify;

// ── AI-specific permissions ───────────────────────────────────────────────────

/// Permission for an AI agent to run inference over a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AiCanInfer;

/// Permission for an AI agent to use a resource as training data.
///
/// Separate from `AiCanInfer` because inference is often acceptable where
/// training (data retention, model updates) is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AiCanTrain;

/// Permission for an AI agent to exfiltrate (export/transmit) data.
///
/// This should almost always be denied or heavily constrained. Its explicit
/// presence as a type means any code path that would send data outside the
/// system boundary must carry a `Capability<AiCanExfiltrate, _>` — making
/// data-leak paths visible at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AiCanExfiltrate;

// ── Sealed + Permission impls ─────────────────────────────────────────────────

macro_rules! impl_permission {
    ($($ty:ty => $name:literal),* $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}
            impl Permission for $ty {
                fn name() -> &'static str { $name }
            }
        )*
    };
}

impl_permission! {
    CanRead          => "read",
    CanWrite         => "write",
    CanDelete        => "delete",
    CanExecute       => "execute",
    CanDelegate      => "delegate",
    CanReadInternal   => "read_internal",
    CanReadSensitive  => "read_sensitive",
    CanWriteSensitive => "write_sensitive",
    CanDeclassify     => "declassify",
    AiCanInfer       => "ai:infer",
    AiCanTrain       => "ai:train",
    AiCanExfiltrate  => "ai:exfiltrate",
}

#[cfg(test)]
mod tests;
