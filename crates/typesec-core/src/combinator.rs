//! # Policy Combinator
//!
//! Multi-engine composition with configurable resolution strategies.
//!
//! Instead of a fixed two-engine chain, [`ComposedEngine`] holds any number of
//! [`PolicyEngine`]s and merges their verdicts with a [`CombineStrategy`].
//!
//! ## Strategies
//!
//! | Strategy | When to allow |
//! |---|---|
//! | `AllowIfAll` | Every non-delegating engine must say Allow |
//! | `AllowIfAny` | At least one engine says Allow |
//! | `DenyOverrides` | Any Deny beats any Allow (XACML default) |
//! | `PriorityOrder` | First non-Delegate answer wins (left to right) |
//!
//! ## Builder Example
//!
//! ```rust,ignore
//! let engine = PolicyEngineBuilder::new()
//!     .add_engine(rbac_engine)
//!     .add_engine(odrl_engine)
//!     .strategy(CombineStrategy::DenyOverrides)
//!     .build();
//! ```

use std::sync::Arc;

use tracing::debug;

use crate::policy::{PolicyEngine, PolicyResult};

// ── CombineStrategy ──────────────────────────────────────────────────────────

/// How to combine multiple policy engine verdicts into a single decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CombineStrategy {
    /// Allow only when **all** non-delegating engines say Allow.
    ///
    /// If every engine delegates, the combined result is also Delegate.
    /// Any single Deny overrides any number of Allows.
    AllowIfAll,

    /// Allow when **any** engine says Allow.
    ///
    /// If all engines deny, the last Deny is returned.
    /// If all delegate, the result is Delegate.
    AllowIfAny,

    /// A Deny from **any** engine overrides all Allows (XACML-style).
    ///
    /// If at least one engine Allows and none deny, the result is Allow.
    /// If all delegate, the result is Delegate.
    DenyOverrides,

    /// The **first** non-Delegate answer wins (left-to-right priority).
    ///
    /// Engines are tried in the order they were added. The first one that
    /// returns Allow or Deny is used; the rest are skipped.
    #[default]
    PriorityOrder,
}

// ── ComposedEngine ───────────────────────────────────────────────────────────

/// A multi-engine policy combinator with configurable strategy.
///
/// Created via [`PolicyEngineBuilder`].
pub struct ComposedEngine {
    engines: Vec<Arc<dyn PolicyEngine>>,
    strategy: CombineStrategy,
}

impl ComposedEngine {
    /// Create a combinator directly (prefer [`PolicyEngineBuilder`]).
    pub fn new(engines: Vec<Arc<dyn PolicyEngine>>, strategy: CombineStrategy) -> Self {
        Self { engines, strategy }
    }
}

impl PolicyEngine for ComposedEngine {
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        debug!(
            subject,
            action,
            resource,
            strategy = ?self.strategy,
            n_engines = self.engines.len(),
            "composed engine check"
        );

        match self.strategy {
            CombineStrategy::PriorityOrder => {
                priority_order(&self.engines, subject, action, resource)
            }
            CombineStrategy::AllowIfAll => allow_if_all(&self.engines, subject, action, resource),
            CombineStrategy::AllowIfAny => allow_if_any(&self.engines, subject, action, resource),
            CombineStrategy::DenyOverrides => {
                deny_overrides(&self.engines, subject, action, resource)
            }
        }
    }
}

// ── Strategy implementations ─────────────────────────────────────────────────

fn priority_order(
    engines: &[Arc<dyn PolicyEngine>],
    subject: &str,
    action: &str,
    resource: &str,
) -> PolicyResult {
    for engine in engines {
        match engine.check(subject, action, resource) {
            PolicyResult::Delegate(_) => continue,
            result => return result,
        }
    }
    PolicyResult::Delegate("all engines delegated".into())
}

fn allow_if_all(
    engines: &[Arc<dyn PolicyEngine>],
    subject: &str,
    action: &str,
    resource: &str,
) -> PolicyResult {
    let mut any_definitive = false;

    for engine in engines {
        match engine.check(subject, action, resource) {
            PolicyResult::Allow => {
                any_definitive = true;
            }
            PolicyResult::Delegate(_) => {
                // Abstain — skip this engine.
            }
            deny @ PolicyResult::Deny(_) => {
                // A single Deny breaks unanimous consent.
                return deny;
            }
        }
    }

    if any_definitive {
        PolicyResult::Allow
    } else {
        PolicyResult::Delegate("all engines delegated".into())
    }
}

fn allow_if_any(
    engines: &[Arc<dyn PolicyEngine>],
    subject: &str,
    action: &str,
    resource: &str,
) -> PolicyResult {
    let mut last_deny: Option<PolicyResult> = None;

    for engine in engines {
        match engine.check(subject, action, resource) {
            PolicyResult::Allow => return PolicyResult::Allow,
            deny @ PolicyResult::Deny(_) => {
                last_deny = Some(deny);
            }
            PolicyResult::Delegate(_) => {}
        }
    }

    last_deny.unwrap_or_else(|| PolicyResult::Delegate("all engines delegated".into()))
}

fn deny_overrides(
    engines: &[Arc<dyn PolicyEngine>],
    subject: &str,
    action: &str,
    resource: &str,
) -> PolicyResult {
    let mut any_allow = false;
    let mut first_deny: Option<String> = None;

    for engine in engines {
        match engine.check(subject, action, resource) {
            PolicyResult::Allow => {
                any_allow = true;
            }
            PolicyResult::Deny(reason) => {
                if first_deny.is_none() {
                    first_deny = Some(reason);
                }
            }
            PolicyResult::Delegate(_) => {}
        }
    }

    if let Some(reason) = first_deny {
        PolicyResult::Deny(reason)
    } else if any_allow {
        PolicyResult::Allow
    } else {
        PolicyResult::Delegate("all engines delegated".into())
    }
}

// ── PolicyEngineBuilder ──────────────────────────────────────────────────────

/// Builder for [`ComposedEngine`].
///
/// # Example
///
/// ```rust,ignore
/// let engine = PolicyEngineBuilder::new()
///     .add_engine(rbac)
///     .add_engine(odrl)
///     .strategy(CombineStrategy::DenyOverrides)
///     .build();
/// ```
#[derive(Default)]
pub struct PolicyEngineBuilder {
    engines: Vec<Arc<dyn PolicyEngine>>,
    strategy: CombineStrategy,
}

impl PolicyEngineBuilder {
    /// Create a new builder with `PriorityOrder` strategy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an engine (evaluated left to right).
    pub fn add_engine(mut self, engine: Arc<dyn PolicyEngine>) -> Self {
        self.engines.push(engine);
        self
    }

    /// Set the combination strategy.
    pub fn strategy(mut self, strategy: CombineStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Build the [`ComposedEngine`].
    pub fn build(self) -> ComposedEngine {
        ComposedEngine::new(self.engines, self.strategy)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyResult;
    use std::sync::Arc;

    fn allow() -> Arc<dyn PolicyEngine> {
        struct A;
        impl PolicyEngine for A {
            fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
                PolicyResult::Allow
            }
        }
        Arc::new(A)
    }

    fn deny(msg: &'static str) -> Arc<dyn PolicyEngine> {
        struct D(&'static str);
        impl PolicyEngine for D {
            fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
                PolicyResult::Deny(self.0.into())
            }
        }
        Arc::new(D(msg))
    }

    fn delegate() -> Arc<dyn PolicyEngine> {
        struct G;
        impl PolicyEngine for G {
            fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
                PolicyResult::Delegate("abstain".into())
            }
        }
        Arc::new(G)
    }

    // ── PriorityOrder ─────────────────────────────────────────────────────────

    #[test]
    fn priority_first_allow_wins() {
        let e = PolicyEngineBuilder::new()
            .add_engine(allow())
            .add_engine(deny("second"))
            .strategy(CombineStrategy::PriorityOrder)
            .build();
        assert_eq!(e.check("s", "a", "r"), PolicyResult::Allow);
    }

    #[test]
    fn priority_skips_delegate() {
        let e = PolicyEngineBuilder::new()
            .add_engine(delegate())
            .add_engine(allow())
            .strategy(CombineStrategy::PriorityOrder)
            .build();
        assert_eq!(e.check("s", "a", "r"), PolicyResult::Allow);
    }

    #[test]
    fn priority_all_delegate_returns_delegate() {
        let e = PolicyEngineBuilder::new()
            .add_engine(delegate())
            .add_engine(delegate())
            .strategy(CombineStrategy::PriorityOrder)
            .build();
        assert!(matches!(e.check("s", "a", "r"), PolicyResult::Delegate(_)));
    }

    // ── AllowIfAll ────────────────────────────────────────────────────────────

    #[test]
    fn allow_if_all_both_allow() {
        let e = PolicyEngineBuilder::new()
            .add_engine(allow())
            .add_engine(allow())
            .strategy(CombineStrategy::AllowIfAll)
            .build();
        assert_eq!(e.check("s", "a", "r"), PolicyResult::Allow);
    }

    #[test]
    fn allow_if_all_one_deny_overrides() {
        let e = PolicyEngineBuilder::new()
            .add_engine(allow())
            .add_engine(deny("no"))
            .strategy(CombineStrategy::AllowIfAll)
            .build();
        assert!(matches!(e.check("s", "a", "r"), PolicyResult::Deny(_)));
    }

    #[test]
    fn allow_if_all_delegate_abstains() {
        // Two allows and one delegate → Allow (delegate abstained)
        let e = PolicyEngineBuilder::new()
            .add_engine(allow())
            .add_engine(delegate())
            .add_engine(allow())
            .strategy(CombineStrategy::AllowIfAll)
            .build();
        assert_eq!(e.check("s", "a", "r"), PolicyResult::Allow);
    }

    // ── AllowIfAny ────────────────────────────────────────────────────────────

    #[test]
    fn allow_if_any_single_allow_wins() {
        let e = PolicyEngineBuilder::new()
            .add_engine(deny("first"))
            .add_engine(allow())
            .strategy(CombineStrategy::AllowIfAny)
            .build();
        assert_eq!(e.check("s", "a", "r"), PolicyResult::Allow);
    }

    #[test]
    fn allow_if_any_all_deny_returns_deny() {
        let e = PolicyEngineBuilder::new()
            .add_engine(deny("one"))
            .add_engine(deny("two"))
            .strategy(CombineStrategy::AllowIfAny)
            .build();
        assert!(matches!(e.check("s", "a", "r"), PolicyResult::Deny(_)));
    }

    // ── DenyOverrides ─────────────────────────────────────────────────────────

    #[test]
    fn deny_overrides_deny_beats_allow() {
        let e = PolicyEngineBuilder::new()
            .add_engine(allow())
            .add_engine(deny("prohibited"))
            .strategy(CombineStrategy::DenyOverrides)
            .build();
        assert!(matches!(e.check("s", "a", "r"), PolicyResult::Deny(_)));
    }

    #[test]
    fn deny_overrides_no_deny_allows() {
        let e = PolicyEngineBuilder::new()
            .add_engine(allow())
            .add_engine(delegate())
            .strategy(CombineStrategy::DenyOverrides)
            .build();
        assert_eq!(e.check("s", "a", "r"), PolicyResult::Allow);
    }

    #[test]
    fn deny_overrides_all_delegate_returns_delegate() {
        let e = PolicyEngineBuilder::new()
            .add_engine(delegate())
            .strategy(CombineStrategy::DenyOverrides)
            .build();
        assert!(matches!(e.check("s", "a", "r"), PolicyResult::Delegate(_)));
    }
}
