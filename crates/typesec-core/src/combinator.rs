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

use std::ops::ControlFlow;
use std::sync::Arc;

use tracing::debug;

use crate::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyFuture, PolicyResult, RequestContext},
};

// ── CombineStrategy ──────────────────────────────────────────────────────────

/// How to combine multiple policy engine verdicts into a single decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
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
        debug!(
            subject = %subject,
            action,
            resource = %resource,
            strategy = ?self.strategy,
            n_engines = self.engines.len(),
            "composed engine check"
        );

        let mut verdicts = Verdicts::new(self.strategy);
        for engine in &self.engines {
            let verdict = engine.check_with_context(subject, action, resource, ctx);
            if let ControlFlow::Break(result) = verdicts.step(verdict) {
                return result;
            }
        }
        verdicts.finish()
    }

    fn check_with_context_async<'a>(
        &'a self,
        subject: &'a SubjectId,
        action: &'a str,
        resource: &'a ResourceId,
        ctx: &'a RequestContext,
    ) -> PolicyFuture<'a> {
        Box::pin(async move {
            let mut verdicts = Verdicts::new(self.strategy);
            for engine in &self.engines {
                let verdict = PolicyEngine::check_with_context_async(
                    engine.as_ref(),
                    subject,
                    action,
                    resource,
                    ctx,
                )
                .await;
                if let ControlFlow::Break(result) = verdicts.step(verdict) {
                    return result;
                }
            }
            verdicts.finish()
        })
    }
}

// ── Strategy combination ─────────────────────────────────────────────────────

/// The Delegate result returned when every engine abstained.
fn all_delegated() -> PolicyResult {
    PolicyResult::delegate("composed", "all engines delegated")
}

/// Running state for combining engine verdicts under a [`CombineStrategy`].
///
/// [`step`][Verdicts::step] folds in one engine's verdict and may short-circuit
/// (returning [`ControlFlow::Break`] so the driver stops calling engines);
/// [`finish`][Verdicts::finish] produces the combined result once every engine
/// has been consulted. The sync and async drivers in the [`PolicyEngine`] impl
/// both fold through this one type, so the two paths cannot drift apart.
enum Verdicts {
    /// `PriorityOrder`: the first non-Delegate verdict wins.
    Priority,
    /// `AllowIfAny`: the first Allow wins; otherwise the last Deny seen.
    AllowIfAny { last_deny: Option<PolicyResult> },
    /// `AllowIfAll`: any Deny overrides; else Allow if any engine was definitive.
    AllowIfAll {
        any_definitive: bool,
        deny_reasons: Vec<String>,
    },
    /// `DenyOverrides`: the first Deny overrides; else Allow if any engine allowed.
    DenyOverrides {
        any_allow: bool,
        first_deny: Option<String>,
    },
}

impl Verdicts {
    fn new(strategy: CombineStrategy) -> Self {
        match strategy {
            CombineStrategy::PriorityOrder => Self::Priority,
            CombineStrategy::AllowIfAny => Self::AllowIfAny { last_deny: None },
            CombineStrategy::AllowIfAll => Self::AllowIfAll {
                any_definitive: false,
                deny_reasons: Vec::new(),
            },
            CombineStrategy::DenyOverrides => Self::DenyOverrides {
                any_allow: false,
                first_deny: None,
            },
        }
    }

    /// Fold in one engine's verdict, short-circuiting when the decision is final.
    fn step(&mut self, verdict: PolicyResult) -> ControlFlow<PolicyResult> {
        match self {
            Self::Priority => match verdict {
                PolicyResult::Delegate(_) => ControlFlow::Continue(()),
                result => ControlFlow::Break(result),
            },
            Self::AllowIfAny { last_deny } => match verdict {
                PolicyResult::Allow => ControlFlow::Break(PolicyResult::Allow),
                deny @ PolicyResult::Deny(_) => {
                    *last_deny = Some(deny);
                    ControlFlow::Continue(())
                }
                PolicyResult::Delegate(_) => ControlFlow::Continue(()),
            },
            Self::AllowIfAll {
                any_definitive,
                deny_reasons,
            } => {
                match verdict {
                    PolicyResult::Allow => *any_definitive = true,
                    PolicyResult::Deny(reason) => deny_reasons.push(reason),
                    PolicyResult::Delegate(_) => {}
                }
                ControlFlow::Continue(())
            }
            Self::DenyOverrides {
                any_allow,
                first_deny,
            } => {
                match verdict {
                    PolicyResult::Allow => *any_allow = true,
                    PolicyResult::Deny(reason) => {
                        if first_deny.is_none() {
                            *first_deny = Some(reason);
                        }
                    }
                    PolicyResult::Delegate(_) => {}
                }
                ControlFlow::Continue(())
            }
        }
    }

    /// Produce the combined verdict after every engine has been consulted.
    fn finish(self) -> PolicyResult {
        match self {
            Self::Priority => all_delegated(),
            Self::AllowIfAny { last_deny } => last_deny.unwrap_or_else(all_delegated),
            Self::AllowIfAll {
                any_definitive,
                deny_reasons,
            } => {
                if !deny_reasons.is_empty() {
                    PolicyResult::Deny(deny_reasons.join("; "))
                } else if any_definitive {
                    PolicyResult::Allow
                } else {
                    all_delegated()
                }
            }
            Self::DenyOverrides {
                any_allow,
                first_deny,
            } => {
                if let Some(reason) = first_deny {
                    PolicyResult::Deny(reason)
                } else if any_allow {
                    PolicyResult::Allow
                } else {
                    all_delegated()
                }
            }
        }
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
mod tests;
