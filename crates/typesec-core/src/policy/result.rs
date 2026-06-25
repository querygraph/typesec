//! Policy verdicts and the request context engines evaluate against.

use std::collections::HashMap;
use std::fmt;

/// The verdict returned by a policy engine.
#[must_use = "policy decisions must be checked; an ignored result is a silent allow/deny"]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyResult {
    /// The action is allowed. The engine may provide a rationale.
    Allow,
    /// The action is denied. The string explains why (for audit logs / UX).
    Deny(String),
    /// The engine cannot make a decision; defer to another engine.
    ///
    /// Used in policy composition: e.g., an ODRL engine delegates to RBAC
    /// for actions not covered by any ODRL rule.
    Delegate(DelegationReason),
}

impl PolicyResult {
    /// Build a structured delegation decision.
    pub fn delegate(engine: &'static str, reason: impl Into<String>) -> Self {
        Self::Delegate(DelegationReason::new(engine, reason))
    }
}

/// Structured explanation for an unresolved policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationReason {
    /// Engine that delegated.
    pub engine: &'static str,
    /// Why this engine could not decide.
    pub reason: String,
    /// Optional extra context about the delegation path.
    pub context: Option<String>,
}

impl DelegationReason {
    /// Create a delegation reason without extra context.
    pub fn new(engine: &'static str, reason: impl Into<String>) -> Self {
        Self {
            engine,
            reason: reason.into(),
            context: None,
        }
    }

    /// Attach additional path/context detail.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

impl fmt::Display for DelegationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.context {
            Some(context) => write!(f, "{}: {} ({context})", self.engine, self.reason),
            None => write!(f, "{}: {}", self.engine, self.reason),
        }
    }
}

impl fmt::Display for PolicyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny(reason) => write!(f, "deny: {reason}"),
            Self::Delegate(reason) => write!(f, "delegate: {reason}"),
        }
    }
}

/// Runtime context attached to a policy decision request.
///
/// Plain RBAC-style engines can ignore this. Constraint-aware engines, such as
/// ODRL, use it for values that are only known at request time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestContext {
    /// Purpose for this access request, such as `"analytics"` or `"audit"`.
    pub purpose: Option<String>,
    /// Custom context values keyed by constraint operand name.
    pub custom: HashMap<String, String>,
}

impl RequestContext {
    /// Create an empty request context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add purpose context.
    pub fn with_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    /// Add a custom key-value pair.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }
}
