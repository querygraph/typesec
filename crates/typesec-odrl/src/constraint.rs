//! Constraint evaluation for ODRL rules.
//!
//! Constraints are runtime conditions: purpose, date/time, count, etc.
//! This module evaluates them given a [`ConstraintContext`].

use chrono::{DateTime, Utc};
use tracing::debug;
use typesec_core::policy::RequestContext;

use crate::model::{ConstraintOperator, OdrlConstraint};

/// Context provided when evaluating constraints.
///
/// The context carries *all* information about the current request that
/// constraints might need to evaluate. Add fields here as your policies grow.
#[derive(Debug, Clone, Default)]
pub struct ConstraintContext {
    /// The purpose of this access request (e.g., `"analytics"`, `"audit"`).
    pub purpose: Option<String>,
    /// The current time (defaults to `Utc::now()` if not specified).
    pub now: Option<DateTime<Utc>>,
    /// An arbitrary key-value store for custom constraint operands.
    pub custom: std::collections::HashMap<String, String>,
}

impl ConstraintContext {
    /// Create a context with a given purpose.
    pub fn with_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    /// Create a context with a specific time (useful for testing).
    pub fn with_time(mut self, t: DateTime<Utc>) -> Self {
        self.now = Some(t);
        self
    }

    /// Add a custom key-value pair.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }

    fn effective_now(&self) -> DateTime<Utc> {
        self.now.unwrap_or_else(Utc::now)
    }
}

impl From<&RequestContext> for ConstraintContext {
    fn from(ctx: &RequestContext) -> Self {
        Self {
            purpose: ctx.purpose.clone(),
            now: None,
            custom: ctx.custom.clone(),
        }
    }
}

/// Evaluate a single ODRL constraint against a context.
///
/// Returns `true` if the constraint is satisfied, `false` otherwise.
pub fn evaluate(constraint: &OdrlConstraint, ctx: &ConstraintContext) -> bool {
    debug!(
        left = %constraint.left_operand,
        op = ?constraint.operator,
        right = %constraint.right_operand,
        "evaluating constraint"
    );

    match constraint.left_operand.as_str() {
        "purpose" => evaluate_purpose(constraint, ctx),
        "dateTime" => evaluate_datetime(constraint, ctx),
        "date" => evaluate_datetime(constraint, ctx),
        other => {
            // Fall back to custom context values.
            if let Some(val) = ctx.custom.get(other) {
                evaluate_string_op(&constraint.operator, val, &constraint.right_operand)
            } else {
                // Unknown operand — be conservative and deny.
                debug!("unknown constraint left operand '{other}' — failing closed");
                false
            }
        }
    }
}

fn evaluate_purpose(constraint: &OdrlConstraint, ctx: &ConstraintContext) -> bool {
    let actual = match ctx.purpose.as_deref() {
        Some(p) => p,
        None => return false,
    };
    evaluate_string_op(&constraint.operator, actual, &constraint.right_operand)
}

fn evaluate_datetime(constraint: &OdrlConstraint, ctx: &ConstraintContext) -> bool {
    let now = ctx.effective_now();

    let rhs = match constraint.right_operand.parse::<DateTime<Utc>>() {
        Ok(dt) => dt,
        Err(e) => {
            debug!(
                "could not parse dateTime '{}': {e}",
                constraint.right_operand
            );
            return false;
        }
    };

    match constraint.operator {
        ConstraintOperator::Lt => now < rhs,
        ConstraintOperator::Lteq => now <= rhs,
        ConstraintOperator::Gt => now > rhs,
        ConstraintOperator::Gteq => now >= rhs,
        ConstraintOperator::Eq => now == rhs,
        ConstraintOperator::Neq => now != rhs,
        ConstraintOperator::IsPartOf => false, // doesn't apply to dates
    }
}

fn evaluate_string_op(op: &ConstraintOperator, actual: &str, expected: &str) -> bool {
    match op {
        ConstraintOperator::Eq => actual == expected,
        ConstraintOperator::Neq => actual != expected,
        ConstraintOperator::IsPartOf => expected.split(',').any(|v| v.trim() == actual),
        // Lexicographic ordering for strings (reasonable for simple tags).
        ConstraintOperator::Lt => actual < expected,
        ConstraintOperator::Lteq => actual <= expected,
        ConstraintOperator::Gt => actual > expected,
        ConstraintOperator::Gteq => actual >= expected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConstraintOperator, OdrlConstraint};

    fn make_constraint(left: &str, op: ConstraintOperator, right: &str) -> OdrlConstraint {
        OdrlConstraint {
            left_operand: left.into(),
            operator: op,
            right_operand: right.into(),
        }
    }

    #[test]
    fn purpose_eq_passes() {
        let c = make_constraint("purpose", ConstraintOperator::Eq, "analytics");
        let ctx = ConstraintContext::default().with_purpose("analytics");
        assert!(evaluate(&c, &ctx));
    }

    #[test]
    fn purpose_eq_fails_wrong_value() {
        let c = make_constraint("purpose", ConstraintOperator::Eq, "analytics");
        let ctx = ConstraintContext::default().with_purpose("billing");
        assert!(!evaluate(&c, &ctx));
    }

    #[test]
    fn purpose_is_part_of() {
        let c = make_constraint(
            "purpose",
            ConstraintOperator::IsPartOf,
            "analytics, audit, reporting",
        );
        let ctx = ConstraintContext::default().with_purpose("audit");
        assert!(evaluate(&c, &ctx));
    }

    #[test]
    fn datetime_lt_passes_when_before() {
        let future = "2099-01-01T00:00:00Z";
        let c = make_constraint("dateTime", ConstraintOperator::Lt, future);
        let ctx = ConstraintContext::default();
        assert!(evaluate(&c, &ctx));
    }

    #[test]
    fn datetime_lt_fails_when_past() {
        let past = "2000-01-01T00:00:00Z";
        let c = make_constraint("dateTime", ConstraintOperator::Lt, past);
        let ctx = ConstraintContext::default();
        assert!(!evaluate(&c, &ctx));
    }
}
