//! Audit log types for ODRL policy decisions.

use tracing::info;

use crate::model::{ConstraintOperand, OdrlRuleType};

/// A structured audit record for a single ODRL policy check.
#[derive(Debug)]
pub struct OdrlAuditEvent {
    /// The policy UID that produced this verdict.
    pub policy_uid: String,
    /// The matched rule type (or `None` if no rule matched).
    pub matched_rule: Option<OdrlRuleType>,
    /// The subject making the request.
    pub subject: String,
    /// The action requested.
    pub action: String,
    /// The target resource.
    pub target: String,
    /// The final verdict.
    pub verdict: OdrlVerdict,
    /// Constraint evaluation results.
    pub constraint_results: Vec<ConstraintEval>,
}

/// Verdict of an ODRL check.
#[derive(Debug, Clone)]
pub enum OdrlVerdict {
    /// A permission rule matched and all constraints passed.
    Permitted,
    /// A prohibition rule matched and all constraints passed (action blocked).
    Prohibited {
        /// Human-readable reason explaining why the action is prohibited.
        reason: String,
    },
    /// A permission rule matched but was overridden by a prohibition.
    Overridden {
        /// The policy UID containing the prohibition that took priority.
        by_policy: String,
        /// Human-readable reason explaining the override.
        reason: String,
    },
    /// No matching rule found.
    NotApplicable,
    /// A permission rule matched but one or more constraints failed.
    ConstraintFailed {
        /// Description of the constraint that failed.
        constraint: String,
    },
}

/// Record of a single constraint's evaluation.
#[derive(Debug, Clone)]
pub struct ConstraintEval {
    /// The left operand (e.g., `"purpose"`).
    pub operand: ConstraintOperand,
    /// Whether it passed.
    pub passed: bool,
}

impl OdrlAuditEvent {
    /// Emit this event to the `tracing` subscriber.
    pub fn log(&self) {
        let verdict_str = match &self.verdict {
            OdrlVerdict::Permitted => "permitted".to_owned(),
            OdrlVerdict::Prohibited { reason } => format!("prohibited: {reason}"),
            OdrlVerdict::Overridden { by_policy, reason } => {
                format!("overridden by {by_policy}: {reason}")
            }
            OdrlVerdict::NotApplicable => "not_applicable".to_owned(),
            OdrlVerdict::ConstraintFailed { constraint } => {
                format!("constraint_failed: {constraint}")
            }
        };

        info!(
            policy = %self.policy_uid,
            subject = %self.subject,
            action = %self.action,
            target = %self.target,
            verdict = %verdict_str,
            "odrl policy decision"
        );
    }
}
