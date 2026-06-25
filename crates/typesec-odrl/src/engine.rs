//! ODRL policy engine — implements [`PolicyEngine`] for an [`OdrlDocument`].

mod index;

use tracing::debug;
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult, RequestContext},
};

use crate::{
    audit::{ConstraintEval, OdrlAuditEvent, OdrlVerdict},
    constraint::{ConstraintContext, evaluate},
    model::{OdrlDocument, OdrlRuleType},
};
use index::{RuleIndex, RuleRef, WildcardActionIndex, build_rule_index, target_matches};

struct RuleMatch {
    policy_uid: String,
    evals: Vec<ConstraintEval>,
}

/// A rule that matched the target but had at least one failing constraint.
struct ConstraintFailure {
    policy_uid: String,
    rule_type: OdrlRuleType,
    evals: Vec<ConstraintEval>,
}

/// A matched prohibition: `(policy_uid, reason, constraint_evals)`.
type ProhibitionMatch = (String, String, Vec<ConstraintEval>);

/// Outcome of scanning candidate rules, before any audit is emitted.
struct ScanResult {
    permission_matches: Vec<RuleMatch>,
    prohibition_match: Option<ProhibitionMatch>,
    constraint_failures: Vec<ConstraintFailure>,
}

/// An ODRL policy engine.
///
/// The engine holds a parsed [`OdrlDocument`] and evaluates requests against
/// all matching rules. It applies ODRL's conflict resolution: **prohibitions
/// take precedence over permissions** when both match the same (subject, action, target).
///
/// Every check emits a structured [`OdrlAuditEvent`] via `tracing`.
pub struct OdrlEngine {
    doc: OdrlDocument,
    /// Exact `(assignee, action)` index for the common case.
    exact_rules: RuleIndex,
    /// Same-assignee wildcard action (`use`) rules.
    wildcard_action_rules: WildcardActionIndex,
    /// Default context applied to every check (can be overridden per-check).
    default_context: ConstraintContext,
}

impl OdrlEngine {
    /// Build an engine from a parsed document.
    pub fn new(doc: OdrlDocument) -> Self {
        let (exact_rules, wildcard_action_rules) = build_rule_index(&doc);
        Self {
            doc,
            exact_rules,
            wildcard_action_rules,
            default_context: ConstraintContext::default(),
        }
    }

    /// Parse a YAML string and build an engine.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let doc =
            OdrlDocument::from_yaml(yaml).map_err(|e| format!("ODRL YAML parse error: {e}"))?;
        Ok(Self::new(doc))
    }

    /// Override the default constraint context (e.g., set purpose for all checks).
    pub fn with_context(mut self, ctx: ConstraintContext) -> Self {
        self.default_context = ctx;
        self
    }

    /// Run a check with a specific context (overrides per-call).
    pub fn check_with_context(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        ctx: &ConstraintContext,
    ) -> PolicyResult {
        let (verdict, events) = self.decide(subject, action, resource, ctx);
        for event in &events {
            event.log();
        }
        verdict
    }

    /// Evaluate a request and return the verdict together with the full audit
    /// trail, *without* logging. Keeping this pure makes the audit trail
    /// testable; [`check_with_context`][Self::check_with_context] logs the events.
    fn decide(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        ctx: &ConstraintContext,
    ) -> (PolicyResult, Vec<OdrlAuditEvent>) {
        let candidates = self.candidate_rules(subject, action);
        debug!(
            subject,
            action,
            resource,
            n_candidates = candidates.len(),
            "odrl check"
        );

        let scan = self.scan_candidates(&candidates, action, resource, ctx);
        build_decision(scan, subject, action, resource)
    }

    /// Scan candidate rules and collect matching permissions and the first
    /// matching prohibition. Pure: emits no audit and renders no verdict.
    fn scan_candidates(
        &self,
        candidates: &[RuleRef],
        action: &str,
        resource: &str,
        ctx: &ConstraintContext,
    ) -> ScanResult {
        let mut permission_matches: Vec<RuleMatch> = Vec::new();
        let mut prohibition_match: Option<ProhibitionMatch> = None;
        let mut constraint_failures: Vec<ConstraintFailure> = Vec::new();

        for rule_ref in candidates {
            let policy = &self.doc.policies[rule_ref.policy_index];
            let rule = &policy.rules[rule_ref.rule_index];

            // Check target (glob) matches.
            if !target_matches(&rule.target, resource) {
                continue;
            }

            // Evaluate constraints.
            let constraint_evals: Vec<ConstraintEval> = rule
                .constraints
                .iter()
                .map(|c| ConstraintEval {
                    operand: c.left_operand.clone(),
                    passed: evaluate(c, ctx),
                })
                .collect();

            let all_passed = constraint_evals.iter().all(|e| e.passed);

            match rule.rule_type {
                OdrlRuleType::Prohibition if all_passed => {
                    let reason = format!(
                        "prohibited by policy '{}' (action '{}' on '{}')",
                        policy.uid, action, resource
                    );
                    if prohibition_match.is_none() {
                        prohibition_match = Some((policy.uid.clone(), reason, constraint_evals));
                    }
                    // Keep scanning so permissions overridden by the
                    // prohibition still appear in the audit trail.
                }
                OdrlRuleType::Permission if all_passed => {
                    permission_matches.push(RuleMatch {
                        policy_uid: policy.uid.clone(),
                        evals: constraint_evals,
                    });
                    // Don't break: a later prohibition might override this.
                }
                OdrlRuleType::Duty => {
                    // Duties are obligations, not gating rules. Typesec has no
                    // fulfillment-tracking model, so a duty is parsed and indexed
                    // but does not affect the Allow/Deny verdict. Documented no-op.
                }
                // A permission or prohibition that matched the target but failed
                // a constraint — surfaced in the audit trail (below) rather than
                // silently dropped.
                _ => {
                    constraint_failures.push(ConstraintFailure {
                        policy_uid: policy.uid.clone(),
                        rule_type: rule.rule_type,
                        evals: constraint_evals,
                    });
                }
            }
        }

        ScanResult {
            permission_matches,
            prohibition_match,
            constraint_failures,
        }
    }

    fn candidate_rules(&self, subject: &str, action: &str) -> Vec<RuleRef> {
        let mut candidates = Vec::new();

        if let Some(exact) = self
            .exact_rules
            .get(&(subject.to_owned(), action.to_owned()))
        {
            candidates.extend_from_slice(exact);
        }

        if let Some(wildcard) = self.wildcard_action_rules.get(subject) {
            candidates.extend_from_slice(wildcard);
        }

        if candidates.len() > 1 {
            candidates.sort_by_key(|rule_ref| rule_ref.ordinal);
        }

        candidates
    }
}

/// Render an ODRL verdict and the full audit trail for a [`ScanResult`].
///
/// Pure (no logging) so the events are testable. Prohibition wins over
/// permission; every constraint-failed rule and every matched permission is
/// recorded so the trail reflects the full basis for the decision.
fn build_decision(
    scan: ScanResult,
    subject: &str,
    action: &str,
    resource: &str,
) -> (PolicyResult, Vec<OdrlAuditEvent>) {
    let ScanResult {
        permission_matches,
        prohibition_match,
        constraint_failures,
    } = scan;
    let mut events = Vec::new();

    let event_for = |policy_uid, matched_rule, verdict, constraint_results| OdrlAuditEvent {
        policy_uid,
        matched_rule,
        subject: subject.to_owned(),
        action: action.to_owned(),
        target: resource.to_owned(),
        verdict,
        constraint_results,
    };

    // Surface every rule that matched the target but failed a constraint — the
    // event an auditor most wants, previously dropped silently.
    for failure in constraint_failures {
        let failed: Vec<String> = failure
            .evals
            .iter()
            .filter(|e| !e.passed)
            .map(|e| e.operand.to_string())
            .collect();
        events.push(event_for(
            failure.policy_uid,
            Some(failure.rule_type),
            OdrlVerdict::ConstraintFailed {
                constraint: failed.join(", "),
            },
            failure.evals,
        ));
    }

    // Resolution: prohibition wins over permission.
    if let Some((policy_uid, reason, evals)) = prohibition_match {
        for permission_match in permission_matches {
            events.push(event_for(
                permission_match.policy_uid,
                Some(OdrlRuleType::Permission),
                OdrlVerdict::Overridden {
                    by_policy: policy_uid.clone(),
                    reason: reason.clone(),
                },
                permission_match.evals,
            ));
        }
        events.push(event_for(
            policy_uid,
            Some(OdrlRuleType::Prohibition),
            OdrlVerdict::Prohibited {
                reason: reason.clone(),
            },
            evals,
        ));
        return (PolicyResult::Deny(reason), events);
    }

    if !permission_matches.is_empty() {
        // Record *every* matched permission, not just one, so the trail shows
        // the full basis for the Allow.
        for permission_match in permission_matches {
            events.push(event_for(
                permission_match.policy_uid,
                Some(OdrlRuleType::Permission),
                OdrlVerdict::Permitted,
                permission_match.evals,
            ));
        }
        return (PolicyResult::Allow, events);
    }

    // No rule matched — delegate to an outer engine (e.g., RBAC).
    events.push(event_for(
        "<none>".to_owned(),
        None,
        OdrlVerdict::NotApplicable,
        vec![],
    ));
    (
        PolicyResult::delegate("odrl", "no matching ODRL rule"),
        events,
    )
}

impl PolicyEngine for OdrlEngine {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        self.check_with_context(
            subject.as_str(),
            action,
            resource.as_str(),
            &self.default_context,
        )
    }

    fn check_with_context(
        &self,
        subject: &SubjectId,
        action: &str,
        resource: &ResourceId,
        ctx: &RequestContext,
    ) -> PolicyResult {
        let ctx = ConstraintContext::from(ctx);
        self.check_with_context(subject.as_str(), action, resource.as_str(), &ctx)
    }
}

#[cfg(test)]
mod tests;
