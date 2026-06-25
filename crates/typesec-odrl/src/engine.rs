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

/// A matched prohibition: `(policy_uid, reason, constraint_evals)`.
type ProhibitionMatch = (String, String, Vec<ConstraintEval>);

/// Outcome of scanning candidate rules, before any audit is emitted.
struct ScanResult {
    permission_matches: Vec<RuleMatch>,
    prohibition_match: Option<ProhibitionMatch>,
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
        let candidates = self.candidate_rules(subject, action);
        debug!(
            subject,
            action,
            resource,
            n_candidates = candidates.len(),
            "odrl check"
        );

        let scan = self.scan_candidates(&candidates, action, resource, ctx);
        self.resolve_with_audit(scan, subject, action, resource)
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
                _ => {} // duty, or constraint failed
            }
        }

        ScanResult {
            permission_matches,
            prohibition_match,
        }
    }

    /// Apply ODRL conflict resolution to a [`ScanResult`], emit the audit trail,
    /// and return the verdict. Prohibition wins over permission.
    fn resolve_with_audit(
        &self,
        scan: ScanResult,
        subject: &str,
        action: &str,
        resource: &str,
    ) -> PolicyResult {
        let ScanResult {
            mut permission_matches,
            prohibition_match,
        } = scan;

        // Resolution: prohibition wins over permission.
        if let Some((policy_uid, reason, evals)) = prohibition_match {
            for permission_match in permission_matches {
                let event = OdrlAuditEvent {
                    policy_uid: permission_match.policy_uid,
                    matched_rule: Some(OdrlRuleType::Permission),
                    subject: subject.to_owned(),
                    action: action.to_owned(),
                    target: resource.to_owned(),
                    verdict: OdrlVerdict::Overridden {
                        by_policy: policy_uid.clone(),
                        reason: reason.clone(),
                    },
                    constraint_results: permission_match.evals,
                };
                event.log();
            }

            let event = OdrlAuditEvent {
                policy_uid: policy_uid.to_owned(),
                matched_rule: Some(OdrlRuleType::Prohibition),
                subject: subject.to_owned(),
                action: action.to_owned(),
                target: resource.to_owned(),
                verdict: OdrlVerdict::Prohibited {
                    reason: reason.clone(),
                },
                constraint_results: evals,
            };
            event.log();
            return PolicyResult::Deny(reason);
        }

        if let Some(permission_match) = permission_matches.pop() {
            let event = OdrlAuditEvent {
                policy_uid: permission_match.policy_uid,
                matched_rule: Some(OdrlRuleType::Permission),
                subject: subject.to_owned(),
                action: action.to_owned(),
                target: resource.to_owned(),
                verdict: OdrlVerdict::Permitted,
                constraint_results: permission_match.evals,
            };
            event.log();
            return PolicyResult::Allow;
        }

        // No rule matched — delegate to an outer engine (e.g., RBAC).
        let event = OdrlAuditEvent {
            policy_uid: "<none>".to_owned(),
            matched_rule: None,
            subject: subject.to_owned(),
            action: action.to_owned(),
            target: resource.to_owned(),
            verdict: OdrlVerdict::NotApplicable,
            constraint_results: vec![],
        };
        event.log();
        PolicyResult::delegate("odrl", "no matching ODRL rule")
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
