//! ODRL policy engine — implements [`PolicyEngine`] for an [`OdrlDocument`].

use glob::Pattern;
use tracing::debug;
use typesec_core::policy::{PolicyEngine, PolicyResult, RequestContext};

use crate::{
    audit::{ConstraintEval, OdrlAuditEvent, OdrlVerdict},
    constraint::{ConstraintContext, evaluate},
    model::{OdrlDocument, OdrlRuleType},
};

struct RuleMatch {
    policy_uid: String,
    evals: Vec<ConstraintEval>,
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
    /// Default context applied to every check (can be overridden per-check).
    default_context: ConstraintContext,
}

impl OdrlEngine {
    /// Build an engine from a parsed document.
    pub fn new(doc: OdrlDocument) -> Self {
        Self {
            doc,
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
        debug!(subject, action, resource, "odrl check");

        // Collect all matching rules across all policies.
        let mut permission_matches: Vec<RuleMatch> = Vec::new();
        let mut prohibition_match: Option<(String, String, Vec<ConstraintEval>)> = None;

        for policy in &self.doc.policies {
            for rule in &policy.rules {
                // Check assignee matches.
                if rule.assignee != subject {
                    continue;
                }
                // Check action matches.
                if !rule.action.matches_action(action) {
                    continue;
                }
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
                            prohibition_match =
                                Some((policy.uid.clone(), reason, constraint_evals));
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
        }

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
}

impl PolicyEngine for OdrlEngine {
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        self.check_with_context(subject, action, resource, &self.default_context)
    }

    fn check_with_context(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        ctx: &RequestContext,
    ) -> PolicyResult {
        let ctx = ConstraintContext::from(ctx);
        self.check_with_context(subject, action, resource, &ctx)
    }
}

/// Match a target string (which may be an ODRL URI or a glob pattern) against
/// a resource identifier.
fn target_matches(target: &str, resource: &str) -> bool {
    if target == resource {
        return true;
    }
    // Strip `"asset:"` prefix if present for simple matching.
    let stripped = target.strip_prefix("asset:").unwrap_or(target);
    if stripped == resource {
        return true;
    }
    Pattern::new(stripped).is_ok_and(|p| p.matches(resource))
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
policies:
  - uid: "policy:ai-agent-001"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:summarizer"
        action: read
        target: "asset:customer-data"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "analytics"
          - leftOperand: dateTime
            operator: lt
            rightOperand: "2099-01-01T00:00:00Z"
      - type: prohibition
        assignee: "agent:summarizer"
        action: exfiltrate
        target: "asset:customer-data"
"#;

    fn engine() -> OdrlEngine {
        OdrlEngine::from_yaml(YAML).expect("engine build ok")
    }

    #[test]
    fn read_allowed_with_correct_purpose() {
        let e = engine();
        let ctx = ConstraintContext::default().with_purpose("analytics");
        let result = e.check_with_context("agent:summarizer", "read", "customer-data", &ctx);
        assert_eq!(result, PolicyResult::Allow);
    }

    #[test]
    fn read_denied_wrong_purpose() {
        let e = engine();
        let ctx = ConstraintContext::default().with_purpose("billing");
        let result = e.check_with_context("agent:summarizer", "read", "customer-data", &ctx);
        // No permission matched (purpose constraint failed) → delegate
        assert!(matches!(result, PolicyResult::Delegate(_)));
    }

    #[test]
    fn exfiltrate_is_prohibited() {
        let e = engine();
        let ctx = ConstraintContext::default();
        let result =
            e.check_with_context("agent:summarizer", "ai:exfiltrate", "customer-data", &ctx);
        assert!(matches!(result, PolicyResult::Deny(_)));
    }

    #[test]
    fn unknown_subject_delegates() {
        let e = engine();
        let ctx = ConstraintContext::default().with_purpose("analytics");
        let result = e.check_with_context("agent:unknown", "read", "customer-data", &ctx);
        assert!(matches!(result, PolicyResult::Delegate(_)));
    }

    #[test]
    fn prohibition_does_not_stop_later_permission_scan() {
        let yaml = r#"
policies:
  - uid: "policy:block"
    type: Set
    rules:
      - type: prohibition
        assignee: "agent:summarizer"
        action: read
        target: "asset:customer-data"
  - uid: "policy:allow"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:summarizer"
        action: read
        target: "asset:customer-data"
"#;
        let e = OdrlEngine::from_yaml(yaml).expect("engine build ok");
        let ctx = ConstraintContext::default();
        let result = e.check_with_context("agent:summarizer", "read", "customer-data", &ctx);
        assert!(matches!(result, PolicyResult::Deny(_)));
    }
}
