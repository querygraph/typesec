//! ODRL policy engine — implements [`PolicyEngine`] for an [`OdrlDocument`].

use std::collections::HashMap;

use glob::Pattern;
use tracing::debug;
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult, RequestContext},
};

use crate::{
    audit::{ConstraintEval, OdrlAuditEvent, OdrlVerdict},
    constraint::{ConstraintContext, evaluate},
    model::{OdrlDocument, OdrlRuleType, RuleAction},
};

struct RuleMatch {
    policy_uid: String,
    evals: Vec<ConstraintEval>,
}

type RuleKey = (String, String);
type RuleIndex = HashMap<RuleKey, Vec<RuleRef>>;
type WildcardActionIndex = HashMap<String, Vec<RuleRef>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuleRef {
    policy_index: usize,
    rule_index: usize,
    ordinal: usize,
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

        // Collect all matching indexed rules.
        let mut permission_matches: Vec<RuleMatch> = Vec::new();
        let mut prohibition_match: Option<(String, String, Vec<ConstraintEval>)> = None;

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

fn build_rule_index(doc: &OdrlDocument) -> (RuleIndex, WildcardActionIndex) {
    let mut exact_rules: RuleIndex = HashMap::new();
    let mut wildcard_action_rules: WildcardActionIndex = HashMap::new();
    let mut ordinal = 0;

    for (policy_index, policy) in doc.policies.iter().enumerate() {
        for (rule_index, rule) in policy.rules.iter().enumerate() {
            let rule_ref = RuleRef {
                policy_index,
                rule_index,
                ordinal,
            };
            ordinal += 1;

            if matches!(rule.action, RuleAction::Use) {
                wildcard_action_rules
                    .entry(rule.assignee.clone())
                    .or_default()
                    .push(rule_ref);
            } else {
                exact_rules
                    .entry((
                        rule.assignee.clone(),
                        rule.action.as_permission_name().to_owned(),
                    ))
                    .or_default()
                    .push(rule_ref);
            }
        }
    }

    (exact_rules, wildcard_action_rules)
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
    fn exact_rule_index_is_built_at_construction() {
        let e = engine();
        assert_eq!(
            e.exact_rules
                .get(&("agent:summarizer".to_owned(), "read".to_owned()))
                .expect("read rule indexed")
                .len(),
            1
        );
        assert_eq!(
            e.exact_rules
                .get(&("agent:summarizer".to_owned(), "ai:exfiltrate".to_owned()))
                .expect("exfiltrate rule indexed")
                .len(),
            1
        );
    }

    #[test]
    fn indexed_use_action_matches_any_action() {
        let yaml = r#"
policies:
  - uid: "policy:any-action"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:operator"
        action: use
        target: "asset:ops/*"
"#;
        let e = OdrlEngine::from_yaml(yaml).expect("engine build ok");
        assert_eq!(
            e.wildcard_action_rules
                .get("agent:operator")
                .expect("use rule indexed")
                .len(),
            1
        );

        let ctx = ConstraintContext::default();
        let result = e.check_with_context("agent:operator", "execute", "ops/restart", &ctx);
        assert_eq!(result, PolicyResult::Allow);
    }

    #[test]
    fn indexed_exact_action_still_checks_target_globs() {
        let yaml = r#"
policies:
  - uid: "policy:reports"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:analyst"
        action: read
        target: "asset:reports/**"
"#;
        let e = OdrlEngine::from_yaml(yaml).expect("engine build ok");
        let ctx = ConstraintContext::default();

        assert_eq!(
            e.check_with_context("agent:analyst", "read", "reports/2026/q1", &ctx),
            PolicyResult::Allow
        );
        assert!(matches!(
            e.check_with_context("agent:analyst", "read", "metrics/q1", &ctx),
            PolicyResult::Delegate(_)
        ));
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
