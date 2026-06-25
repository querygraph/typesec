//! Rule index: the lookup tables that let the engine find candidate rules for a
//! `(subject, action)` pair without scanning every policy.

use std::collections::HashMap;

use glob::Pattern;

use crate::model::{OdrlDocument, RuleAction};

pub(super) type RuleKey = (String, String);
pub(super) type RuleIndex = HashMap<RuleKey, Vec<RuleRef>>;
pub(super) type WildcardActionIndex = HashMap<String, Vec<RuleRef>>;

/// A pointer into the parsed document identifying a single rule, plus the
/// `ordinal` (document order) used to keep candidate evaluation deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RuleRef {
    pub(super) policy_index: usize,
    pub(super) rule_index: usize,
    pub(super) ordinal: usize,
}

/// Match a target string (which may be an ODRL URI or a glob pattern) against
/// a resource identifier.
pub(super) fn target_matches(target: &str, resource: &str) -> bool {
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

/// Build the exact and wildcard-action rule indexes from a document.
pub(super) fn build_rule_index(doc: &OdrlDocument) -> (RuleIndex, WildcardActionIndex) {
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
