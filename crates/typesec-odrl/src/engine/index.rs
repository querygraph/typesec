//! Rule index: the lookup tables that let the engine find candidate rules for a
//! `(subject, action)` pair without scanning every policy.

use std::collections::HashMap;

use tracing::warn;
use typesec_core::glob::GlobPattern;

use crate::model::{OdrlDocument, RuleAction};

pub(super) type RuleKey = (String, String);
pub(super) type RuleIndex = HashMap<RuleKey, Vec<RuleRef>>;
pub(super) type WildcardActionIndex = HashMap<String, Vec<RuleRef>>;

/// A rule's target, compiled once at load: the raw target string plus a
/// [`GlobPattern`] over its `asset:`-stripped form.
///
/// Compiling at construction (rather than per check) keeps target matching off
/// the hot path and routes ODRL through the same wildcard semantics as RBAC and
/// the graph engine (notably a literal `"*"` matching across `/`).
#[derive(Debug, Clone)]
pub(super) struct CompiledTarget {
    raw: String,
    /// Compiled glob over the `asset:`-stripped target; `None` if the target was
    /// not a valid glob (it then only matches by exact equality).
    pattern: Option<GlobPattern>,
}

impl CompiledTarget {
    fn compile(target: &str) -> Self {
        // Strip `"asset:"` so `asset:foo` globs as `foo`.
        let stripped = target.strip_prefix("asset:").unwrap_or(target);
        // A malformed glob never glob-matches (preserving prior behavior), but log
        // it at load so a typo'd target surfaces instead of silently denying.
        let pattern = match GlobPattern::compile(stripped, "target") {
            Ok(pattern) => Some(pattern),
            Err(err) => {
                warn!(target, %err, "ODRL target is not a valid glob; it will never match");
                None
            }
        };
        Self {
            raw: target.to_owned(),
            pattern,
        }
    }

    /// Match this target against a resource identifier.
    pub(super) fn matches(&self, resource: &str) -> bool {
        // Exact match (covers a resource that includes the `asset:` prefix), then
        // the compiled glob over the stripped form.
        self.raw == resource || self.pattern.as_ref().is_some_and(|p| p.matches(resource))
    }
}

/// Compile every rule's target once, keyed by `(policy_index, rule_index)`.
pub(super) fn compile_targets(doc: &OdrlDocument) -> HashMap<(usize, usize), CompiledTarget> {
    let mut targets = HashMap::new();
    for (policy_index, policy) in doc.policies.iter().enumerate() {
        for (rule_index, rule) in policy.rules.iter().enumerate() {
            targets.insert(
                (policy_index, rule_index),
                CompiledTarget::compile(&rule.target),
            );
        }
    }
    targets
}

/// A pointer into the parsed document identifying a single rule, plus the
/// `ordinal` (document order) used to keep candidate evaluation deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RuleRef {
    pub(super) policy_index: usize,
    pub(super) rule_index: usize,
    pub(super) ordinal: usize,
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
