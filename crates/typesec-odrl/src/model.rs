//! Serde data model for ODRL YAML policies.

use serde::{Deserialize, Serialize};

/// Root document: a collection of ODRL policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdrlDocument {
    /// The policies in this document.
    pub policies: Vec<OdrlPolicy>,
}

impl OdrlDocument {
    /// Parse from YAML.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }
}

/// An ODRL Policy.
///
/// A policy bundles related rules under a unique identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdrlPolicy {
    /// Unique identifier (e.g., `"policy:ai-agent-001"`).
    pub uid: String,
    /// Policy type — `Set`, `Offer`, or `Agreement`.
    #[serde(rename = "type")]
    pub policy_type: String,
    /// The rules in this policy.
    pub rules: Vec<OdrlRule>,
}

/// An ODRL Rule (permission, prohibition, or duty).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdrlRule {
    /// Rule type: `"permission"`, `"prohibition"`, or `"duty"`.
    #[serde(rename = "type")]
    pub rule_type: OdrlRuleType,
    /// The party granting permission (optional for prohibitions).
    #[serde(default)]
    pub assigner: Option<String>,
    /// The party the rule applies to.
    pub assignee: String,
    /// The action this rule covers.
    pub action: RuleAction,
    /// The asset this rule applies to.
    pub target: String,
    /// Constraints that must hold for the rule to apply.
    #[serde(default)]
    pub constraints: Vec<OdrlConstraint>,
}

/// The type of an ODRL rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OdrlRuleType {
    /// Grants the assignee the action on the target (if constraints hold).
    Permission,
    /// Denies the assignee the action on the target (if constraints hold).
    Prohibition,
    /// Obligates the assignee to perform the action.
    Duty,
}

/// An ODRL action.
///
/// Maps to our `Permission::name()` strings plus the special `"use"` wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// Delete access.
    Delete,
    /// Execute access.
    Execute,
    /// Delegation.
    Delegate,
    /// Read sensitive data.
    #[serde(rename = "read_sensitive")]
    ReadSensitive,
    /// Write sensitive data.
    #[serde(rename = "write_sensitive")]
    WriteSensitive,
    /// AI inference.
    #[serde(rename = "ai:infer")]
    AiInfer,
    /// AI training.
    #[serde(rename = "ai:train")]
    AiTrain,
    /// Data exfiltration.
    #[serde(rename = "exfiltrate")]
    Exfiltrate,
    /// Wildcard — applies to all actions.
    Use,
}

impl RuleAction {
    /// Convert to the `Permission::name()` string.
    pub fn as_permission_name(&self) -> &str {
        match self {
            RuleAction::Read => "read",
            RuleAction::Write => "write",
            RuleAction::Delete => "delete",
            RuleAction::Execute => "execute",
            RuleAction::Delegate => "delegate",
            RuleAction::ReadSensitive => "read_sensitive",
            RuleAction::WriteSensitive => "write_sensitive",
            RuleAction::AiInfer => "ai:infer",
            RuleAction::AiTrain => "ai:train",
            RuleAction::Exfiltrate => "ai:exfiltrate",
            RuleAction::Use => "*",
        }
    }

    /// Returns `true` if this action matches the given permission name.
    pub fn matches_action(&self, action: &str) -> bool {
        self == &RuleAction::Use || self.as_permission_name() == action
    }
}

/// An ODRL constraint on a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdrlConstraint {
    /// The left operand (e.g., `"purpose"`, `"dateTime"`, `"count"`).
    #[serde(rename = "leftOperand")]
    pub left_operand: String,
    /// The comparison operator.
    pub operator: ConstraintOperator,
    /// The right operand value (string representation).
    #[serde(rename = "rightOperand")]
    pub right_operand: String,
}

/// ODRL constraint operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConstraintOperator {
    /// Equal.
    Eq,
    /// Not equal.
    Neq,
    /// Less than.
    Lt,
    /// Less than or equal.
    Lteq,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Gteq,
    /// Is in a comma-separated list.
    #[serde(rename = "isPartOf")]
    IsPartOf,
}
