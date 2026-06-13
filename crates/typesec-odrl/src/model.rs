//! Serde data model for ODRL YAML policies.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
    /// Read internal data.
    #[serde(rename = "read_internal")]
    ReadInternal,
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
            RuleAction::ReadInternal => "read_internal",
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
    pub left_operand: ConstraintOperand,
    /// The comparison operator.
    pub operator: ConstraintOperator,
    /// The right operand value (string representation).
    #[serde(rename = "rightOperand")]
    pub right_operand: String,
}

/// Typed ODRL constraint operands supported by TypeSec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintOperand {
    /// The request purpose.
    Purpose,
    /// The request timestamp; accepts `dateTime` and legacy `date` in YAML.
    DateTime,
    /// A count value supplied in the custom request context.
    Count,
    /// An extension operand supplied through custom request context.
    Custom(String),
}

impl ConstraintOperand {
    /// Parse an ODRL operand name.
    pub fn parse(name: impl Into<String>) -> Self {
        let name = name.into();
        match name.as_str() {
            "purpose" => Self::Purpose,
            "dateTime" | "date" => Self::DateTime,
            "count" => Self::Count,
            _ => Self::Custom(name),
        }
    }

    /// Return the canonical ODRL operand name.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Purpose => "purpose",
            Self::DateTime => "dateTime",
            Self::Count => "count",
            Self::Custom(name) => name,
        }
    }
}

impl fmt::Display for ConstraintOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ConstraintOperand {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ConstraintOperand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::parse)
    }
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
