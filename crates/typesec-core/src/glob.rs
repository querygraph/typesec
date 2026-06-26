//! Shared glob pattern matching for subjects, resources, and policy targets.
//!
//! One home for the `"*"`-special-cased glob used across the policy engines
//! (RBAC subject/resource patterns, the graph engine's resource matching, and
//! ODRL targets), so the three can't drift in their wildcard semantics or
//! recompile a pattern on every check.

use glob::{MatchOptions, Pattern};

/// Match options shared by every [`GlobPattern`]: a single `*` (or `?`) does not
/// cross `/` separators, so `reports/*` grants `reports/q1` but **not**
/// `reports/2024/q1` — a `reports/**` is required to span path segments. This is
/// the safer authorization default (a one-segment wildcard can't silently widen
/// to a whole subtree) and matches the documented semantics.
const MATCH_OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// A compiled glob pattern, with the literal `"*"` special-cased to match
/// everything (including across `/` separators).
#[derive(Debug, Clone)]
pub enum GlobPattern {
    /// The literal `"*"` — matches everything, including across `/`.
    Any,
    /// A compiled glob. A single `*` does not cross `/` separators:
    /// `reports/*` matches `reports/q1` but not `reports/2024/q1` (use
    /// `reports/**` for that).
    Glob(Pattern),
}

impl GlobPattern {
    /// Compile `pattern`, special-casing `"*"`.
    ///
    /// `kind` names what is being matched (`"subject"`, `"resource"`,
    /// `"target"`, …) and is only used to build the error message, e.g.
    /// `invalid resource pattern '...': ...`.
    pub fn compile(pattern: &str, kind: &str) -> Result<Self, String> {
        if pattern == "*" {
            return Ok(Self::Any);
        }
        Pattern::new(pattern)
            .map(Self::Glob)
            .map_err(|e| format!("invalid {kind} pattern '{pattern}': {e}"))
    }

    /// Returns `true` if `value` matches this pattern.
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Glob(pattern) => pattern.matches_with(value, MATCH_OPTIONS),
        }
    }
}

/// Returns `true` if `value` contains any glob metacharacter (`*`, `?`, `[`).
pub fn is_glob_pattern(value: &str) -> bool {
    value.contains(['*', '?', '['])
}

#[cfg(test)]
mod tests;
