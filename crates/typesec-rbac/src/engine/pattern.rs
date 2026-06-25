//! Glob pattern matching for subjects and resources.

use glob::Pattern;

/// A compiled glob pattern, with the literal `"*"` special-cased to match
/// everything (including across `/` separators).
///
/// This backs both subject and resource matching — the two were byte-identical
/// apart from the error-message noun, which is supplied to [`GlobPattern::compile`]
/// as `kind`.
#[derive(Debug, Clone)]
pub(super) enum GlobPattern {
    /// The literal `"*"` — matches everything.
    Any,
    /// A compiled glob. Note glob `*` does not cross `/` separators:
    /// `reports/*` matches `reports/q1` but not `reports/2024/q1` (use
    /// `reports/**` for that).
    Glob(Pattern),
}

impl GlobPattern {
    /// Compile `pattern`, special-casing `"*"`.
    ///
    /// `kind` names what is being matched (`"subject"` or `"resource"`) and is
    /// only used to build the error message, e.g.
    /// `invalid resource pattern '...': ...`.
    pub(super) fn compile(pattern: &str, kind: &str) -> Result<Self, String> {
        if pattern == "*" {
            return Ok(Self::Any);
        }
        Pattern::new(pattern)
            .map(Self::Glob)
            .map_err(|e| format!("invalid {kind} pattern '{pattern}': {e}"))
    }

    /// Returns `true` if `value` matches this pattern.
    pub(super) fn matches(&self, value: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Glob(pattern) => pattern.matches(value),
        }
    }
}

/// Returns `true` if `value` contains any glob metacharacter (`*`, `?`, `[`).
pub(super) fn is_glob_pattern(value: &str) -> bool {
    value.contains(['*', '?', '['])
}
