//! Shared policy-format detection, engine loading, and exit-code mapping.
//!
//! `check`, `run`, and `validate` all need to recognise a policy format and act
//! on it. Keeping one canonical detector here avoids the bug where the same file
//! is routed differently by different subcommands.

use std::sync::Arc;

use anyhow::{Result, bail};
use typesec_core::policy::{PolicyEngine, PolicyResult, RequestContext};

/// Detect the policy format from an explicit `--format` flag or the YAML body.
///
/// Returns `"graph"`, `"rbac"`, `"odrl"`, or `None` when nothing matches.
pub fn detect_format(explicit: &Option<String>, yaml: &str) -> Option<String> {
    if let Some(f) = explicit {
        return Some(f.clone());
    }
    if yaml.contains("graph_policy:") || yaml.contains("\"graph_policy\"") {
        Some("graph".into())
    } else if yaml.contains("roles:") {
        Some("rbac".into())
    } else if yaml.contains("policies:") {
        Some("odrl".into())
    } else {
        None
    }
}

/// Load a runtime policy engine for the given format.
pub fn load_engine(format: Option<&str>, yaml: &str) -> Result<Arc<dyn PolicyEngine>> {
    match format {
        Some("rbac") => Ok(Arc::new(
            typesec_rbac::RbacEngine::from_yaml(yaml).map_err(|e| anyhow::anyhow!(e))?,
        )),
        Some("odrl") => Ok(Arc::new(
            typesec_odrl::OdrlEngine::from_yaml(yaml).map_err(|e| anyhow::anyhow!(e))?,
        )),
        Some("graph") => Ok(Arc::new(
            typesec_rbac::GraphPolicyEngine::from_yaml(yaml).map_err(|e| anyhow::anyhow!(e))?,
        )),
        _ => bail!(
            "Could not detect policy format. Use --format rbac, --format odrl, or --format graph"
        ),
    }
}

/// Build a [`RequestContext`] from an optional purpose string.
pub fn request_context(purpose: Option<&str>) -> RequestContext {
    purpose.map_or_else(RequestContext::default, |p| {
        RequestContext::default().with_purpose(p)
    })
}

/// Exit code reflecting a policy decision: 0 = allow, 1 = deny, 2 = delegate.
///
/// Pure so the exit-code contract is unit-testable; [`exit_for_result`] is the
/// thin wrapper that actually terminates the process.
pub fn code_for_result(result: &PolicyResult) -> i32 {
    match result {
        PolicyResult::Allow => 0,
        PolicyResult::Deny(_) => 1,
        PolicyResult::Delegate(_) => 2,
        _ => 1,
    }
}

/// Exit reflecting a policy decision: 0 = allow, 1 = deny, 2 = delegate.
///
/// Shared by `check` and `run` so both are safe to gate CI on.
pub fn exit_for_result(result: &PolicyResult) -> ! {
    std::process::exit(code_for_result(result))
}

#[cfg(test)]
mod tests;
