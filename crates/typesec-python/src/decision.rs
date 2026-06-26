//! The `Decision` pyclass and helpers that map `PolicyResult` to it.

use pyo3::prelude::*;
use typesec_core::policy::PolicyResult;

use crate::engine::compile_policy;
use crate::format::PolicyFormat;

#[pyclass(frozen)]
#[derive(Clone, Debug)]
pub(crate) struct Decision {
    #[pyo3(get)]
    pub(crate) allowed: bool,
    #[pyo3(get)]
    pub(crate) subject: String,
    #[pyo3(get)]
    pub(crate) action: String,
    #[pyo3(get)]
    pub(crate) resource: String,
    #[pyo3(get)]
    pub(crate) reason: Option<String>,
}

impl Decision {
    /// Build a decision from its parts; the four `PolicyResult` arms differ only
    /// in `allowed` and `reason`, so they share this one constructor.
    fn new(
        subject: &str,
        action: &str,
        resource: &str,
        allowed: bool,
        reason: Option<String>,
    ) -> Self {
        Self {
            allowed,
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            reason,
        }
    }
}

#[pymethods]
impl Decision {
    fn __repr__(&self) -> String {
        let verdict = if self.allowed { "ALLOW" } else { "DENY" };
        match &self.reason {
            Some(reason) => format!(
                "Decision({verdict}, subject={:?}, action={:?}, resource={:?}, reason={:?})",
                self.subject, self.action, self.resource, reason
            ),
            None => format!(
                "Decision({verdict}, subject={:?}, action={:?}, resource={:?})",
                self.subject, self.action, self.resource
            ),
        }
    }
}

pub(crate) fn check_policy(
    yaml: &str,
    format: PolicyFormat,
    subject: &str,
    action: &str,
    resource: &str,
    purpose: Option<&str>,
) -> PyResult<Decision> {
    let engine = compile_policy(yaml, format)?;
    Ok(decision_from_result(
        subject,
        action,
        resource,
        engine.check(subject, action, resource, purpose),
    ))
}

pub(crate) fn decision_from_result(
    subject: &str,
    action: &str,
    resource: &str,
    result: PolicyResult,
) -> Decision {
    let (allowed, reason) = match result {
        PolicyResult::Allow => (true, None),
        PolicyResult::Deny(reason) => (false, Some(reason)),
        PolicyResult::Delegate(reason) => (
            false,
            Some(format!(
                "policy delegated to {}: {}",
                reason.engine, reason.reason
            )),
        ),
        _ => (false, Some("unknown policy result".to_string())),
    };
    Decision::new(subject, action, resource, allowed, reason)
}
