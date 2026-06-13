//! Rust-backed Python bindings for Typesec policy decisions.

use pyo3::exceptions::{PyPermissionError, PyValueError};
use pyo3::prelude::*;
use typesec_core::policy::{PolicyEngine, PolicyResult, RequestContext};

#[derive(Clone, Copy)]
enum PolicyFormat {
    Rbac,
    Odrl,
    Graph,
}

impl PolicyFormat {
    fn detect(explicit: Option<&str>, yaml: &str) -> PyResult<Self> {
        match explicit {
            Some("rbac") => Ok(Self::Rbac),
            Some("odrl") => Ok(Self::Odrl),
            Some("graph") => Ok(Self::Graph),
            Some(other) => Err(PyValueError::new_err(format!(
                "unsupported policy format '{other}'; use rbac, odrl, or graph"
            ))),
            None if yaml.contains("graph_policy:") => Ok(Self::Graph),
            None if yaml.contains("roles:") => Ok(Self::Rbac),
            None if yaml.contains("policies:") => Ok(Self::Odrl),
            None => Err(PyValueError::new_err(
                "could not detect policy format; pass format='rbac', 'odrl', or 'graph'",
            )),
        }
    }
}

#[pyclass(frozen)]
#[derive(Clone, Debug)]
struct Decision {
    #[pyo3(get)]
    allowed: bool,
    #[pyo3(get)]
    subject: String,
    #[pyo3(get)]
    action: String,
    #[pyo3(get)]
    resource: String,
    #[pyo3(get)]
    reason: Option<String>,
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

#[pyclass]
struct TypesecGate {
    engine: CompiledPolicyEngine,
}

#[pymethods]
impl TypesecGate {
    #[new]
    #[pyo3(signature = (policy_yaml, format = None))]
    fn new(policy_yaml: String, format: Option<&str>) -> PyResult<Self> {
        let format = PolicyFormat::detect(format, &policy_yaml)?;
        let engine = compile_policy(&policy_yaml, format)?;
        Ok(Self { engine })
    }

    #[staticmethod]
    #[pyo3(signature = (path, format = None))]
    fn from_file(path: &str, format: Option<&str>) -> PyResult<Self> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|err| PyValueError::new_err(format!("failed to read policy: {err}")))?;
        Self::new(yaml, format)
    }

    #[pyo3(signature = (subject, action, resource, purpose = None))]
    fn check(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        purpose: Option<&str>,
    ) -> PyResult<Decision> {
        Ok(decision_from_result(
            subject,
            action,
            resource,
            self.engine.check(subject, action, resource, purpose),
        ))
    }

    #[pyo3(signature = (subject, action, resource, purpose = None))]
    fn require(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        purpose: Option<&str>,
    ) -> PyResult<Decision> {
        let decision = self.check(subject, action, resource, purpose)?;
        if decision.allowed {
            Ok(decision)
        } else {
            let reason = decision
                .reason
                .clone()
                .unwrap_or_else(|| "access denied".to_string());
            Err(PyPermissionError::new_err(reason))
        }
    }
}

#[pyfunction]
/// Evaluate one policy decision by compiling the supplied policy YAML.
///
/// This function is convenient for one-shot checks. For repeated decisions,
/// construct `TypesecGate` once and call its `check()`/`require()` methods so
/// the compiled policy engine is reused.
#[pyo3(signature = (policy_yaml, subject, action, resource, format = None, purpose = None))]
fn check(
    policy_yaml: &str,
    subject: &str,
    action: &str,
    resource: &str,
    format: Option<&str>,
    purpose: Option<&str>,
) -> PyResult<Decision> {
    let format = PolicyFormat::detect(format, policy_yaml)?;
    check_policy(policy_yaml, format, subject, action, resource, purpose)
}

#[pyfunction]
#[pyo3(signature = (policy_yaml, format = None))]
fn validate(policy_yaml: &str, format: Option<&str>) -> PyResult<()> {
    let format = PolicyFormat::detect(format, policy_yaml)?;
    compile_policy(policy_yaml, format).map(|_| ())
}

fn compile_policy(yaml: &str, format: PolicyFormat) -> PyResult<CompiledPolicyEngine> {
    match format {
        PolicyFormat::Rbac => {
            let engine = typesec_rbac::RbacEngine::from_yaml(yaml)
                .map_err(|err| PyValueError::new_err(format!("RBAC YAML parse error: {err}")))?;
            Ok(CompiledPolicyEngine::Rbac(engine))
        }
        PolicyFormat::Odrl => {
            let engine = typesec_odrl::OdrlEngine::from_yaml(yaml)
                .map_err(|err| PyValueError::new_err(format!("ODRL YAML parse error: {err}")))?;
            Ok(CompiledPolicyEngine::Odrl(engine))
        }
        PolicyFormat::Graph => {
            let engine = typesec_rbac::GraphPolicyEngine::from_yaml(yaml).map_err(|err| {
                PyValueError::new_err(format!("graph policy YAML parse error: {err}"))
            })?;
            Ok(CompiledPolicyEngine::Graph(engine))
        }
    }
}

enum CompiledPolicyEngine {
    Rbac(typesec_rbac::RbacEngine),
    Odrl(typesec_odrl::OdrlEngine),
    Graph(typesec_rbac::GraphPolicyEngine),
}

impl CompiledPolicyEngine {
    fn check(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        purpose: Option<&str>,
    ) -> PolicyResult {
        match self {
            Self::Rbac(engine) => engine.check(subject, action, resource),
            Self::Odrl(engine) => {
                let ctx = request_context(purpose);
                PolicyEngine::check_with_context(engine, subject, action, resource, &ctx)
            }
            Self::Graph(engine) => engine.check(subject, action, resource),
        }
    }
}

fn request_context(purpose: Option<&str>) -> RequestContext {
    purpose.map_or_else(RequestContext::default, |purpose| {
        RequestContext::default().with_purpose(purpose.to_string())
    })
}

fn check_policy(
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

fn decision_from_result(
    subject: &str,
    action: &str,
    resource: &str,
    result: PolicyResult,
) -> Decision {
    match result {
        PolicyResult::Allow => Decision {
            allowed: true,
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            reason: None,
        },
        PolicyResult::Deny(reason) => Decision {
            allowed: false,
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            reason: Some(reason),
        },
        PolicyResult::Delegate(reason) => Decision {
            allowed: false,
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            reason: Some(format!(
                "policy delegated to {}: {}",
                reason.engine, reason.reason
            )),
        },
        _ => Decision {
            allowed: false,
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            reason: Some("unknown policy result".to_string()),
        },
    }
}

#[pymodule]
fn typesec_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Decision>()?;
    m.add_class::<TypesecGate>()?;
    m.add_function(wrap_pyfunction!(check, m)?)?;
    m.add_function(wrap_pyfunction!(validate, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RBAC: &str = include_str!("../../../policies/rbac-example.yaml");
    const ODRL: &str = include_str!("../../../policies/odrl-example.yaml");
    const GRAPH: &str = include_str!("../../../policies/graph-corporate-example.yaml");

    #[test]
    fn typesec_gate_rbac_allows_and_denies() {
        let gate = TypesecGate::new(RBAC.to_string(), Some("rbac")).expect("valid rbac");

        let allowed = gate
            .check("agent:data-pipeline", "read", "reports/q1", None)
            .expect("check ok");
        assert!(allowed.allowed);

        let denied = gate
            .check("agent:data-pipeline", "write", "reports/q1", None)
            .expect("check ok");
        assert!(!denied.allowed);
        assert!(denied.reason.is_some());

        let unknown = gate
            .check("agent:ghost", "read", "reports/q1", None)
            .expect("check ok");
        assert!(!unknown.allowed);
    }

    #[test]
    fn typesec_gate_odrl_uses_per_call_purpose() {
        let gate = TypesecGate::new(ODRL.to_string(), Some("odrl")).expect("valid odrl");

        let allowed = gate
            .check(
                "agent:summarizer",
                "read",
                "customer-data",
                Some("analytics"),
            )
            .expect("check ok");
        assert!(allowed.allowed);

        let delegated = gate
            .check("agent:summarizer", "read", "customer-data", None)
            .expect("check ok");
        assert!(!delegated.allowed);
        assert!(
            delegated
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("delegated"))
        );
    }

    #[test]
    fn typesec_gate_graph_allows_basic_policy_path() {
        let gate = TypesecGate::new(GRAPH.to_string(), Some("graph")).expect("valid graph");

        let allowed = gate
            .check("agent:executive-chief", "write", "company/strategy", None)
            .expect("check ok");
        assert!(allowed.allowed);
    }

    #[test]
    fn validate_rejects_malformed_yaml() {
        assert!(validate("roles: [", Some("rbac")).is_err());
    }

    #[test]
    fn free_check_returns_decision() {
        let decision = check(
            RBAC,
            "agent:data-pipeline",
            "read",
            "reports/q1",
            Some("rbac"),
            None,
        )
        .expect("check ok");

        assert!(decision.allowed);
    }

    #[test]
    fn require_raises_permission_error_on_deny() {
        let gate = TypesecGate::new(RBAC.to_string(), Some("rbac")).expect("valid rbac");
        let err = gate
            .require("agent:data-pipeline", "write", "reports/q1", None)
            .expect_err("deny should raise");

        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            assert!(err.is_instance_of::<PyPermissionError>(py));
        });
    }
}
