//! Rust-backed Python bindings for Typesec policy decisions.

use pyo3::exceptions::{PyPermissionError, PyValueError};
use pyo3::prelude::*;

mod decision;
mod engine;
mod format;

use decision::{Decision, check_policy, decision_from_result};
use engine::{CompiledPolicyEngine, compile_policy};
use format::PolicyFormat;

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
    use pyo3::types::{PyAny, PyModule};

    const RBAC: &str = include_str!("../../../policies/rbac-example.yaml");
    const ODRL: &str = include_str!("../../../policies/odrl-example.yaml");
    const GRAPH: &str = include_str!("../../../policies/graph-corporate-example.yaml");

    #[test]
    fn typesec_gate_rbac_allows_and_denies() -> PyResult<()> {
        with_module(|module| {
            let gate = module.getattr("TypesecGate")?.call1((RBAC, "rbac"))?;

            let allowed =
                gate.call_method1("check", ("agent:data-pipeline", "read", "reports/q1"))?;
            assert!(decision_allowed(&allowed)?);

            let denied =
                gate.call_method1("check", ("agent:data-pipeline", "write", "reports/q1"))?;
            assert!(!decision_allowed(&denied)?);
            assert!(decision_reason(&denied)?.is_some());

            let unknown = gate.call_method1("check", ("agent:ghost", "read", "reports/q1"))?;
            assert!(!decision_allowed(&unknown)?);

            Ok(())
        })
    }

    #[test]
    fn typesec_gate_odrl_uses_per_call_purpose() -> PyResult<()> {
        with_module(|module| {
            let gate = module.getattr("TypesecGate")?.call1((ODRL, "odrl"))?;

            let allowed = gate.call_method1(
                "check",
                ("agent:summarizer", "read", "customer-data", "analytics"),
            )?;
            assert!(decision_allowed(&allowed)?);

            let delegated =
                gate.call_method1("check", ("agent:summarizer", "read", "customer-data"))?;
            assert!(!decision_allowed(&delegated)?);
            let reason = decision_reason(&delegated)?;
            assert!(
                reason.as_deref().is_some_and(|r| r.contains("delegated")),
                "expected delegated reason, got {reason:?}"
            );

            Ok(())
        })
    }

    #[test]
    fn typesec_gate_graph_allows_basic_policy_path() -> PyResult<()> {
        with_module(|module| {
            let gate = module.getattr("TypesecGate")?.call1((GRAPH, "graph"))?;

            let allowed = gate.call_method1(
                "check",
                ("agent:executive-chief", "write", "company/strategy"),
            )?;
            assert!(decision_allowed(&allowed)?);

            Ok(())
        })
    }

    #[test]
    fn validate_rejects_malformed_yaml() -> PyResult<()> {
        with_module(|module| {
            let err = module
                .getattr("validate")?
                .call1(("roles: [", "rbac"))
                .expect_err("malformed YAML should fail");
            assert!(err.is_instance_of::<PyValueError>(module.py()));
            Ok(())
        })
    }

    #[test]
    fn free_check_returns_decision() -> PyResult<()> {
        with_module(|module| {
            let decision = module.getattr("check")?.call1((
                RBAC,
                "agent:data-pipeline",
                "read",
                "reports/q1",
                "rbac",
            ))?;

            assert!(decision_allowed(&decision)?);

            Ok(())
        })
    }

    #[test]
    fn require_raises_permission_error_on_deny() -> PyResult<()> {
        with_module(|module| {
            let gate = module.getattr("TypesecGate")?.call1((RBAC, "rbac"))?;
            let err = gate
                .call_method1("require", ("agent:data-pipeline", "write", "reports/q1"))
                .expect_err("deny should raise");

            assert!(err.is_instance_of::<PyPermissionError>(module.py()));

            Ok(())
        })
    }

    fn with_module(test: impl FnOnce(&Bound<'_, PyModule>) -> PyResult<()>) -> PyResult<()> {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new(py, "typesec_native")?;
            typesec_native(&module)?;
            test(&module)
        })
    }

    fn decision_allowed(decision: &Bound<'_, PyAny>) -> PyResult<bool> {
        decision.getattr("allowed")?.extract()
    }

    fn decision_reason(decision: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
        decision.getattr("reason")?.extract()
    }
}
