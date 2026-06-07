//! Rust-backed Python bindings for Typesec policy decisions.

use pyo3::exceptions::{PyPermissionError, PyValueError};
use pyo3::prelude::*;
use typesec_core::policy::{PolicyEngine, PolicyResult};

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
#[derive(Clone)]
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
    yaml: String,
    format: PolicyFormat,
}

#[pymethods]
impl TypesecGate {
    #[new]
    #[pyo3(signature = (policy_yaml, format = None))]
    fn new(policy_yaml: String, format: Option<&str>) -> PyResult<Self> {
        let format = PolicyFormat::detect(format, &policy_yaml)?;
        validate_policy(&policy_yaml, format)?;
        Ok(Self {
            yaml: policy_yaml,
            format,
        })
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
        check_policy(&self.yaml, self.format, subject, action, resource, purpose)
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
    validate_policy(policy_yaml, format)
}

fn validate_policy(yaml: &str, format: PolicyFormat) -> PyResult<()> {
    match format {
        PolicyFormat::Rbac => {
            let policy = typesec_rbac::RbacPolicy::from_yaml(yaml)
                .map_err(|err| PyValueError::new_err(format!("RBAC YAML parse error: {err}")))?;
            policy.validate().map_err(PyValueError::new_err)
        }
        PolicyFormat::Odrl => {
            typesec_odrl::model::OdrlDocument::from_yaml(yaml)
                .map_err(|err| PyValueError::new_err(format!("ODRL YAML parse error: {err}")))?;
            Ok(())
        }
        PolicyFormat::Graph => {
            let doc = typesec_rbac::graph_policy::GraphPolicyDocument::from_yaml(yaml).map_err(
                |err| PyValueError::new_err(format!("graph policy YAML parse error: {err}")),
            )?;
            doc.validate().map_err(PyValueError::new_err)
        }
    }
}

fn check_policy(
    yaml: &str,
    format: PolicyFormat,
    subject: &str,
    action: &str,
    resource: &str,
    purpose: Option<&str>,
) -> PyResult<Decision> {
    let result = match format {
        PolicyFormat::Rbac => {
            let engine = typesec_rbac::RbacEngine::from_yaml(yaml)
                .map_err(|err| PyValueError::new_err(format!("RBAC YAML parse error: {err}")))?;
            engine.check(subject, action, resource)
        }
        PolicyFormat::Odrl => {
            let base = typesec_odrl::OdrlEngine::from_yaml(yaml)
                .map_err(|err| PyValueError::new_err(format!("ODRL YAML parse error: {err}")))?;
            let engine = if let Some(purpose) = purpose {
                let ctx = typesec_odrl::constraint::ConstraintContext::default()
                    .with_purpose(purpose.to_string());
                base.with_context(ctx)
            } else {
                base
            };
            engine.check(subject, action, resource)
        }
        PolicyFormat::Graph => {
            let engine =
                typesec_rbac::GraphPolicyEngine::from_yaml(yaml).map_err(PyValueError::new_err)?;
            engine.check(subject, action, resource)
        }
    };

    Ok(match result {
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
        PolicyResult::Delegate(to) => Decision {
            allowed: false,
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            reason: Some(format!("policy delegated to {to}")),
        },
    })
}

#[pymodule]
fn typesec_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Decision>()?;
    m.add_class::<TypesecGate>()?;
    m.add_function(wrap_pyfunction!(check, m)?)?;
    m.add_function(wrap_pyfunction!(validate, m)?)?;
    Ok(())
}
