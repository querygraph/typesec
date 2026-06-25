//! Compiled policy engine wrapper over the RBAC/ODRL/graph backends.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult, RequestContext},
};

use crate::format::PolicyFormat;

pub(crate) fn compile_policy(yaml: &str, format: PolicyFormat) -> PyResult<CompiledPolicyEngine> {
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

pub(crate) enum CompiledPolicyEngine {
    Rbac(typesec_rbac::RbacEngine),
    Odrl(typesec_odrl::OdrlEngine),
    Graph(typesec_rbac::GraphPolicyEngine),
}

impl CompiledPolicyEngine {
    pub(crate) fn check(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        purpose: Option<&str>,
    ) -> PolicyResult {
        let subject = SubjectId::from(subject);
        let resource = ResourceId::from(resource);
        match self {
            Self::Rbac(engine) => engine.check(&subject, action, &resource),
            Self::Odrl(engine) => {
                let ctx = request_context(purpose);
                PolicyEngine::check_with_context(engine, &subject, action, &resource, &ctx)
            }
            Self::Graph(engine) => engine.check(&subject, action, &resource),
        }
    }
}

fn request_context(purpose: Option<&str>) -> RequestContext {
    purpose.map_or_else(RequestContext::default, |purpose| {
        RequestContext::default().with_purpose(purpose.to_string())
    })
}
