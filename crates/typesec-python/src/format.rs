//! Policy-format detection.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[derive(Clone, Copy)]
pub(crate) enum PolicyFormat {
    Rbac,
    Odrl,
    Graph,
}

impl PolicyFormat {
    pub(crate) fn detect(explicit: Option<&str>, yaml: &str) -> PyResult<Self> {
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
