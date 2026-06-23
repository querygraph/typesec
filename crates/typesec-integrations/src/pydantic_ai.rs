//! Pydantic AI capability metadata for Typesec-protected tools.
//!
//! Pydantic AI v2 treats capabilities as composable bundles of tools,
//! instructions, settings, and hooks. This module keeps the Rust side
//! framework-neutral by producing the stable metadata a Python adapter needs to
//! construct a `pydantic_ai.capabilities.Capability` while preserving the
//! Typesec authorization boundary: every tool still names the permission and
//! resource that must be checked before invocation.

use serde::{Deserialize, Serialize};

/// Metadata for one Typesec-protected tool exposed through a Pydantic AI
/// capability bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PydanticAiToolCapability {
    /// Tool name exposed to the Pydantic AI agent.
    pub name: String,
    /// Tool description shown to the model.
    pub description: String,
    /// Typesec action or permission required before this tool may run.
    pub required_permission: String,
    /// Resource identifier the permission applies to.
    pub resource_id: String,
}

impl PydanticAiToolCapability {
    /// Create protected-tool metadata for a Pydantic AI capability bundle.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        required_permission: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            required_permission: required_permission.into(),
            resource_id: resource_id.into(),
        }
    }
}

/// A Pydantic AI capability bundle backed by Typesec policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PydanticAiCapability {
    /// Stable Pydantic AI capability id.
    pub id: String,
    /// Catalog description for the bundle.
    pub description: String,
    /// Instructions attached to the capability.
    pub instructions: String,
    /// Whether Pydantic AI should expose the capability through on-demand
    /// loading instead of eagerly sending every tool and instruction.
    pub defer_loading: bool,
    /// Tool metadata protected by this capability.
    pub tools: Vec<PydanticAiToolCapability>,
}

impl PydanticAiCapability {
    /// Create an eager Pydantic AI capability descriptor.
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        instructions: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            instructions: instructions.into(),
            defer_loading: false,
            tools: Vec::new(),
        }
    }

    /// Mark the capability as on-demand loadable.
    #[must_use]
    pub fn defer_loading(mut self, defer_loading: bool) -> Self {
        self.defer_loading = defer_loading;
        self
    }

    /// Add one Typesec-protected tool to this capability bundle.
    #[must_use]
    pub fn with_tool(mut self, tool: PydanticAiToolCapability) -> Self {
        self.tools.push(tool);
        self
    }

    /// Return a JSON representation suitable for a Python adapter to turn into
    /// `pydantic_ai.capabilities.Capability`.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_typesec_capability_bundle() {
        let capability = PydanticAiCapability::new(
            "typesec_reports",
            "Use for governed report access.",
            "Check Typesec policy before using protected report data.",
        )
        .defer_loading(true)
        .with_tool(PydanticAiToolCapability::new(
            "summarize_report",
            "Summarize a sensitive report.",
            "read_sensitive",
            "reports/q1",
        ));

        let json = capability.to_json().expect("serialize capability");
        assert!(json.contains("\"id\":\"typesec_reports\""));
        assert!(json.contains("\"defer_loading\":true"));
        assert!(json.contains("\"required_permission\":\"read_sensitive\""));
    }
}
