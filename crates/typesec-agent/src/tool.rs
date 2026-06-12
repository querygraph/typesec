//! Capability-bound tool wrappers for agent and MCP-style tool execution.

use std::marker::PhantomData;
use std::{future::Future, pin::Pin};

use typesec_core::{Capability, Permission, Resource, typestate::Authenticated};

use crate::{SecureAgent, executor::TaskError};

/// Boxed future returned by protected tool handlers.
pub type ToolFuture<'a> = Pin<Box<dyn Future<Output = Result<(), TaskError>> + Send + 'a>>;

/// Metadata describing the authorization boundary for a protected tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSpec {
    /// Tool name exposed to an agent or MCP client.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Permission required to invoke this tool.
    pub required_permission: &'static str,
    /// Resource identifier the permission applies to.
    pub resource_id: String,
}

/// A tool that cannot run unless the caller supplies a matching capability.
pub struct ProtectedTool<P, R, F>
where
    P: Permission,
    R: Resource,
{
    spec: ToolSpec,
    resource: R,
    action: F,
    _permission: PhantomData<fn() -> P>,
}

impl<P, R, F> ProtectedTool<P, R, F>
where
    P: Permission,
    R: Resource,
{
    /// Create a new protected tool.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        resource: R,
        action: F,
    ) -> Self {
        let resource_id = resource.resource_id().to_string();
        Self {
            spec: ToolSpec {
                name: name.into(),
                description: description.into(),
                required_permission: P::name(),
                resource_id,
            },
            resource,
            action,
            _permission: PhantomData,
        }
    }

    /// Return this tool's authorization metadata.
    pub fn spec(&self) -> &ToolSpec {
        &self.spec
    }
}

impl<P, R, F> ProtectedTool<P, R, F>
where
    P: Permission,
    R: Resource,
    F: for<'a> Fn(&'a R) -> ToolFuture<'a>,
{
    /// Invoke the tool with a typed capability.
    pub async fn invoke(
        &self,
        agent: &SecureAgent<Authenticated>,
        cap: &Capability<P, R>,
    ) -> Result<(), TaskError> {
        tracing::info!(
            subject = %agent.subject(),
            permission = %Capability::<P, R>::permission_name(),
            resource = %cap.resource_id(),
            tool = %self.spec.name,
            "invoking protected tool"
        );
        (self.action)(&self.resource).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use typesec_core::{
        CanExecute,
        policy::{PolicyEngine, PolicyResult},
        resource::GenericResource,
        typestate::Credentials,
    };

    struct AllowAll;
    impl PolicyEngine for AllowAll {
        fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
            PolicyResult::Allow
        }
    }

    fn no_op_tool(_resource: &GenericResource) -> ToolFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    #[tokio::test]
    async fn protected_tool_invokes_with_capability() {
        let agent = SecureAgent::new(Arc::new(AllowAll))
            .authenticate_unverified(Credentials::new("agent:test", "tok"))
            .expect("auth ok");
        let resource = GenericResource::new("Gmail.ListEmails", "tool");
        let cap: Capability<CanExecute, GenericResource> =
            agent.request_capability(&resource).await.expect("cap ok");
        let tool = ProtectedTool::<CanExecute, _, _>::new(
            "gmail.list",
            "List email messages",
            resource,
            no_op_tool,
        );

        assert_eq!(tool.spec().required_permission, "execute");
        tool.invoke(&agent, &cap).await.expect("tool should run");
    }
}
