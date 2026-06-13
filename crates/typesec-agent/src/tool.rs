//! Capability-bound tool wrappers for agent and MCP-style tool execution.

use std::any::Any;
use std::collections::HashMap;
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
        if cap.subject() != agent.subject() {
            return Err(TaskError::CapabilityMismatch(format!(
                "capability was minted for subject '{}', not '{}'",
                cap.subject(),
                agent.subject()
            )));
        }
        if cap.resource_id() != self.resource.resource_id() {
            return Err(TaskError::CapabilityMismatch(format!(
                "capability covers resource '{}', not '{}'",
                cap.resource_id(),
                self.resource.resource_id()
            )));
        }
        cap.ensure_active()?;

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

trait ErasedTool: Send + Sync {
    fn spec(&self) -> &ToolSpec;

    fn invoke_erased<'a>(
        &'a self,
        agent: &'a SecureAgent<Authenticated>,
        cap: &'a (dyn Any + Send + Sync),
    ) -> ToolFuture<'a>;
}

impl<P, R, F> ErasedTool for ProtectedTool<P, R, F>
where
    P: Permission + 'static,
    R: Resource + 'static,
    F: for<'a> Fn(&'a R) -> ToolFuture<'a> + Send + Sync + 'static,
{
    fn spec(&self) -> &ToolSpec {
        &self.spec
    }

    fn invoke_erased<'a>(
        &'a self,
        agent: &'a SecureAgent<Authenticated>,
        cap: &'a (dyn Any + Send + Sync),
    ) -> ToolFuture<'a> {
        let Some(cap) = cap.downcast_ref::<Capability<P, R>>() else {
            return Box::pin(async move {
                Err(TaskError::CapabilityMismatch(format!(
                    "tool '{}' requires Capability<{}, {}>",
                    self.spec.name,
                    P::name(),
                    R::resource_type()
                )))
            });
        };

        Box::pin(async move { self.invoke(agent, cap).await })
    }
}

/// Registry for named capability-protected tools.
#[derive(Default)]
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn ErasedTool>>,
}

impl ToolRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a protected tool by its exposed name.
    ///
    /// Registering another tool with the same name replaces the previous one.
    pub fn register<P, R, F>(&mut self, tool: ProtectedTool<P, R, F>)
    where
        P: Permission + 'static,
        R: Resource + 'static,
        F: for<'a> Fn(&'a R) -> ToolFuture<'a> + Send + Sync + 'static,
    {
        self.tools.insert(tool.spec.name.clone(), Box::new(tool));
    }

    /// Return metadata for every registered tool.
    pub fn list_specs(&self) -> Vec<ToolSpec> {
        self.tools
            .values()
            .map(|tool| tool.spec().clone())
            .collect()
    }

    /// Return metadata for one registered tool.
    pub fn spec(&self, name: &str) -> Option<&ToolSpec> {
        self.tools.get(name).map(|tool| tool.spec())
    }

    /// Invoke a named tool with an erased capability.
    pub async fn invoke(
        &self,
        name: &str,
        agent: &SecureAgent<Authenticated>,
        cap: &(dyn Any + Send + Sync),
    ) -> Result<(), TaskError> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| TaskError::UnknownTool(name.to_owned()))?;
        tool.invoke_erased(agent, cap).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use typesec_core::{
        CanExecute, CanRead,
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

    #[tokio::test]
    async fn protected_tool_rejects_capability_for_other_resource() {
        let agent = SecureAgent::new(Arc::new(AllowAll))
            .authenticate_unverified(Credentials::new("agent:test", "tok"))
            .expect("auth ok");
        let cap_resource = GenericResource::new("Gmail.ListEmails", "tool");
        let tool_resource = GenericResource::new("Gmail.DeleteEmail", "tool");
        let cap: Capability<CanExecute, GenericResource> = agent
            .request_capability(&cap_resource)
            .await
            .expect("cap ok");
        let tool = ProtectedTool::<CanExecute, _, _>::new(
            "gmail.delete",
            "Delete an email message",
            tool_resource,
            no_op_tool,
        );

        assert!(matches!(
            tool.invoke(&agent, &cap).await,
            Err(TaskError::CapabilityMismatch(reason)) if reason.contains("Gmail.ListEmails")
        ));
    }

    #[tokio::test]
    async fn registry_lists_and_invokes_registered_tools() {
        let agent = SecureAgent::new(Arc::new(AllowAll))
            .authenticate_unverified(Credentials::new("agent:test", "tok"))
            .expect("auth ok");
        let resource = GenericResource::new("Gmail.ListEmails", "tool");
        let cap: Capability<CanExecute, GenericResource> =
            agent.request_capability(&resource).await.expect("cap ok");
        let mut registry = ToolRegistry::new();
        registry.register(ProtectedTool::<CanExecute, _, _>::new(
            "gmail.list",
            "List email messages",
            resource,
            no_op_tool,
        ));

        let specs = registry.list_specs();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "gmail.list");
        assert_eq!(
            registry
                .spec("gmail.list")
                .expect("registered spec")
                .required_permission,
            "execute"
        );

        registry
            .invoke("gmail.list", &agent, &cap)
            .await
            .expect("registry invoke should run");
    }

    #[tokio::test]
    async fn registry_rejects_wrong_capability_type_and_unknown_tool() {
        let agent = SecureAgent::new(Arc::new(AllowAll))
            .authenticate_unverified(Credentials::new("agent:test", "tok"))
            .expect("auth ok");
        let resource = GenericResource::new("Gmail.ListEmails", "tool");
        let read_cap: Capability<CanRead, GenericResource> =
            agent.request_capability(&resource).await.expect("cap ok");
        let mut registry = ToolRegistry::new();
        registry.register(ProtectedTool::<CanExecute, _, _>::new(
            "gmail.list",
            "List email messages",
            resource,
            no_op_tool,
        ));

        assert!(matches!(
            registry.invoke("gmail.list", &agent, &read_cap).await,
            Err(TaskError::CapabilityMismatch(reason)) if reason.contains("Capability<execute")
        ));
        assert!(matches!(
            registry.invoke("missing", &agent, &read_cap).await,
            Err(TaskError::UnknownTool(name)) if name == "missing"
        ));
    }
}
