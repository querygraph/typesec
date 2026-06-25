use super::*;
use std::sync::Arc;
use typesec_core::{
    CanExecute, CanRead, ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult},
    resource::GenericResource,
    typestate::Credentials,
};

struct AllowAll;
impl PolicyEngine for AllowAll {
    fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
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
