use super::*;
use std::sync::Arc;
use typesec_core::{
    ResourceId, SubjectId, permissions::CanRead, policy::PolicyResult, resource::GenericResource,
};

struct AllowAll;
impl PolicyEngine for AllowAll {
    fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
        PolicyResult::Allow
    }
}

struct DenyAll;
impl PolicyEngine for DenyAll {
    fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
        PolicyResult::Deny("DenyAll".into())
    }
}

#[tokio::test]
async fn full_flow_allow() {
    let agent = SecureAgent::new(Arc::new(AllowAll));
    let agent = agent
        .authenticate_unverified(Credentials::new("agent:test", "tok"))
        .expect("auth ok");
    let resource = GenericResource::new("reports/q1", "report");
    let cap: Capability<CanRead, GenericResource> = agent
        .request_capability(&resource)
        .await
        .expect("should get cap");
    assert_eq!(cap.subject(), "agent:test");
}

#[tokio::test]
async fn denied_request_returns_error() {
    let agent = SecureAgent::new(Arc::new(DenyAll));
    let agent = agent
        .authenticate_unverified(Credentials::new("agent:test", "tok"))
        .expect("auth ok");
    let resource = GenericResource::new("reports/q1", "report");
    let result: Result<Capability<CanRead, GenericResource>, _> =
        agent.request_capability(&resource).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn execute_requires_capability() {
    let agent = SecureAgent::new(Arc::new(AllowAll));
    let agent = agent
        .authenticate_unverified(Credentials::new("agent:test", "tok"))
        .expect("auth ok");
    let resource = GenericResource::new("reports/q1", "report");
    let cap: Capability<CanRead, GenericResource> =
        agent.request_capability(&resource).await.expect("cap ok");

    let executed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let executed_clone = executed.clone();

    agent
        .execute(&cap, &resource, |_r| {
            let flag = executed_clone.clone();
            Box::pin(async move {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
        })
        .await
        .expect("execute ok");

    assert!(executed.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn execute_rejects_capability_for_other_resource() {
    let agent = SecureAgent::new(Arc::new(AllowAll));
    let agent = agent
        .authenticate_unverified(Credentials::new("agent:test", "tok"))
        .expect("auth ok");
    let q1 = GenericResource::new("reports/q1", "report");
    let q2 = GenericResource::new("reports/q2", "report");
    let cap: Capability<CanRead, GenericResource> =
        agent.request_capability(&q1).await.expect("cap ok");

    // Same resource type, different instance — must be rejected.
    let result = agent
        .execute(&cap, &q2, |_r| Box::pin(async { Ok(()) }))
        .await;
    assert!(matches!(
        result,
        Err(crate::executor::TaskError::CapabilityMismatch(_))
    ));
}

#[tokio::test]
async fn execute_rejects_capability_for_other_subject() {
    let resource = GenericResource::new("reports/q1", "report");

    // Mint a capability as agent:other...
    let other = SecureAgent::new(Arc::new(AllowAll))
        .authenticate_unverified(Credentials::new("agent:other", "tok"))
        .expect("auth ok");
    let cap: Capability<CanRead, GenericResource> =
        other.request_capability(&resource).await.expect("cap ok");

    // ...and try to use it as agent:test.
    let agent = SecureAgent::new(Arc::new(AllowAll))
        .authenticate_unverified(Credentials::new("agent:test", "tok"))
        .expect("auth ok");
    let result = agent
        .execute(&cap, &resource, |_r| Box::pin(async { Ok(()) }))
        .await;
    assert!(matches!(
        result,
        Err(crate::executor::TaskError::CapabilityMismatch(_))
    ));
}
