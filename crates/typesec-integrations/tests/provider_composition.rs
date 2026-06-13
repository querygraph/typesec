use std::sync::Arc;

use serde_json::json;
use typesec_core::{
    CanExecute, CanWrite, Capability, CombineStrategy, PolicyEngine, PolicyEngineBuilder,
    PolicyResult, ResourceId, SubjectId, mint_capability, resource::GenericResource,
};
use typesec_integrations::{
    ArcadeToolAuthEngine, JwtClaimsEngine, WorkOsFgaEngine,
    http::{RecordingHttpClient, StaticHttpClient},
};

fn check(engine: &dyn PolicyEngine, subject: &str, action: &str, resource: &str) -> PolicyResult {
    engine.check(
        &SubjectId::from(subject),
        action,
        &ResourceId::from(resource),
    )
}

#[test]
fn workos_engine_posts_expected_authorization_check() {
    let url = "https://api.workos.test/authorization/organization_memberships/om_123/check";
    let http = RecordingHttpClient::new().with_response(url, json!({ "authorized": true }));
    let captured = http.clone();
    let engine = WorkOsFgaEngine::with_http("sk_test", "https://api.workos.test", Arc::new(http));

    assert_eq!(
        check(&engine, "om_123", "edit", "project/proj_123"),
        PolicyResult::Allow
    );

    let requests = captured.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].url, url);
    assert_eq!(
        requests[0].body,
        Some(json!({
            "permission_slug": "project:edit",
            "resource_type_slug": "project",
            "resource_external_id": "proj_123"
        }))
    );
}

#[test]
fn arcade_engine_posts_expected_tool_authorization_check() {
    let url = "https://api.arcade.test/v1/tools/authorize";
    let http = RecordingHttpClient::new().with_response(url, json!({ "status": "completed" }));
    let captured = http.clone();
    let engine =
        ArcadeToolAuthEngine::with_http("arc_test", "https://api.arcade.test", Arc::new(http))
            .with_tool_mapping("gmail/list", "Gmail.ListEmails");

    assert_eq!(
        check(&engine, "user@example.com", "execute", "gmail/list"),
        PolicyResult::Allow
    );

    let requests = captured.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].url, url);
    assert_eq!(
        requests[0].body,
        Some(json!({
            "tool_name": "Gmail.ListEmails",
            "user_id": "user@example.com"
        }))
    );
}

#[test]
fn jwt_claims_delegate_to_workos_before_minting_capability() {
    let url = "https://api.workos.test/authorization/organization_memberships/om_123/check";
    let workos_http = StaticHttpClient::new().with_response(url, json!({ "authorized": true }));
    let jwt = Arc::new(JwtClaimsEngine::from_permissions(
        "om_123",
        ["org:view".to_string()],
    ));
    let workos = Arc::new(WorkOsFgaEngine::with_http(
        "sk_test",
        "https://api.workos.test",
        Arc::new(workos_http),
    ));
    let engine = PolicyEngineBuilder::new()
        .add_engine(jwt)
        .add_engine(workos)
        .strategy(CombineStrategy::PriorityOrder)
        .build();

    let project = GenericResource::new("project/proj_123", "project");
    let cap = mint_capability::<CanWrite, _>(&engine, "om_123", &project)
        .expect("WorkOS FGA should allow project write");

    assert_eq!(cap.subject(), "om_123");
    assert_eq!(cap.resource_id(), "project/proj_123");
}

#[test]
fn arcade_authorization_can_mint_execute_capability() {
    let arcade_http = StaticHttpClient::new().with_response(
        "https://api.arcade.test/v1/tools/authorize",
        json!({ "status": "completed" }),
    );
    let engine = ArcadeToolAuthEngine::with_http(
        "arc_test",
        "https://api.arcade.test",
        Arc::new(arcade_http),
    )
    .with_tool_mapping("gmail/list", "Gmail.ListEmails");

    let tool_resource = GenericResource::new("gmail/list", "tool");
    let cap = mint_capability::<CanExecute, _>(&engine, "user@example.com", &tool_resource)
        .expect("completed Arcade authorization should mint execute cap");

    assert_eq!(
        Capability::<CanExecute, GenericResource>::permission_name(),
        "execute"
    );
    assert_eq!(cap.resource_id(), "gmail/list");
}
