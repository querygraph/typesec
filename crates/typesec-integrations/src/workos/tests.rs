use super::*;
use crate::http::StaticHttpClient;
use serde_json::json;

fn check(engine: &WorkOsFgaEngine, subject: &str, action: &str, resource: &str) -> PolicyResult {
    engine.check(
        &SubjectId::from(subject),
        action,
        &ResourceId::from(resource),
    )
}

#[test]
fn parses_resource_ids_for_workos() {
    let parsed = WorkOsResource::parse("project/proj_123").expect("parse");
    assert_eq!(parsed.resource_type_slug, "project");
    assert_eq!(parsed.resource_external_id, "proj_123");
}

#[test]
fn allows_when_workos_authorizes() {
    let url = "https://api.workos.test/authorization/organization_memberships/om_1/check";
    let http = StaticHttpClient::new().with_response(url, json!({ "authorized": true }));
    let engine = WorkOsFgaEngine::with_http("sk_test", "https://api.workos.test", Arc::new(http));

    assert_eq!(
        check(&engine, "om_1", "edit", "project/proj_123"),
        PolicyResult::Allow
    );
}

#[test]
fn denies_when_workos_denies() {
    let url = "https://api.workos.test/authorization/organization_memberships/om_1/check";
    let http = StaticHttpClient::new().with_response(url, json!({ "authorized": false }));
    let engine = WorkOsFgaEngine::with_http("sk_test", "https://api.workos.test", Arc::new(http));

    assert!(matches!(
        check(&engine, "om_1", "edit", "project/proj_123"),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn delegates_on_unparseable_resource() {
    // No `type/id` shape — WorkOS can't be asked, so the engine abstains rather
    // than guessing an answer.
    let http = StaticHttpClient::new();
    let engine = WorkOsFgaEngine::with_http("sk_test", "https://api.workos.test", Arc::new(http));

    assert!(matches!(
        check(&engine, "om_1", "edit", "badresource"),
        PolicyResult::Delegate(_)
    ));
}

#[test]
fn denies_on_transport_error() {
    // No response registered for the URL → the HTTP double errors → Deny.
    let http = StaticHttpClient::new();
    let engine = WorkOsFgaEngine::with_http("sk_test", "https://api.workos.test", Arc::new(http));

    assert!(matches!(
        check(&engine, "om_1", "edit", "project/proj_123"),
        PolicyResult::Deny(reason) if reason.to_lowercase().contains("fail")
    ));
}

#[test]
fn denies_on_parse_error() {
    // A 200 whose body lacks the expected `authorized` field → parse error → Deny.
    let url = "https://api.workos.test/authorization/organization_memberships/om_1/check";
    let http = StaticHttpClient::new().with_response(url, json!({ "unexpected": true }));
    let engine = WorkOsFgaEngine::with_http("sk_test", "https://api.workos.test", Arc::new(http));

    assert!(matches!(
        check(&engine, "om_1", "edit", "project/proj_123"),
        PolicyResult::Deny(_)
    ));
}
