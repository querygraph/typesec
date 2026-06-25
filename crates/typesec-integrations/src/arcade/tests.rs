use super::*;
use crate::http::StaticHttpClient;
use serde_json::json;

fn check(
    engine: &ArcadeToolAuthEngine,
    subject: &str,
    action: &str,
    resource: &str,
) -> PolicyResult {
    engine.check(
        &SubjectId::from(subject),
        action,
        &ResourceId::from(resource),
    )
}

#[test]
fn allows_completed_authorization() {
    let http = StaticHttpClient::new().with_response(
        "https://api.arcade.test/v1/tools/authorize",
        json!({ "status": "completed" }),
    );
    let engine =
        ArcadeToolAuthEngine::with_http("arc_test", "https://api.arcade.test", Arc::new(http))
            .with_tool_mapping("gmail/list", "Gmail.ListEmails");

    assert_eq!(
        check(&engine, "user@example.com", "execute", "gmail/list"),
        PolicyResult::Allow
    );
}

#[test]
fn denies_pending_authorization_with_url() {
    let http = StaticHttpClient::new().with_response(
        "https://api.arcade.test/v1/tools/authorize",
        json!({ "status": "pending", "url": "https://authorize.example" }),
    );
    let engine =
        ArcadeToolAuthEngine::with_http("arc_test", "https://api.arcade.test", Arc::new(http))
            .with_tool_mapping("gmail/list", "Gmail.ListEmails");

    let result = check(&engine, "user@example.com", "execute", "gmail/list");
    assert!(matches!(result, PolicyResult::Deny(reason) if reason.contains("authorize")));
}
