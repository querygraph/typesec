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

#[test]
fn delegates_on_unhandled_action() {
    let http = StaticHttpClient::new();
    let engine =
        ArcadeToolAuthEngine::with_http("arc_test", "https://api.arcade.test", Arc::new(http))
            .with_tool_mapping("gmail/list", "Gmail.ListEmails");

    assert!(matches!(
        check(&engine, "user@example.com", "delete", "gmail/list"),
        PolicyResult::Delegate(_)
    ));
}

#[test]
fn delegates_on_unmapped_resource() {
    let http = StaticHttpClient::new();
    let engine =
        ArcadeToolAuthEngine::with_http("arc_test", "https://api.arcade.test", Arc::new(http));

    assert!(matches!(
        check(&engine, "user@example.com", "execute", "unknown/tool"),
        PolicyResult::Delegate(_)
    ));
}

#[test]
fn denies_on_transport_error() {
    // Mapped tool but no registered response → the HTTP double errors → Deny.
    let http = StaticHttpClient::new();
    let engine =
        ArcadeToolAuthEngine::with_http("arc_test", "https://api.arcade.test", Arc::new(http))
            .with_tool_mapping("gmail/list", "Gmail.ListEmails");

    assert!(matches!(
        check(&engine, "user@example.com", "execute", "gmail/list"),
        PolicyResult::Deny(reason) if reason.to_lowercase().contains("fail")
    ));
}

#[test]
fn denies_on_parse_error() {
    // A 200 whose body lacks the expected `status` field → parse error → Deny.
    let http = StaticHttpClient::new().with_response(
        "https://api.arcade.test/v1/tools/authorize",
        json!({ "unexpected": true }),
    );
    let engine =
        ArcadeToolAuthEngine::with_http("arc_test", "https://api.arcade.test", Arc::new(http))
            .with_tool_mapping("gmail/list", "Gmail.ListEmails");

    assert!(matches!(
        check(&engine, "user@example.com", "execute", "gmail/list"),
        PolicyResult::Deny(reason) if reason.contains("parse error")
    ));
}
