use super::*;

#[test]
fn detect_format_prefers_explicit_flag() {
    let yaml = "roles:\n  - name: a";
    assert_eq!(
        detect_format(&Some("odrl".to_string()), yaml).as_deref(),
        Some("odrl"),
        "an explicit --format must win over body sniffing"
    );
}

#[test]
fn detect_format_sniffs_body_by_precedence() {
    assert_eq!(
        detect_format(&None, "graph_policy:\n  graph: {}").as_deref(),
        Some("graph")
    );
    assert_eq!(
        detect_format(&None, "roles:\n  - name: a").as_deref(),
        Some("rbac")
    );
    assert_eq!(
        detect_format(&None, "policies:\n  - uid: p").as_deref(),
        Some("odrl")
    );
    assert_eq!(detect_format(&None, "unrelated: true"), None);
}

#[test]
fn detect_format_graph_outranks_rbac_and_odrl() {
    // A graph document can also mention roles/policies; graph must still win.
    let yaml = "graph_policy:\n  graph: {}\nroles: []\npolicies: []";
    assert_eq!(detect_format(&None, yaml).as_deref(), Some("graph"));
}

#[test]
fn exit_codes_follow_the_verdict() {
    assert_eq!(code_for_result(&PolicyResult::Allow), 0);
    assert_eq!(code_for_result(&PolicyResult::Deny("no".into())), 1);
    assert_eq!(
        code_for_result(&PolicyResult::delegate("e", "abstain")),
        2
    );
}

#[test]
fn request_context_carries_purpose() {
    assert_eq!(request_context(Some("analytics")).purpose.as_deref(), Some("analytics"));
    assert_eq!(request_context(None).purpose, None);
}
