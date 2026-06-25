
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
