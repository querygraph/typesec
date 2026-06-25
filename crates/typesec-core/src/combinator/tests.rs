use super::*;
use crate::policy::PolicyResult;
use std::sync::Arc;

fn subject() -> SubjectId {
    SubjectId::from("s")
}

fn resource() -> ResourceId {
    ResourceId::from("r")
}

fn allow() -> Arc<dyn PolicyEngine> {
    struct A;
    impl PolicyEngine for A {
        fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
            PolicyResult::Allow
        }
    }
    Arc::new(A)
}

fn deny(msg: &'static str) -> Arc<dyn PolicyEngine> {
    struct D(&'static str);
    impl PolicyEngine for D {
        fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
            PolicyResult::Deny(self.0.into())
        }
    }
    Arc::new(D(msg))
}

fn delegate() -> Arc<dyn PolicyEngine> {
    struct G;
    impl PolicyEngine for G {
        fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
            PolicyResult::delegate("test", "abstain")
        }
    }
    Arc::new(G)
}

// ── PriorityOrder ─────────────────────────────────────────────────────────

#[test]
fn priority_first_allow_wins() {
    let e = PolicyEngineBuilder::new()
        .add_engine(allow())
        .add_engine(deny("second"))
        .strategy(CombineStrategy::PriorityOrder)
        .build();
    assert_eq!(e.check(&subject(), "a", &resource()), PolicyResult::Allow);
}

#[test]
fn priority_skips_delegate() {
    let e = PolicyEngineBuilder::new()
        .add_engine(delegate())
        .add_engine(allow())
        .strategy(CombineStrategy::PriorityOrder)
        .build();
    assert_eq!(e.check(&subject(), "a", &resource()), PolicyResult::Allow);
}

#[test]
fn priority_all_delegate_returns_delegate() {
    let e = PolicyEngineBuilder::new()
        .add_engine(delegate())
        .add_engine(delegate())
        .strategy(CombineStrategy::PriorityOrder)
        .build();
    assert!(matches!(
        e.check(&subject(), "a", &resource()),
        PolicyResult::Delegate(_)
    ));
}

// ── AllowIfAll ────────────────────────────────────────────────────────────

#[test]
fn allow_if_all_both_allow() {
    let e = PolicyEngineBuilder::new()
        .add_engine(allow())
        .add_engine(allow())
        .strategy(CombineStrategy::AllowIfAll)
        .build();
    assert_eq!(e.check(&subject(), "a", &resource()), PolicyResult::Allow);
}

#[test]
fn allow_if_all_one_deny_overrides() {
    let e = PolicyEngineBuilder::new()
        .add_engine(allow())
        .add_engine(deny("no"))
        .strategy(CombineStrategy::AllowIfAll)
        .build();
    assert!(matches!(
        e.check(&subject(), "a", &resource()),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn allow_if_all_collects_all_denial_reasons() {
    let e = PolicyEngineBuilder::new()
        .add_engine(deny("first"))
        .add_engine(deny("second"))
        .strategy(CombineStrategy::AllowIfAll)
        .build();
    let result = e.check(&subject(), "a", &resource());

    assert!(
        matches!(result, PolicyResult::Deny(reason) if reason.contains("first") && reason.contains("second"))
    );
}

#[test]
fn allow_if_all_delegate_abstains() {
    // Two allows and one delegate → Allow (delegate abstained)
    let e = PolicyEngineBuilder::new()
        .add_engine(allow())
        .add_engine(delegate())
        .add_engine(allow())
        .strategy(CombineStrategy::AllowIfAll)
        .build();
    assert_eq!(e.check(&subject(), "a", &resource()), PolicyResult::Allow);
}

// ── AllowIfAny ────────────────────────────────────────────────────────────

#[test]
fn allow_if_any_single_allow_wins() {
    let e = PolicyEngineBuilder::new()
        .add_engine(deny("first"))
        .add_engine(allow())
        .strategy(CombineStrategy::AllowIfAny)
        .build();
    assert_eq!(e.check(&subject(), "a", &resource()), PolicyResult::Allow);
}

#[test]
fn allow_if_any_all_deny_returns_deny() {
    let e = PolicyEngineBuilder::new()
        .add_engine(deny("one"))
        .add_engine(deny("two"))
        .strategy(CombineStrategy::AllowIfAny)
        .build();
    assert!(matches!(
        e.check(&subject(), "a", &resource()),
        PolicyResult::Deny(_)
    ));
}

// ── DenyOverrides ─────────────────────────────────────────────────────────

#[test]
fn deny_overrides_deny_beats_allow() {
    let e = PolicyEngineBuilder::new()
        .add_engine(allow())
        .add_engine(deny("prohibited"))
        .strategy(CombineStrategy::DenyOverrides)
        .build();
    assert!(matches!(
        e.check(&subject(), "a", &resource()),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn deny_overrides_no_deny_allows() {
    let e = PolicyEngineBuilder::new()
        .add_engine(allow())
        .add_engine(delegate())
        .strategy(CombineStrategy::DenyOverrides)
        .build();
    assert_eq!(e.check(&subject(), "a", &resource()), PolicyResult::Allow);
}

#[test]
fn deny_overrides_all_delegate_returns_delegate() {
    let e = PolicyEngineBuilder::new()
        .add_engine(delegate())
        .strategy(CombineStrategy::DenyOverrides)
        .build();
    assert!(matches!(
        e.check(&subject(), "a", &resource()),
        PolicyResult::Delegate(_)
    ));
}
