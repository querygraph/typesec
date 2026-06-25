//! Policy-engine combinator strategies (deny-overrides, allow-if-any/all,
//! priority-order) and request-context propagation through them.

mod common;

use std::sync::Arc;

use typesec_core::{
    PolicyResult, RequestContext,
    combinator::{CombineStrategy, PolicyEngineBuilder},
};
use typesec_odrl::OdrlEngine;
use typesec_rbac::RbacEngine;

use common::{
    ODRL_ALLOW_SHARED_READ, ODRL_PERMIT_READ, ODRL_PROHIBIT_READ, ODRL_PROHIBIT_TRAINING_READ,
    RBAC_ALLOW_READ, RBAC_NO_RULES, check_engine, check_engine_with_context,
};

/// RBAC says Allow; ODRL has a Prohibition → DenyOverrides yields Deny.
#[tokio::test]
async fn combinator_deny_overrides() {
    let rbac: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(RbacEngine::from_yaml(RBAC_ALLOW_READ).expect("rbac"));
    let odrl: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(OdrlEngine::from_yaml(ODRL_PROHIBIT_READ).expect("odrl"));

    let composed = PolicyEngineBuilder::new()
        .add_engine(rbac)
        .add_engine(odrl)
        .strategy(CombineStrategy::DenyOverrides)
        .build();

    // RBAC → Allow; ODRL → Deny (prohibition); DenyOverrides → Deny
    let result = check_engine(&composed, "agent:combinator", "read", "shared/data");
    assert!(
        matches!(result, PolicyResult::Deny(_)),
        "DenyOverrides must yield Deny when any engine prohibits: {result:?}"
    );
}

/// RBAC denies (no rules); ODRL permits → AllowIfAny yields Allow.
#[tokio::test]
async fn combinator_allow_if_any() {
    let rbac: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(RbacEngine::from_yaml(RBAC_NO_RULES).expect("rbac"));
    let odrl: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(OdrlEngine::from_yaml(ODRL_PERMIT_READ).expect("odrl"));

    let composed = PolicyEngineBuilder::new()
        .add_engine(rbac)
        .add_engine(odrl)
        .strategy(CombineStrategy::AllowIfAny)
        .build();

    // RBAC → Deny (no assignment); ODRL → Allow; AllowIfAny → Allow
    let result = check_engine(&composed, "agent:odrl-only", "read", "private/data");
    assert_eq!(
        result,
        PolicyResult::Allow,
        "AllowIfAny must yield Allow when at least one engine permits: {result:?}"
    );
}

#[tokio::test]
async fn deny_overrides_preserves_odrl_request_context() {
    let rbac: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(RbacEngine::from_yaml(RBAC_ALLOW_READ).expect("rbac"));
    let odrl: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(OdrlEngine::from_yaml(ODRL_PROHIBIT_TRAINING_READ).expect("odrl"));
    let composed = PolicyEngineBuilder::new()
        .add_engine(rbac)
        .add_engine(odrl)
        .strategy(CombineStrategy::DenyOverrides)
        .build();

    let ctx = RequestContext::default().with_purpose("training");
    let result =
        check_engine_with_context(&composed, "agent:combinator", "read", "shared/data", &ctx);

    assert!(
        matches!(result, PolicyResult::Deny(_)),
        "ODRL purpose prohibition should override RBAC allow"
    );
}

#[tokio::test]
async fn priority_order_delegates_to_rbac_allow() {
    let odrl: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(OdrlEngine::from_yaml(ODRL_PERMIT_READ).expect("odrl"));
    let rbac: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(RbacEngine::from_yaml(RBAC_ALLOW_READ).expect("rbac"));
    let composed = PolicyEngineBuilder::new()
        .add_engine(odrl)
        .add_engine(rbac)
        .strategy(CombineStrategy::PriorityOrder)
        .build();

    let result = check_engine(&composed, "agent:combinator", "read", "shared/data");

    assert_eq!(result, PolicyResult::Allow);
}

#[tokio::test]
async fn allow_if_all_requires_both_engines_to_allow() {
    let rbac: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(RbacEngine::from_yaml(RBAC_ALLOW_READ).expect("rbac"));
    let odrl: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(OdrlEngine::from_yaml(ODRL_ALLOW_SHARED_READ).expect("odrl"));
    let both_allow = PolicyEngineBuilder::new()
        .add_engine(rbac)
        .add_engine(odrl)
        .strategy(CombineStrategy::AllowIfAll)
        .build();

    assert_eq!(
        check_engine(&both_allow, "agent:combinator", "read", "shared/data"),
        PolicyResult::Allow
    );

    let rbac_deny: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(RbacEngine::from_yaml(RBAC_NO_RULES).expect("rbac"));
    let odrl_allow: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(OdrlEngine::from_yaml(ODRL_PERMIT_READ).expect("odrl"));
    let one_denies = PolicyEngineBuilder::new()
        .add_engine(rbac_deny)
        .add_engine(odrl_allow)
        .strategy(CombineStrategy::AllowIfAll)
        .build();

    assert!(matches!(
        check_engine(&one_denies, "agent:odrl-only", "read", "private/data"),
        PolicyResult::Deny(_)
    ));
}
