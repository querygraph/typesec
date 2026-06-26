use super::*;
use crate::permissions::{CanRead, CanWrite};
use std::time::Duration;

// A minimal test resource.
#[derive(Debug)]
struct TestResource;
impl Resource for TestResource {
    fn resource_id(&self) -> &str {
        "test://resource"
    }
    fn resource_type() -> &'static str {
        "TestResource"
    }
}

#[test]
fn capability_fields_are_correct() {
    let cap: Capability<CanRead, TestResource> =
        Capability::new_unchecked("agent:test", "test://resource");
    assert_eq!(cap.subject(), "agent:test");
    assert_eq!(cap.resource_id(), "test://resource");
    assert_eq!(
        Capability::<CanRead, TestResource>::permission_name(),
        "read"
    );
}

#[test]
fn read_and_write_caps_are_different_types() {
    // This test is really a compile-time check, but we can demonstrate
    // the Debug output differs.
    let read: Capability<CanRead, TestResource> =
        Capability::new_unchecked("agent:test", "test://resource");
    let write: Capability<CanWrite, TestResource> =
        Capability::new_unchecked("agent:test", "test://resource");
    assert!(format!("{read:?}").contains("read"));
    assert!(format!("{write:?}").contains("write"));
}

#[test]
fn capability_expires_after_default_ttl() {
    let issued_at = SystemTime::now()
        .checked_sub(DEFAULT_CAPABILITY_TTL + Duration::from_secs(1))
        .expect("time subtraction");
    let cap: Capability<CanRead, TestResource> =
        Capability::new_with_issued_at("agent:test", "test://resource", issued_at);

    assert!(cap.is_expired());
    assert!(matches!(
        cap.ensure_active(),
        Err(CapabilityUseError::Expired { .. })
    ));
}

#[test]
fn revocation_epoch_invalidates_minted_capability() {
    let epoch = RevocationEpoch::new();
    let cap: Capability<CanRead, TestResource> = Capability::new_minted(
        "agent:test",
        "test://resource",
        SystemTime::now(),
        DEFAULT_CAPABILITY_TTL,
        Some(epoch.clone()),
        None,
    );

    cap.ensure_active().expect("active before revocation");
    epoch.revoke_all();
    assert!(cap.is_revoked());
    assert!(matches!(
        cap.ensure_active(),
        Err(CapabilityUseError::Revoked { .. })
    ));
}

#[test]
fn capability_without_revocation_binding_is_never_revoked() {
    let cap: Capability<CanRead, TestResource> =
        Capability::new_unchecked("agent:test", "test://resource");
    assert!(!cap.is_revoked());
}

#[test]
fn custom_ttl_bounds_the_lease() {
    let cap: Capability<CanRead, TestResource> = Capability::new_minted(
        "agent:test",
        "test://resource",
        SystemTime::now() - Duration::from_secs(2),
        Duration::from_secs(1),
        None,
        None,
    );
    assert!(cap.is_expired());
}

#[test]
fn revocation_list_invalidates_one_capability() {
    let list = Arc::new(CapabilityRevocationList::new());
    let first: Capability<CanRead, TestResource> = Capability::new_minted(
        "agent:test",
        "test://resource",
        SystemTime::now(),
        DEFAULT_CAPABILITY_TTL,
        None,
        Some(list.clone()),
    );
    let second: Capability<CanRead, TestResource> = Capability::new_minted(
        "agent:test",
        "test://resource",
        SystemTime::now(),
        DEFAULT_CAPABILITY_TTL,
        None,
        Some(list.clone()),
    );

    list.revoke(first.id());

    assert!(first.is_revoked());
    assert!(!second.is_revoked());
    assert!(matches!(
        first.ensure_active(),
        Err(CapabilityUseError::RevokedById { id }) if id == first.id()
    ));
    second
        .ensure_active()
        .expect("second capability remains active");
}

#[test]
fn new_capability_is_active() {
    let cap: Capability<CanRead, TestResource> =
        Capability::new_unchecked("agent:test", "test://resource");

    assert!(!cap.is_expired());
    cap.ensure_active().expect("new capability is active");
}

#[test]
fn is_fresh_bounds_the_toctou_window() {
    let cap: Capability<CanRead, TestResource> = Capability::new_minted(
        "agent:test",
        "test://resource",
        SystemTime::now(),
        DEFAULT_CAPABILITY_TTL,
        None,
        None,
    );

    // Freshly minted: within a generous window, but never within a zero window.
    assert!(cap.is_fresh(Duration::from_secs(60)));
    assert!(!cap.is_fresh(Duration::ZERO));

    // A capability issued in the past is not fresh against a tight window.
    let stale: Capability<CanRead, TestResource> = Capability::new_minted(
        "agent:test",
        "test://resource",
        SystemTime::now() - Duration::from_secs(120),
        DEFAULT_CAPABILITY_TTL,
        None,
        None,
    );
    assert!(!stale.is_fresh(Duration::from_secs(60)));
    assert!(stale.is_fresh(Duration::from_secs(600)));
}
