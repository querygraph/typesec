use super::*;
use crate::{
    capability::{Capability, DEFAULT_CAPABILITY_TTL},
    permissions::{CanDeclassify, CanReadInternal, CanReadSensitive},
    resource::GenericResource,
};
use std::time::{Duration, SystemTime};

#[test]
fn map_preserves_label_and_resource() {
    let resource = GenericResource::new("customer/1", "customer");
    let value: SecureValue<Sensitive, String, GenericResource> =
        SecureValue::protect("alice@example.com".to_owned(), &resource);

    let len = value.map(|email| email.len());

    assert_eq!(
        SecureValue::<Sensitive, usize, GenericResource>::label_name(),
        "sensitive"
    );
    assert_eq!(len.resource_id(), "customer/1");
}

#[test]
fn zip_uses_more_restrictive_label() {
    let resource = GenericResource::new("customer/1", "customer");
    let public: SecureValue<Public, u32, GenericResource> = SecureValue::protect(7, &resource);
    let secret: SecureValue<Secret, &str, GenericResource> =
        SecureValue::protect("token", &resource);

    let combined: SecureValue<Secret, (u32, &str), GenericResource> =
        public.zip(secret).expect("same resource id");

    assert_eq!(combined.resource_id(), "customer/1");
}

#[test]
fn zip_rejects_different_resource_ids() {
    let left_resource = GenericResource::new("customer/1", "customer");
    let right_resource = GenericResource::new("customer/2", "customer");
    let public: SecureValue<Public, u32, GenericResource> = SecureValue::protect(7, &left_resource);
    let secret: SecureValue<Secret, &str, GenericResource> =
        SecureValue::protect("token", &right_resource);

    assert!(matches!(
        public.zip(secret),
        Err(SecureValueError::ResourceIdMismatch {
            left_resource,
            right_resource
        }) if left_resource == "customer/1" && right_resource == "customer/2"
    ));
}

#[test]
fn public_values_can_be_unwrapped_without_capability() {
    let resource = GenericResource::new("report/1", "report");
    let public: SecureValue<Public, &str, GenericResource> = SecureValue::protect("ok", &resource);

    assert_eq!(public.into_public(), "ok");
}

#[test]
fn sensitive_values_require_capability_to_reveal() {
    let resource = GenericResource::new("customer/1", "customer");
    let secret: SecureValue<Secret, &str, GenericResource> = SecureValue::protect("ssn", &resource);
    let cap: Capability<CanReadSensitive, GenericResource> =
        Capability::new_unchecked("agent:test", "customer/1");

    assert_eq!(secret.reveal(&cap).expect("matching resource"), "ssn");
}

#[test]
fn internal_values_reveal_with_internal_capability() {
    let resource = GenericResource::new("memo/1", "memo");
    let internal: SecureValue<Internal, &str, GenericResource> =
        SecureValue::protect("draft roadmap", &resource);
    let cap: Capability<CanReadInternal, GenericResource> =
        Capability::new_unchecked("agent:test", "memo/1");

    assert_eq!(
        internal.reveal_internal(&cap).expect("matching resource"),
        "draft roadmap"
    );
}

#[test]
fn declassify_makes_public_value() {
    let resource = GenericResource::new("metric/1", "metric");
    let sensitive: SecureValue<Sensitive, usize, GenericResource> =
        SecureValue::protect(42, &resource);
    let cap: Capability<CanDeclassify, GenericResource> =
        Capability::new_unchecked("agent:test", "metric/1");

    let public = sensitive.declassify(&cap).expect("matching resource");

    assert_eq!(public.into_public(), 42);
}

#[test]
fn reveal_rejects_capability_for_other_resource_instance() {
    let resource = GenericResource::new("customer/1", "customer");
    let secret: SecureValue<Secret, &str, GenericResource> = SecureValue::protect("ssn", &resource);
    // Same resource *type*, different *instance*:
    let cap: Capability<CanReadSensitive, GenericResource> =
        Capability::new_unchecked("agent:test", "customer/2");

    assert!(matches!(
        secret.reveal(&cap),
        Err(SecureAccessError::ResourceMismatch { .. })
    ));
}

#[test]
fn reveal_internal_rejects_capability_for_other_resource_instance() {
    let resource = GenericResource::new("memo/1", "memo");
    let internal: SecureValue<Internal, &str, GenericResource> =
        SecureValue::protect("draft roadmap", &resource);
    let cap: Capability<CanReadInternal, GenericResource> =
        Capability::new_unchecked("agent:test", "memo/2");

    assert!(matches!(
        internal.reveal_internal(&cap),
        Err(SecureAccessError::ResourceMismatch { .. })
    ));
}

#[test]
fn declassify_rejects_capability_for_other_resource_instance() {
    let resource = GenericResource::new("metric/1", "metric");
    let sensitive: SecureValue<Sensitive, usize, GenericResource> =
        SecureValue::protect(42, &resource);
    let cap: Capability<CanDeclassify, GenericResource> =
        Capability::new_unchecked("agent:test", "metric/other");

    assert!(matches!(
        sensitive.declassify(&cap),
        Err(SecureAccessError::ResourceMismatch { .. })
    ));
}

#[test]
fn debug_redacts_protected_value() {
    let resource = GenericResource::new("customer/1", "customer");
    let secret: SecureValue<Secret, &str, GenericResource> =
        SecureValue::protect("ssn-123-45-6789", &resource);

    let rendered = format!("{secret:?}");
    assert!(!rendered.contains("ssn-123-45-6789"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn reveal_rejects_expired_capability() {
    let resource = GenericResource::new("customer/1", "customer");
    let secret: SecureValue<Secret, &str, GenericResource> = SecureValue::protect("ssn", &resource);
    let issued_at = SystemTime::now()
        .checked_sub(DEFAULT_CAPABILITY_TTL + Duration::from_secs(1))
        .expect("time subtraction");
    let cap: Capability<CanReadSensitive, GenericResource> =
        Capability::new_with_issued_at("agent:test", "customer/1", issued_at);

    assert!(matches!(
        secret.reveal(&cap),
        Err(SecureAccessError::Capability(_))
    ));
}

#[test]
fn reveal_internal_rejects_expired_capability() {
    let resource = GenericResource::new("memo/1", "memo");
    let internal: SecureValue<Internal, &str, GenericResource> =
        SecureValue::protect("draft roadmap", &resource);
    let issued_at = SystemTime::now()
        .checked_sub(DEFAULT_CAPABILITY_TTL + Duration::from_secs(1))
        .expect("time subtraction");
    let cap: Capability<CanReadInternal, GenericResource> =
        Capability::new_with_issued_at("agent:test", "memo/1", issued_at);

    assert!(matches!(
        internal.reveal_internal(&cap),
        Err(SecureAccessError::Capability(_))
    ));
}
