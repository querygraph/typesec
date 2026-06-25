use super::*;
use crate::capability::{CapabilityRevocationList, RevocationEpoch};
use crate::{Capability, permissions::CanRead, resource::GenericResource};
use chrono::Utc;
use std::error::Error;
use std::time::Duration;

struct AllowAll;
impl PolicyEngine for AllowAll {
    fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
        PolicyResult::Allow
    }
}

struct DenyAll;
impl PolicyEngine for DenyAll {
    fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
        PolicyResult::Deny("DenyAll engine".into())
    }
}

struct AsyncAllowOnly;
impl PolicyEngine for AsyncAllowOnly {
    fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
        PolicyResult::Deny("sync path should not be used".into())
    }

    fn check_with_context_async<'a>(
        &'a self,
        _: &'a SubjectId,
        _: &'a str,
        _: &'a ResourceId,
        _: &'a RequestContext,
    ) -> PolicyFuture<'a> {
        Box::pin(async { PolicyResult::Allow })
    }
}

#[test]
fn allow_all_mints_capability() {
    let engine = AllowAll;
    let resource = GenericResource::new("reports/q1", "report");
    let cap: Capability<CanRead, GenericResource> =
        mint_capability(&engine, "agent:test", &resource).expect("should allow");
    assert_eq!(cap.subject(), "agent:test");
}

#[test]
fn deny_all_returns_error() {
    let engine = DenyAll;
    let resource = GenericResource::new("reports/q1", "report");
    let result: Result<Capability<CanRead, GenericResource>, _> =
        mint_capability(&engine, "agent:test", &resource);
    assert!(matches!(result, Err(CapabilityError::Denied { .. })));
}

#[test]
fn async_mint_uses_async_policy_path() {
    let engine = AsyncAllowOnly;
    let resource = GenericResource::new("reports/q1", "report");

    let sync_result: Result<Capability<CanRead, GenericResource>, _> =
        mint_capability(&engine, "agent:test", &resource);
    assert!(matches!(sync_result, Err(CapabilityError::Denied { .. })));

    let async_result: Result<Capability<CanRead, GenericResource>, _> =
        futures::executor::block_on(mint_capability_async(&engine, "agent:test", &resource));
    let cap = async_result.expect("async policy path should allow");
    assert_eq!(cap.subject(), "agent:test");
    assert_eq!(cap.resource_id(), "reports/q1");
}

#[test]
fn audit_sink_can_override_async_recording() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct AsyncOnlySink {
        sync_records: AtomicUsize,
        async_records: AtomicUsize,
    }

    impl AuditSink for AsyncOnlySink {
        fn record(&self, _: &AuditEvent) {
            self.sync_records.fetch_add(1, Ordering::Relaxed);
        }

        fn record_async<'a>(&'a self, _: &'a AuditEvent) -> AuditFuture<'a> {
            Box::pin(async move {
                self.async_records.fetch_add(1, Ordering::Relaxed);
            })
        }
    }

    let sink = AsyncOnlySink {
        sync_records: AtomicUsize::new(0),
        async_records: AtomicUsize::new(0),
    };
    let event = AuditEvent {
        subject: "agent:test".into(),
        action: "read".into(),
        resource: "reports/q1".into(),
        result: PolicyResult::Allow,
        timestamp: now_utc(),
    };

    futures::executor::block_on(sink.record_async(&event));
    assert_eq!(sink.sync_records.load(Ordering::Relaxed), 0);
    assert_eq!(sink.async_records.load(Ordering::Relaxed), 1);
}

#[test]
fn mint_with_revocation_epoch_supports_mid_lease_revocation() {
    let engine = AllowAll;
    let resource = GenericResource::new("reports/q1", "report");
    let epoch = RevocationEpoch::new();
    let options = MintOptions {
        revocation: Some(epoch.clone()),
        ..MintOptions::default()
    };
    let cap: Capability<CanRead, GenericResource> =
        mint_capability_with(&engine, "agent:test", &resource, &options).expect("allow");

    cap.ensure_active().expect("active before revocation");
    epoch.revoke_all();
    assert!(cap.ensure_active().is_err());
}

#[test]
fn mint_with_revocation_list_revokes_one_capability() {
    let engine = AllowAll;
    let resource = GenericResource::new("reports/q1", "report");
    let revocation_list = Arc::new(CapabilityRevocationList::new());
    let options = MintOptions::default().with_revocation_list(revocation_list.clone());

    let first: Capability<CanRead, GenericResource> =
        mint_capability_with(&engine, "agent:test", &resource, &options).expect("allow");
    let second: Capability<CanRead, GenericResource> =
        mint_capability_with(&engine, "agent:test", &resource, &options).expect("allow");

    revocation_list.revoke(first.id());

    assert!(matches!(
        first.ensure_active(),
        Err(crate::capability::CapabilityUseError::RevokedById { id }) if id == first.id()
    ));
    second
        .ensure_active()
        .expect("second capability remains active");
}

#[test]
fn mint_with_short_ttl_expires() {
    let engine = AllowAll;
    let resource = GenericResource::new("reports/q1", "report");
    let options = MintOptions {
        ttl: Duration::ZERO,
        ..MintOptions::default()
    };
    let cap: Capability<CanRead, GenericResource> =
        mint_capability_with(&engine, "agent:test", &resource, &options).expect("allow");
    assert!(cap.is_expired());
}

#[test]
fn audit_timestamp_is_typed_and_formats_as_rfc3339() {
    let event = AuditEvent {
        subject: SubjectId::from("agent:test"),
        action: "read".to_owned(),
        resource: ResourceId::from("reports/q1"),
        result: PolicyResult::Allow,
        timestamp: Utc::now(),
    };

    let rendered = format_audit_timestamp(&event.timestamp);

    assert!(rendered.ends_with('Z'));
    assert!(rendered.contains('T'));
}

#[test]
fn engine_error_preserves_source() {
    let err = CapabilityError::engine_error_source(std::io::Error::other("join failed"));

    assert!(err.source().is_some());
    assert_eq!(
        err.source().map(ToString::to_string).as_deref(),
        Some("join failed")
    );
}

#[test]
fn mint_with_request_context_passes_context_to_engine() {
    struct PurposeEngine;
    impl PolicyEngine for PurposeEngine {
        fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
            PolicyResult::Deny("missing context".into())
        }

        fn check_with_context(
            &self,
            _: &SubjectId,
            _: &str,
            _: &ResourceId,
            ctx: &RequestContext,
        ) -> PolicyResult {
            if ctx.purpose.as_deref() == Some("analytics") {
                PolicyResult::Allow
            } else {
                PolicyResult::Deny("wrong purpose".into())
            }
        }
    }

    let resource = GenericResource::new("reports/q1", "report");
    let options = MintOptions {
        context: RequestContext::default().with_purpose("analytics"),
        ..MintOptions::default()
    };
    let cap: Capability<CanRead, GenericResource> =
        mint_capability_with(&PurposeEngine, "agent:test", &resource, &options)
            .expect("context should allow");

    assert_eq!(cap.resource_id(), "reports/q1");
}

#[test]
fn composed_engine_falls_back() {
    struct DelegateAlways;
    impl PolicyEngine for DelegateAlways {
        fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
            PolicyResult::delegate("test", "fallback")
        }
    }

    let engine = DelegateAlways.with_fallback(Arc::new(AllowAll));
    let result = engine.check(
        &SubjectId::from("agent:x"),
        "read",
        &ResourceId::from("reports/q1"),
    );
    assert_eq!(result, PolicyResult::Allow);
}
