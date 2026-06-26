//! Capability minting — the single gated path from a policy check to a proof.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::capability::{CapabilityRevocationList, DEFAULT_CAPABILITY_TTL, RevocationEpoch};
use crate::{Capability, Permission, Resource, ResourceId};

use super::{
    AuditEvent, CapabilityError, PolicyEngine, PolicyResult, RequestContext, SubjectId, now_utc,
    record_audit, record_audit_async,
};

/// Mint a [`Capability`] by running a policy check.
///
/// This is the *only* public way to obtain a `Capability` outside `typesec-core`'s
/// test module. The engine performs the check, logs the decision, and either
/// returns a typed capability or an error.
///
/// Implemented as a free function (not a trait method) so that `PolicyEngine`
/// remains object-safe (`dyn PolicyEngine` is valid).
///
/// # Why is this the only path?
///
/// `Capability` has no public constructor — `new_minted` is `pub(crate)`, so only
/// code inside `typesec-core` can call it. This function is that single gated
/// path: it calls the policy engine, logs the verdict, and only creates a
/// capability on `Allow`.
#[must_use = "capability minting can fail and the returned proof should be used"]
pub fn mint_capability<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: impl Into<SubjectId>,
    resource: &R,
) -> Result<Capability<P, R>, CapabilityError> {
    mint_capability_for_id(
        engine,
        subject,
        resource.resource_id(),
        &MintOptions::default(),
    )
}

/// Async variant of [`mint_capability`].
#[must_use = "capability minting can fail and the returned proof should be used"]
pub async fn mint_capability_async<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: impl Into<SubjectId>,
    resource: &R,
) -> Result<Capability<P, R>, CapabilityError> {
    mint_capability_for_id_async(
        engine,
        subject,
        resource.resource_id(),
        &MintOptions::default(),
    )
    .await
}

/// Lease parameters for capability minting.
///
/// Defaults match plain [`mint_capability`]: the
/// [`DEFAULT_CAPABILITY_TTL`] lease and no revocation binding.
#[derive(Clone, Debug)]
pub struct MintOptions {
    /// How long the minted capability stays usable. Pick per risk: a
    /// `CanDeclassify` capability warrants seconds; a low-risk read can hold
    /// the default 5 minutes or longer.
    pub ttl: Duration,
    /// Optional shared revocation epoch. Capabilities minted with one can be
    /// invalidated mid-lease by calling [`RevocationEpoch::revoke_all`]
    /// (e.g. after a policy reload).
    pub revocation: Option<RevocationEpoch>,
    /// Optional per-capability revocation list. Capabilities minted with one
    /// can be invalidated individually via [`CapabilityRevocationList::revoke`].
    pub revocation_list: Option<Arc<CapabilityRevocationList>>,
    /// Runtime context to pass into the policy engine while minting.
    pub context: RequestContext,
}

impl Default for MintOptions {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_CAPABILITY_TTL,
            revocation: None,
            revocation_list: None,
            context: RequestContext::default(),
        }
    }
}

impl MintOptions {
    /// Bind minted capabilities to a per-capability revocation list.
    pub fn with_revocation_list(mut self, revocation_list: Arc<CapabilityRevocationList>) -> Self {
        self.revocation_list = Some(revocation_list);
        self
    }
}

/// Like [`mint_capability`], but with explicit lease parameters.
#[must_use = "capability minting can fail and the returned proof should be used"]
pub fn mint_capability_with<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: impl Into<SubjectId>,
    resource: &R,
    options: &MintOptions,
) -> Result<Capability<P, R>, CapabilityError> {
    mint_capability_for_id(engine, subject, resource.resource_id(), options)
}

/// Async variant of [`mint_capability_with`].
#[must_use = "capability minting can fail and the returned proof should be used"]
pub async fn mint_capability_with_async<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: impl Into<SubjectId>,
    resource: &R,
    options: &MintOptions,
) -> Result<Capability<P, R>, CapabilityError> {
    mint_capability_for_id_async(engine, subject, resource.resource_id(), options).await
}

/// Mint a capability for a resource identified only by its id string.
///
/// This exists for callers that only have a stable resource identifier. The
/// resulting capability is bound to `resource_id` exactly as if the `&R` form
/// had been used: every consumption site (`execute`, `reveal`, `declassify`)
/// still compares ids at use time, so naming a mismatched `R` type buys an
/// attacker nothing — the capability only covers the id the engine approved.
#[must_use = "capability minting can fail and the returned proof should be used"]
pub fn mint_capability_for_id<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: impl Into<SubjectId>,
    resource_id: impl Into<ResourceId>,
    options: &MintOptions,
) -> Result<Capability<P, R>, CapabilityError> {
    let subject = subject.into();
    let resource_id = resource_id.into();
    let action = P::name();

    let result = engine.check_with_context(&subject, action, &resource_id, &options.context);

    // Emit the structured audit event for every decision, allow or deny.
    record_audit(&audit_event(&subject, action, &resource_id, &result));

    finish_mint(result, subject, resource_id, options)
}

/// Async variant of [`mint_capability_for_id`].
#[must_use = "capability minting can fail and the returned proof should be used"]
pub async fn mint_capability_for_id_async<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: impl Into<SubjectId>,
    resource_id: impl Into<ResourceId>,
    options: &MintOptions,
) -> Result<Capability<P, R>, CapabilityError> {
    let subject = subject.into();
    let resource_id = resource_id.into();
    let action = P::name();

    let result = engine
        .check_with_context_async(&subject, action, &resource_id, &options.context)
        .await;

    record_audit_async(&audit_event(&subject, action, &resource_id, &result)).await;

    finish_mint(result, subject, resource_id, options)
}

/// Build the structured [`AuditEvent`] for a decision.
///
/// Shared by the sync and async mint paths so the two cannot drift in which
/// fields they record (the "twin bodies that silently diverge" hazard).
fn audit_event(
    subject: &SubjectId,
    action: &str,
    resource: &ResourceId,
    result: &PolicyResult,
) -> AuditEvent {
    AuditEvent {
        subject: subject.clone(),
        action: action.to_owned(),
        resource: resource.clone(),
        result: result.clone(),
        timestamp: now_utc(),
    }
}

/// Turn an audited policy verdict into a minted capability or a typed error.
///
/// Shared terminal step of the sync and async `mint_capability_for_id` paths so
/// the Allow/Deny/Delegate handling cannot diverge between them.
fn finish_mint<P: Permission, R: Resource>(
    result: PolicyResult,
    subject: SubjectId,
    resource_id: ResourceId,
    options: &MintOptions,
) -> Result<Capability<P, R>, CapabilityError> {
    match result {
        PolicyResult::Allow => Ok(Capability::new_minted(
            subject,
            resource_id,
            SystemTime::now(),
            options.ttl,
            options.revocation.clone(),
            options.revocation_list.clone(),
        )),
        PolicyResult::Deny(reason) => Err(CapabilityError::Denied { reason }),
        PolicyResult::Delegate(_) => Err(CapabilityError::UnhandledDelegation),
    }
}
