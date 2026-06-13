//! # TypeDID Agent Communications Example
//!
//! Demonstrates TypeDID as a secure envelope over multiple agent protocols:
//!
//! - A2A-style request/reply delegation.
//! - ACP-style send-only editor context.
//! - BAND-style room message through the generic secure-envelope adapter.
//!
//! The outer protocols stay responsible for rooms, sessions, tasks, routing,
//! and UX. TypeDID provides DID sender/recipient binding, encrypted payloads,
//! reply binding, and the Typesec policy handoff.

use std::sync::Arc;

use typesec_core::{
    Capability, PolicyEngine, ResourceId, SubjectId,
    permissions::CanReadSensitive,
    policy::{CapabilityError, PolicyResult, mint_capability},
    resource::GenericResource,
};
use typesec_integrations::{
    A2aTypeDidAdapter, AcpTypeDidAdapter, BandSecureEnvelopeAdapter, Did, DidEnvelope,
    DidMessageBody, Ed25519DidKey, Ed25519DidKeyStore, SecureEnvelopeAdapter, StaticDidResolver,
    TypeDidGateway, TypeDidMode, TypeDidProfile, TypeDidWrapRequest,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TypeDID Agent Communications Demo ===\n");

    let planner_key = Ed25519DidKey::from_seed(b"planner-agent");
    let reviewer_key = Ed25519DidKey::from_seed(b"reviewer-agent");

    let planner = Did::key(planner_key.signing_public());
    let reviewer = Did::key(reviewer_key.signing_public());

    let resolver = StaticDidResolver::new()
        .with_document(planner_key.document(planner.clone()))
        .with_document(reviewer_key.document(reviewer.clone()));
    let key_store = Ed25519DidKeyStore::new()
        .with_key(planner.clone(), planner_key)
        .with_key(reviewer.clone(), reviewer_key);

    let local_profiles = vec![TypeDidProfile::ed25519_x25519_chacha20()];
    let remote_profiles = vec![TypeDidProfile::ed25519_x25519_chacha20()];
    let gateway = TypeDidGateway::new(
        Arc::new(resolver.clone()),
        Arc::new(key_store.clone()),
        reviewer.clone(),
    );
    let policy = AgentMessagePolicy {
        allowed_subject: planner.to_string(),
    };

    let a2a = A2aTypeDidAdapter;
    let a2a_envelope = a2a.wrap(
        TypeDidWrapRequest {
            id: "a2a-delegate-1".to_owned(),
            from: planner.clone(),
            to: reviewer.clone(),
            conversation_id: "task/review-42".to_owned(),
            mode: TypeDidMode::RequestReply,
            body: DidMessageBody::agent_delegate("room/release-review", "secret"),
            payload: br#"{"jsonrpc":"2.0","method":"message/send","params":{"text":"review the release diff"}}"#,
            local_profiles: &local_profiles,
            remote_profiles: &remote_profiles,
        },
        &resolver,
        &key_store,
    )?;
    let a2a_verified = gateway.open_message(&a2a_envelope)?;
    let read = mint_agent_read(&policy, &a2a_verified.subject, &a2a_verified.resource)?;
    let a2a_reply = DidEnvelope::typedid_reply(
        "a2a-delegate-reply-1",
        reviewer.clone(),
        planner.clone(),
        &a2a_verified,
        b"{\"status\":\"accepted\",\"result\":\"release diff reviewed\"}",
        &resolver,
        &key_store,
    )?;
    println!(
        "A2A:  {} {} -> {}",
        a2a.content_type(),
        a2a_verified.conversation.conversation_id,
        String::from_utf8(a2a_verified.payload.reveal(&read)?)?
    );
    println!(
        "A2A reply: bound to {}\n",
        a2a_reply.body.reply_to.as_ref().unwrap().id
    );

    let acp = AcpTypeDidAdapter;
    let acp_envelope = acp.wrap(
        TypeDidWrapRequest {
            id: "acp-editor-context-1".to_owned(),
            from: planner.clone(),
            to: reviewer.clone(),
            conversation_id: "session/editor-7".to_owned(),
            mode: TypeDidMode::Send,
            body: DidMessageBody::agent_message("room/release-review", "secret"),
            payload: b"private editor context: staged files and reviewer notes",
            local_profiles: &local_profiles,
            remote_profiles: &remote_profiles,
        },
        &resolver,
        &key_store,
    )?;
    let acp_verified = gateway.open_message(&acp_envelope)?;
    let read = mint_agent_read(&policy, &acp_verified.subject, &acp_verified.resource)?;
    println!(
        "ACP:  {} {} -> {}",
        acp.content_type(),
        acp_verified.conversation.conversation_id,
        String::from_utf8(acp_verified.payload.reveal(&read)?)?
    );

    let band = BandSecureEnvelopeAdapter;
    let band_envelope = band.wrap(
        TypeDidWrapRequest {
            id: "band-room-message-1".to_owned(),
            from: planner.clone(),
            to: reviewer,
            conversation_id: "room/release-review".to_owned(),
            mode: TypeDidMode::Send,
            body: DidMessageBody::agent_message("room/release-review", "secret"),
            payload: b"room message: coordinate reviewer and docs agents",
            local_profiles: &local_profiles,
            remote_profiles: &remote_profiles,
        },
        &resolver,
        &key_store,
    )?;
    let band_verified = gateway.open_message(&band_envelope)?;
    let read = mint_agent_read(&policy, &band_verified.subject, &band_verified.resource)?;
    println!(
        "BAND: {} {} -> {}",
        band.content_type(),
        band_verified.conversation.conversation_id,
        String::from_utf8(band_verified.payload.reveal(&read)?)?
    );

    println!("\n=== Demo complete ===");
    Ok(())
}

fn mint_agent_read(
    policy: &AgentMessagePolicy,
    subject: &Did,
    resource: &GenericResource,
) -> Result<Capability<CanReadSensitive, GenericResource>, CapabilityError> {
    mint_capability(policy, subject.as_str(), resource)
}

struct AgentMessagePolicy {
    allowed_subject: String,
}

impl PolicyEngine for AgentMessagePolicy {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
        if subject == self.allowed_subject
            && action == "read_sensitive"
            && resource == "room/release-review"
        {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny(format!("{subject} may not {action} {resource}"))
        }
    }
}
