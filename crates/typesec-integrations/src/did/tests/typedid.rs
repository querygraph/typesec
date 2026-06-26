use std::sync::Arc;

use typesec_core::{permissions::CanReadSensitive, policy::mint_capability};

use super::super::crypto::unix_time;
use super::super::*;
use super::common::*;

#[test]
fn typedid_profile_negotiates_on_protocol_and_mode() {
    let local = vec![TypeDidProfile::ed25519_x25519_chacha20()];
    let remote = vec![TypeDidProfile::ed25519_x25519_chacha20()];
    let selected = TypeDidProfile::negotiate(&local, &remote, "a2a", TypeDidMode::RequestReply)
        .expect("compatible profile");
    assert_eq!(selected.id, "typedid/v1/x25519-chacha20poly1305-ed25519");

    assert!(matches!(
        TypeDidProfile::negotiate(&local, &remote, "smtp", TypeDidMode::Send),
        Err(DidError::NoCompatibleTypeDidProfile)
    ));
}

#[test]
fn typedid_adapter_wraps_and_gateway_opens_opaque_payload() {
    let (alice, agent, resolver, keys) = fixture();
    let profiles = vec![TypeDidProfile::ed25519_x25519_chacha20()];
    let adapter = A2aTypeDidAdapter;
    let payload = br#"{"jsonrpc":"2.0","method":"message/send","params":{"text":"triage case"}}"#;

    let envelope = adapter
        .wrap(
            TypeDidWrapRequest {
                id: "a2a-msg-1".to_owned(),
                from: alice.clone(),
                to: agent.clone(),
                conversation_id: "task/a2a-123".to_owned(),
                mode: TypeDidMode::RequestReply,
                body: DidMessageBody::agent_delegate("room/acme-support", "secret"),
                payload,
                local_profiles: &profiles,
                remote_profiles: &profiles,
            },
            &resolver,
            &keys,
        )
        .expect("wrapped envelope");

    assert_eq!(
        adapter.content_type(),
        "application/vnd.typedid.envelope+json"
    );
    assert_eq!(
        envelope.message_type,
        "https://typesec.dev/did/message/v1/typedid"
    );
    assert_eq!(envelope.typedid.as_ref().unwrap().protocol, "a2a");
    assert_ne!(envelope.ciphertext.as_bytes(), payload);

    let gateway = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    let verified = gateway.open_message(&envelope).expect("verified typedid");
    assert_eq!(verified.subject, alice);
    assert_eq!(verified.conversation.conversation_id, "task/a2a-123");
    assert_eq!(verified.body.action, "agent:delegate");

    let read = mint_capability::<CanReadSensitive, _>(
        &AgentPolicy {
            allowed_subject: verified.subject.to_string(),
        },
        verified.subject.as_str(),
        &verified.resource,
    )
    .expect("read cap");
    assert_eq!(verified.payload.reveal(&read).expect("payload"), payload);
}

#[test]
fn typedid_wrap_enforces_negotiated_payload_cap() {
    let (alice, agent, resolver, keys) = fixture();
    // A negotiated profile with a tiny payload cap; the local profile's cap is
    // what `wrap` enforces.
    let mut small = TypeDidProfile::ed25519_x25519_chacha20();
    small.max_payload_bytes = Some(8);
    let profiles = vec![small];
    let adapter = A2aTypeDidAdapter;

    let result = adapter.wrap(
        TypeDidWrapRequest {
            id: "a2a-too-big".to_owned(),
            from: alice,
            to: agent,
            conversation_id: "task/a2a-456".to_owned(),
            mode: TypeDidMode::RequestReply,
            body: DidMessageBody::agent_delegate("room/acme-support", "secret"),
            payload: b"this payload is nine+ bytes",
            local_profiles: &profiles,
            remote_profiles: &profiles,
        },
        &resolver,
        &keys,
    );

    assert!(matches!(
        result,
        Err(DidError::PayloadTooLarge { max: 8, .. })
    ));
}

#[test]
fn typedid_verified_message_exposes_audit_safe_attestation() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let envelope = DidEnvelope::typedid(
        "typedid-attestation-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::agent_message("lakecat:table:events", "internal"),
        TypeDidConversation::new(
            "conversation-1",
            TypeDidMode::RequestReply,
            TypeDidProfile::ed25519_x25519_chacha20().id,
            "a2a",
        )
        .with_expires_at(unix_time() + 300),
        b"secret payload",
        &resolver,
        &keys,
    )
    .expect("typedid envelope");
    let gateway = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    let verified = gateway.open_message(&envelope).expect("verified typedid");
    let attestation = verified.attestation();

    assert_eq!(attestation.subject, alice);
    assert_eq!(attestation.envelope_id, "typedid-attestation-1");
    assert_eq!(attestation.action, "agent:message");
    assert_eq!(attestation.resource, "lakecat:table:events");
    assert_eq!(attestation.privacy, "internal");
    assert_eq!(attestation.protocol, "a2a");
    assert_eq!(attestation.mode, TypeDidMode::RequestReply);
    let serialized = serde_json::to_string(&attestation).unwrap();
    assert!(!serialized.contains("secret payload"));
    assert!(!serialized.contains(&envelope.signature));
}

#[test]
fn typedid_reply_is_bound_to_request_envelope() {
    let (alice, agent, resolver, keys) = fixture();
    let request = DidEnvelope::typedid(
        "band-room-msg-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::agent_message("room/acme-support", "secret"),
        TypeDidConversation::new(
            "room/acme-support",
            TypeDidMode::RequestReply,
            TypeDidProfile::ed25519_x25519_chacha20().id,
            "band",
        ),
        b"please coordinate with the support agent",
        &resolver,
        &keys,
    )
    .expect("request envelope");
    let request_ref = request.reference();
    let gateway = TypeDidGateway::new(
        Arc::new(resolver.clone()),
        Arc::new(keys.clone()),
        agent.clone(),
    );
    let verified = gateway.open_message(&request).expect("verified request");
    let reply = DidEnvelope::typedid_reply(
        "band-room-reply-1",
        agent.clone(),
        alice.clone(),
        &verified,
        b"support agent accepted the handoff",
        &resolver,
        &keys,
    )
    .expect("reply envelope");

    assert_eq!(reply.typedid.as_ref().unwrap().protocol, "band");
    assert_eq!(reply.body.reply_to, Some(request_ref));

    let reply_gateway = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), alice);
    let opened_reply = reply_gateway.open_message(&reply).expect("opened reply");
    assert_eq!(opened_reply.subject, agent);
}

#[test]
fn typedid_signature_covers_conversation_metadata() {
    let (alice, agent, resolver, keys) = fixture();
    let mut envelope = DidEnvelope::typedid(
        "acp-session-msg-1",
        alice,
        agent.clone(),
        DidMessageBody::agent_message("room/acme-support", "secret"),
        TypeDidConversation::new(
            "session/editor-1",
            TypeDidMode::Send,
            TypeDidProfile::ed25519_x25519_chacha20().id,
            "acp",
        ),
        b"review this private diff",
        &resolver,
        &keys,
    )
    .expect("typedid envelope");
    envelope.typedid.as_mut().unwrap().protocol = "band".to_owned();

    let gateway = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    assert!(matches!(
        gateway.open_message(&envelope),
        Err(DidError::InvalidSignature)
    ));
}
