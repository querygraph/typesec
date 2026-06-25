use std::sync::Arc;

use serde_json::json;
use typesec_core::{
    Capability, PolicyEngine, Resource, ResourceId, SecureValue, SubjectId,
    permissions::{AiCanInfer, CanReadSensitive},
    policy::{PolicyResult, mint_capability},
    resource::GenericResource,
    secure_value::Secret,
};

use super::crypto::unix_time;
use super::*;
use crate::http::RecordingHttpClient;

struct PromptPolicy;

impl PolicyEngine for PromptPolicy {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
        if subject == "did:key:z616c696365"
            && matches!(action, "ai:infer" | "read_sensitive")
            && resource == "prompt/session/123"
        {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny("not allowed".to_owned())
        }
    }
}

fn fixture() -> (Did, Did, StaticDidResolver, DemoDidKeyStore) {
    let alice = Did::key(b"alice");
    let agent = Did::key(b"agent");
    let alice_key = DemoDidKeyPair::from_seed(b"alice");
    let agent_key = DemoDidKeyPair::from_seed(b"agent");
    let resolver = StaticDidResolver::new()
        .with_document(DidDocument::single_key(
            alice.clone(),
            alice_key.public_key.clone(),
        ))
        .with_document(DidDocument::single_key(
            agent.clone(),
            agent_key.public_key.clone(),
        ));
    let keys = DemoDidKeyStore::new()
        .with_key(alice.clone(), alice_key)
        .with_key(agent.clone(), agent_key);
    (alice, agent, resolver, keys)
}

struct AgentPolicy {
    allowed_subject: String,
}

impl PolicyEngine for AgentPolicy {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
        if subject == self.allowed_subject
            && matches!(
                action,
                "agent:message" | "agent:delegate" | "read_sensitive"
            )
            && resource == "room/acme-support"
        {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny("agent message denied".to_owned())
        }
    }
}

#[test]
fn dids_parse_and_reject_bad_values() {
    assert!(Did::parse("did:web:example.com").is_ok());
    assert!(Did::parse("not-a-did").is_err());
    assert_eq!(
        Did::web("typesec.dev").unwrap().as_str(),
        "did:web:typesec.dev"
    );
}

#[test]
fn encrypted_prompt_opens_as_secret_secure_value() {
    let (alice, agent, resolver, keys) = fixture();
    let envelope = DidEnvelope::prompt(
        "msg-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/123"),
        "summarize this confidential record",
        &resolver,
        &keys,
    )
    .expect("envelope");
    assert_ne!(envelope.ciphertext, "summarize this confidential record");

    let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    let verified = gateway.open_prompt(&envelope).expect("verified prompt");
    assert_eq!(verified.subject, alice);
    assert_eq!(verified.resource.resource_id(), "prompt/session/123");
    assert_eq!(
        SecureValue::<Secret, String, GenericResource>::label_name(),
        "secret"
    );

    let infer = mint_capability::<AiCanInfer, _>(
        &PromptPolicy,
        verified.subject.as_str(),
        &verified.resource,
    )
    .expect("infer cap");
    let read = mint_capability::<CanReadSensitive, _>(
        &PromptPolicy,
        verified.subject.as_str(),
        &verified.resource,
    )
    .expect("read cap");
    assert_eq!(infer.resource_id(), "prompt/session/123");
    assert_eq!(
        verified.prompt.reveal(&read).expect("matching resource"),
        "summarize this confidential record"
    );
}

#[test]
fn did_ollama_client_sends_plaintext_only_after_capabilities() {
    let (alice, agent, resolver, keys) = fixture();
    let envelope = DidEnvelope::prompt(
        "msg-1",
        alice,
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/123"),
        "private prompt",
        &resolver,
        &keys,
    )
    .expect("envelope");
    let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    let verified = gateway.open_prompt(&envelope).expect("verified prompt");
    let infer = mint_capability::<AiCanInfer, _>(
        &PromptPolicy,
        verified.subject.as_str(),
        &verified.resource,
    )
    .expect("infer cap");
    let read = mint_capability::<CanReadSensitive, _>(
        &PromptPolicy,
        verified.subject.as_str(),
        &verified.resource,
    )
    .expect("read cap");

    let http = RecordingHttpClient::new().with_response(
        "http://localhost:11434/api/chat",
        json!({ "message": { "content": "ok" } }),
    );
    let client =
        DidOllamaClient::with_http("http://localhost:11434", "llama3.2", Arc::new(http.clone()));
    let response = client
        .chat_verified_prompt(verified, &infer, &read)
        .expect("ollama call");

    assert_eq!(response["message"]["content"], "ok");
    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url, "http://localhost:11434/api/chat");
    assert_eq!(
        requests[0].body.as_ref().unwrap()["messages"][0]["content"],
        "private prompt"
    );
}

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

#[test]
fn bound_ollama_reply_creates_signed_reply_envelope_for_prompt() {
    let (alice, agent, resolver, keys) = fixture();
    let prompt_envelope = DidEnvelope::prompt(
        "msg-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/123"),
        "private prompt",
        &resolver,
        &keys,
    )
    .expect("prompt envelope");
    let prompt_ref = prompt_envelope.reference();
    let gateway = DidMessageGateway::new(
        Arc::new(resolver.clone()),
        Arc::new(keys.clone()),
        agent.clone(),
    );
    let verified = gateway
        .open_prompt(&prompt_envelope)
        .expect("verified prompt");
    let infer = mint_capability::<AiCanInfer, _>(
        &PromptPolicy,
        verified.subject.as_str(),
        &verified.resource,
    )
    .expect("infer cap");
    let read = mint_capability::<CanReadSensitive, _>(
        &PromptPolicy,
        verified.subject.as_str(),
        &verified.resource,
    )
    .expect("read cap");

    let http = RecordingHttpClient::new().with_response(
        "http://localhost:11434/api/chat",
        json!({ "message": { "content": "bound reply" } }),
    );
    let client =
        DidOllamaClient::with_http("http://localhost:11434", "llama3.2", Arc::new(http.clone()));
    let reply_envelope = client
        .chat_verified_prompt_bound(verified, agent.clone(), &resolver, &keys, &infer, &read)
        .expect("bound reply");

    assert!(reply_envelope.id.starts_with("did:key:z"));
    assert_eq!(
        reply_envelope.message_type,
        "https://typesec.dev/did/message/v1/reply"
    );
    assert_eq!(reply_envelope.from, agent);
    assert_eq!(reply_envelope.to, vec![alice.clone()]);
    assert_eq!(reply_envelope.body.resource, "prompt/session/123");
    assert_eq!(reply_envelope.body.privacy, "secret");
    assert_eq!(reply_envelope.body.reply_to, Some(prompt_ref));
    assert_ne!(reply_envelope.ciphertext, "bound reply");

    let reply_gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), alice);
    let opened_reply = reply_gateway
        .open_prompt(&reply_envelope)
        .expect("verified reply");
    assert_eq!(opened_reply.subject, reply_envelope.from);
    assert_eq!(
        opened_reply
            .prompt
            .reveal(&read)
            .expect("matching resource"),
        "bound reply"
    );
}

#[test]
fn reply_signature_covers_prompt_reference() {
    let (alice, agent, resolver, keys) = fixture();
    let prompt_envelope = DidEnvelope::prompt(
        "msg-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/123"),
        "private prompt",
        &resolver,
        &keys,
    )
    .expect("prompt envelope");
    let gateway = DidMessageGateway::new(
        Arc::new(resolver.clone()),
        Arc::new(keys.clone()),
        agent.clone(),
    );
    let verified = gateway
        .open_prompt(&prompt_envelope)
        .expect("verified prompt");
    let mut reply_envelope = DidEnvelope::reply(
        Did::key(b"reply-1"),
        agent,
        alice.clone(),
        DidReplyBinding::for_prompt(&verified),
        "bound reply",
        &resolver,
        &keys,
    )
    .expect("reply envelope");
    reply_envelope
        .body
        .reply_to
        .as_mut()
        .expect("prompt reference")
        .digest = "tampered".to_owned();

    let reply_gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), alice);
    assert!(matches!(
        reply_gateway.open_prompt(&reply_envelope),
        Err(DidError::InvalidSignature)
    ));
}

fn ed25519_fixture() -> (Did, Did, StaticDidResolver, Ed25519DidKeyStore) {
    let alice_key = Ed25519DidKey::from_seed(b"alice-ed25519");
    let agent_key = Ed25519DidKey::from_seed(b"agent-ed25519");
    let alice = Did::key(alice_key.signing_public());
    let agent = Did::key(agent_key.signing_public());
    let resolver = StaticDidResolver::new()
        .with_document(alice_key.document(alice.clone()))
        .with_document(agent_key.document(agent.clone()));
    let keys = Ed25519DidKeyStore::new()
        .with_key(alice.clone(), alice_key)
        .with_key(agent.clone(), agent_key);
    (alice, agent, resolver, keys)
}

#[test]
fn ed25519_envelope_roundtrip() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let envelope = DidEnvelope::prompt(
        "msg-ed-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/ed"),
        "confidential prompt over real crypto",
        &resolver,
        &keys,
    )
    .expect("envelope");
    assert_ne!(envelope.ciphertext, "confidential prompt over real crypto");

    let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    let verified = gateway.open_prompt(&envelope).expect("verified prompt");
    assert_eq!(verified.subject, alice);

    let cap: Capability<CanReadSensitive, GenericResource> = mint_capability(
        &AllowAllForTest,
        verified.subject.as_str(),
        &verified.resource,
    )
    .expect("read cap");
    assert_eq!(
        verified.prompt.reveal(&cap).expect("matching resource"),
        "confidential prompt over real crypto"
    );
}

#[test]
fn ed25519_rejects_tampered_envelope() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let mut envelope = DidEnvelope::prompt(
        "msg-ed-2",
        alice,
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/ed"),
        "payload",
        &resolver,
        &keys,
    )
    .expect("envelope");
    envelope.body.resource = "prompt/session/other".to_owned();

    let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    assert!(matches!(
        gateway.open_prompt(&envelope),
        Err(DidError::InvalidSignature)
    ));
}

#[test]
fn ed25519_signature_is_not_forgeable_from_public_key() {
    // With the demo store, anyone holding the public key could mint a
    // valid signature. The Ed25519 store must not allow that.
    let (alice, _agent, resolver, _keys) = ed25519_fixture();
    let document = resolver.resolve(&alice).expect("document");
    let auth_method = &document.verification_method[0];

    // An attacker key store that does NOT hold alice's private key but
    // knows her public key cannot produce a signature that verifies.
    let attacker_key = Ed25519DidKey::from_seed(b"attacker");
    let attacker_store = Ed25519DidKeyStore::new().with_key(alice.clone(), attacker_key);
    let forged = attacker_store.sign(&alice, b"message").expect("sign");

    let honest_store = Ed25519DidKeyStore::new();
    assert!(matches!(
        honest_store.verify(auth_method, b"message", &forged),
        Err(DidError::InvalidSignature)
    ));
}

#[test]
fn ed25519_rotation_keeps_old_envelopes_until_retired() {
    let alice = Did::web("alice.example").expect("alice did");
    let agent = Did::web("agent.example").expect("agent did");
    let mut keys = Ed25519DidKeyStore::new()
        .with_key(alice.clone(), Ed25519DidKey::from_seed(b"alice-v1"))
        .with_key(agent.clone(), Ed25519DidKey::from_seed(b"agent-v1"));
    let resolver_v1 = StaticDidResolver::new()
        .with_document(keys.document(&alice).expect("alice v1 document"))
        .with_document(keys.document(&agent).expect("agent v1 document"));

    let old_envelope = DidEnvelope::prompt(
        "msg-rot-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/rot"),
        "old in-flight payload",
        &resolver_v1,
        &keys,
    )
    .expect("old envelope");
    assert_eq!(old_envelope.kid, format!("{alice}#key-1"));

    assert_eq!(
        keys.rotate_key(&alice, Ed25519DidKey::from_seed(b"alice-v2"))
            .expect("rotate alice"),
        2
    );
    assert_eq!(
        keys.rotate_key(&agent, Ed25519DidKey::from_seed(b"agent-v2"))
            .expect("rotate agent"),
        2
    );
    assert_eq!(keys.active_key_version(&alice).expect("active alice"), 2);

    let resolver_v2 = StaticDidResolver::new()
        .with_document(keys.document(&alice).expect("alice v2 document"))
        .with_document(keys.document(&agent).expect("agent v2 document"));
    let alice_doc = resolver_v2.resolve(&alice).expect("alice document");
    assert_eq!(
        alice_doc.authentication[0],
        format!("{alice}#key-signing-v2")
    );
    assert_eq!(
        alice_doc
            .verification_method
            .iter()
            .find(|method| method.id == old_envelope.kid)
            .and_then(|method| method.key_status.as_deref()),
        Some("previous")
    );

    let gateway =
        DidMessageGateway::new(Arc::new(resolver_v2.clone()), Arc::new(keys.clone()), agent);
    let verified = gateway
        .open_prompt(&old_envelope)
        .expect("old envelope remains valid while previous key is advertised");
    assert_eq!(
        verified.resource.resource_id(),
        "prompt/session/rot",
        "old payload opened after sender and recipient rotation"
    );

    let new_envelope = DidEnvelope::prompt(
        "msg-rot-2",
        alice.clone(),
        Did::web("agent.example").expect("agent did"),
        DidMessageBody::infer_prompt("prompt/session/rot-new"),
        "new payload",
        &resolver_v2,
        &keys,
    )
    .expect("new envelope");
    assert_eq!(new_envelope.kid, format!("{alice}#key-signing-v2"));
}

#[test]
fn ed25519_retired_key_rejects_old_signatures() {
    let alice = Did::web("alice-retired.example").expect("alice did");
    let agent = Did::web("agent-retired.example").expect("agent did");
    let mut keys = Ed25519DidKeyStore::new()
        .with_key(alice.clone(), Ed25519DidKey::from_seed(b"alice-retired-v1"))
        .with_key(agent.clone(), Ed25519DidKey::from_seed(b"agent-retired-v1"));
    let resolver_v1 = StaticDidResolver::new()
        .with_document(keys.document(&alice).expect("alice v1 document"))
        .with_document(keys.document(&agent).expect("agent v1 document"));
    let envelope = DidEnvelope::prompt(
        "msg-retired-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/retired"),
        "payload",
        &resolver_v1,
        &keys,
    )
    .expect("envelope");
    let old_method = resolver_v1
        .resolve(&alice)
        .expect("alice document")
        .authentication_key(&envelope.kid)
        .expect("old auth method")
        .clone();

    keys.rotate_key(&alice, Ed25519DidKey::from_seed(b"alice-retired-v2"))
        .expect("rotate alice");
    keys.retire_key(&alice, 1).expect("retire old alice key");

    assert!(matches!(
        keys.verify(&old_method, envelope.signing_input().as_bytes(), &envelope.signature),
        Err(DidError::RetiredKey(method)) if method == old_method.id
    ));
    let rotated_doc = keys.document(&alice).expect("rotated alice document");
    assert!(
        !rotated_doc
            .authentication
            .iter()
            .any(|kid| kid == &envelope.kid)
    );
}

struct AllowAllForTest;
impl PolicyEngine for AllowAllForTest {
    fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
        PolicyResult::Allow
    }
}

#[test]
fn wrapped_prompt_passthrough_keeps_envelope() {
    let (alice, agent, resolver, keys) = fixture();
    let envelope = DidEnvelope::prompt(
        "msg-1",
        alice,
        agent,
        DidMessageBody::infer_prompt("prompt/session/123"),
        "private prompt",
        &resolver,
        &keys,
    )
    .expect("envelope");
    let http = RecordingHttpClient::new().with_response(
        "http://localhost:11434/api/chat",
        json!({ "message": { "content": "ok" } }),
    );
    let client = DidOllamaClient::with_http(
        "http://localhost:11434",
        "codata-did",
        Arc::new(http.clone()),
    );

    client.chat_wrapped_prompt(&envelope).expect("ollama call");

    let requests = http.requests();
    assert_eq!(
        requests[0].body.as_ref().unwrap()["did_envelope"]["ciphertext"],
        envelope.ciphertext
    );
}
