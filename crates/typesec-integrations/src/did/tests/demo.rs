use std::sync::Arc;

use serde_json::json;
use typesec_core::{
    Resource, SecureValue,
    permissions::{AiCanInfer, CanReadSensitive},
    policy::mint_capability,
    resource::GenericResource,
    secure_value::Secret,
};

use super::super::*;
use super::common::*;
use crate::http::RecordingHttpClient;

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
fn replayed_envelope_is_rejected() {
    let (alice, agent, resolver, keys) = fixture();
    let envelope = DidEnvelope::prompt(
        "msg-replay",
        alice,
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/replay"),
        "one-shot payload",
        &resolver,
        &keys,
    )
    .expect("envelope");

    let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    gateway.open_prompt(&envelope).expect("first open succeeds");
    assert!(
        matches!(gateway.open_prompt(&envelope), Err(DidError::Replayed(_))),
        "re-opening the same envelope must be rejected as a replay"
    );
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
