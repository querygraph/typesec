use std::sync::Arc;

use serde_json::json;
use typesec_core::{
    permissions::{AiCanInfer, CanReadSensitive},
    policy::mint_capability,
};

use super::super::*;
use super::common::*;
use crate::http::RecordingHttpClient;

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
fn did_ollama_bound_reply_requires_assistant_content() {
    let (alice, agent, resolver, keys) = fixture();
    let envelope = DidEnvelope::prompt(
        "msg-missing-reply",
        alice,
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/123"),
        "private prompt",
        &resolver,
        &keys,
    )
    .expect("envelope");
    // A second fixture supplies the reply path's resolver/key store; the call
    // errors on the missing assistant content before ever using them.
    let (_a2, reply_from, resolver2, keys2) = fixture();
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

    // Ollama answers with no `message.content` field.
    let http =
        RecordingHttpClient::new().with_response("http://localhost:11434/api/chat", json!({}));
    let client = DidOllamaClient::with_http("http://localhost:11434", "llama3.2", Arc::new(http));

    let result =
        client.chat_verified_prompt_bound(verified, reply_from, &resolver2, &keys2, &infer, &read);
    assert!(matches!(result, Err(DidError::MissingOllamaReply)));
}
