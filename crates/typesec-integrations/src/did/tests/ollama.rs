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
