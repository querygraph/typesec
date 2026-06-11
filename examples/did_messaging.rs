//! # DID Messaging Example
//!
//! Demonstrates a DID-wrapped encrypted prompt flowing into Typesec:
//!
//! 1. Build local DID documents for a sender and model gateway.
//! 2. Encrypt and sign a prompt envelope.
//! 3. Verify/decrypt it into `SecureValue<Secret, String, GenericResource>`.
//! 4. Mint `AiCanInfer` and `CanReadSensitive` capabilities.
//! 5. Send the revealed prompt to an Ollama-shaped HTTP endpoint.
//!
//! The example uses `DemoDidKeyStore` and mocked HTTP. It does not use
//! production cryptography and does not require a live Ollama server.

use std::sync::Arc;

use serde_json::json;
use typesec_core::{
    Capability, PolicyEngine, Resource,
    permissions::{AiCanInfer, CanReadSensitive},
    policy::{PolicyResult, mint_capability},
    resource::GenericResource,
};
use typesec_integrations::{
    DemoDidKeyPair, DemoDidKeyStore, Did, DidDocument, DidEnvelope, DidMessageBody,
    DidMessageGateway, DidOllamaClient, StaticDidResolver, http::RecordingHttpClient,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== typesec DID Messaging Demo ===\n");

    let alice = Did::key(b"alice");
    let gateway_did = Did::key(b"typesec-ollama-gateway");

    let alice_key = DemoDidKeyPair::from_seed(b"alice");
    let gateway_key = DemoDidKeyPair::from_seed(b"typesec-ollama-gateway");

    let resolver = StaticDidResolver::new()
        .with_document(DidDocument::single_key(
            alice.clone(),
            alice_key.public_key.clone(),
        ))
        .with_document(DidDocument::single_key(
            gateway_did.clone(),
            gateway_key.public_key.clone(),
        ));

    let key_store = DemoDidKeyStore::new()
        .with_key(alice.clone(), alice_key)
        .with_key(gateway_did.clone(), gateway_key);

    let envelope = DidEnvelope::prompt(
        "prompt-msg-1",
        alice.clone(),
        gateway_did.clone(),
        DidMessageBody::infer_prompt("prompt/session/123"),
        "Summarize this confidential report without exposing raw customer data.",
        &resolver,
        &key_store,
    )?;

    println!("sender:     {alice}");
    println!("recipient:  {gateway_did}");
    println!("resource:   {}", envelope.body.resource);
    println!("ciphertext: {}...", &envelope.ciphertext[..24]);

    let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(key_store), gateway_did);
    let verified = gateway.open_prompt(&envelope)?;
    println!("verified:   {}", verified.subject);

    let policy = PromptPolicy;
    let infer: Capability<AiCanInfer, GenericResource> =
        mint_capability(&policy, verified.subject.as_str(), &verified.resource)?;
    let read: Capability<CanReadSensitive, GenericResource> =
        mint_capability(&policy, verified.subject.as_str(), &verified.resource)?;
    println!(
        "caps:       {} and {} on {}",
        Capability::<AiCanInfer, GenericResource>::permission_name(),
        Capability::<CanReadSensitive, GenericResource>::permission_name(),
        verified.resource.resource_id()
    );

    let http = RecordingHttpClient::new().with_response(
        "http://localhost:11434/api/chat",
        json!({
            "message": {
                "role": "assistant",
                "content": "Confidential report summarized under Typesec policy."
            }
        }),
    );
    let ollama =
        DidOllamaClient::with_http("http://localhost:11434", "llama3.2", Arc::new(http.clone()));
    let response = ollama.chat_verified_prompt(verified, &infer, &read)?;

    println!("ollama:     {}", response["message"]["content"]);
    println!("requests:   {}", http.requests().len());
    println!("\n=== Demo complete ===");

    Ok(())
}

struct PromptPolicy;

impl PolicyEngine for PromptPolicy {
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        if subject == "did:key:z616c696365"
            && matches!(action, "ai:infer" | "read_sensitive")
            && resource == "prompt/session/123"
        {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny(format!("{subject} may not {action} {resource}"))
        }
    }
}
