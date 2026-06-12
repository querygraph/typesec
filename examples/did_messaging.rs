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
//! The example uses `Ed25519DidKeyStore` (Ed25519 signatures, X25519 key
//! agreement, ChaCha20-Poly1305 encryption) with mocked HTTP. It does not
//! require a live Ollama server.

use std::sync::Arc;

use serde_json::json;
use typesec_core::{
    Capability, PolicyEngine, Resource,
    permissions::{AiCanInfer, CanReadSensitive},
    policy::{PolicyResult, mint_capability},
    resource::GenericResource,
};
use typesec_integrations::{
    Did, DidEnvelope, DidMessageBody, DidMessageGateway, DidOllamaClient, Ed25519DidKey,
    Ed25519DidKeyStore, StaticDidResolver, http::RecordingHttpClient,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== typesec DID Messaging Demo ===\n");

    // Deterministic keys keep the demo reproducible; use
    // `Ed25519DidKey::generate()` for real deployments.
    let alice_key = Ed25519DidKey::from_seed(b"alice");
    let gateway_key = Ed25519DidKey::from_seed(b"typesec-ollama-gateway");

    let alice = Did::key(alice_key.signing_public());
    let gateway_did = Did::key(gateway_key.signing_public());

    let resolver = StaticDidResolver::new()
        .with_document(alice_key.document(alice.clone()))
        .with_document(gateway_key.document(gateway_did.clone()));

    let key_store = Ed25519DidKeyStore::new()
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

    let gateway = DidMessageGateway::new(
        Arc::new(resolver.clone()),
        Arc::new(key_store.clone()),
        gateway_did.clone(),
    );
    let verified = gateway.open_prompt(&envelope)?;
    println!("verified:   {}", verified.subject);

    let policy = PromptPolicy {
        allowed_subject: alice.to_string(),
    };
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
    let reply = ollama.chat_verified_prompt_bound(
        verified,
        gateway_did,
        &resolver,
        &key_store,
        &infer,
        &read,
    )?;

    println!("reply did:  {}", reply.id);
    println!(
        "reply to:   {}",
        reply
            .body
            .reply_to
            .as_ref()
            .map(|reference| reference.id.as_str())
            .unwrap_or("<missing>")
    );
    println!("requests:   {}", http.requests().len());
    println!("\n=== Demo complete ===");

    Ok(())
}

struct PromptPolicy {
    allowed_subject: String,
}

impl PolicyEngine for PromptPolicy {
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        if subject == self.allowed_subject
            && matches!(action, "ai:infer" | "read_sensitive")
            && resource == "prompt/session/123"
        {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny(format!("{subject} may not {action} {resource}"))
        }
    }
}
