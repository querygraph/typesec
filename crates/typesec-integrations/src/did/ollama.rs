//! Ollama client that can send verified DID prompts.

use std::sync::Arc;

use serde_json::{Value, json};
use typesec_core::{
    Capability,
    permissions::{AiCanInfer, CanReadSensitive},
    resource::GenericResource,
};

use crate::http::{HttpClient, ReqwestHttpClient};

use super::crypto::sha256_tagged;
use super::document::DidResolver;
use super::envelope::{DidEnvelope, DidReplyBinding};
use super::error::DidError;
use super::gateway::VerifiedDidPrompt;
use super::identifier::Did;
use super::keystore::DidKeyStore;

/// Ollama client that can send verified DID prompts.
pub struct DidOllamaClient {
    base_url: String,
    model: String,
    http: Arc<dyn HttpClient>,
}

impl DidOllamaClient {
    /// Create an Ollama client using reqwest.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self::with_http(base_url, model, Arc::new(ReqwestHttpClient::new()))
    }

    /// Create an Ollama client with an injected HTTP client.
    pub fn with_http(
        base_url: impl Into<String>,
        model: impl Into<String>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            model: model.into(),
            http,
        }
    }

    /// The `/api/chat` endpoint for this client's base URL.
    fn chat_endpoint(&self) -> String {
        format!("{}/api/chat", self.base_url)
    }

    /// A non-streaming single-user-turn chat request body.
    fn chat_body(&self, content: &str) -> Value {
        json!({
            "model": self.model,
            "stream": false,
            "messages": [{
                "role": "user",
                "content": content
            }]
        })
    }

    /// POST a chat request and map a transport failure to [`DidError::Http`].
    fn post_chat(&self, body: &Value) -> Result<Value, DidError> {
        self.http
            .post_json(&self.chat_endpoint(), &[], body)
            .map_err(DidError::Http)
    }

    /// Reveal a verified prompt under typed authority and send it to Ollama.
    pub fn chat_verified_prompt(
        &self,
        prompt: VerifiedDidPrompt,
        _infer: &Capability<AiCanInfer, GenericResource>,
        read: &Capability<CanReadSensitive, GenericResource>,
    ) -> Result<Value, DidError> {
        let plaintext = prompt.prompt.reveal(read)?;
        self.post_chat(&self.chat_body(&plaintext))
    }

    /// Send a verified prompt to Ollama and bind the assistant reply to it.
    pub fn chat_verified_prompt_bound(
        &self,
        prompt: VerifiedDidPrompt,
        reply_from: Did,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
        _infer: &Capability<AiCanInfer, GenericResource>,
        read: &Capability<CanReadSensitive, GenericResource>,
    ) -> Result<DidEnvelope, DidError> {
        let reply_to = prompt.subject.clone();
        let binding = DidReplyBinding::for_prompt(&prompt);
        let plaintext = prompt.prompt.reveal(read)?;
        let response = self.post_chat(&self.chat_body(&plaintext))?;
        let reply = ollama_reply_content(&response)?;
        let reply_did = Did::key(sha256_tagged(
            b"typesec-did-ollama-reply",
            format!("{}\n{}", binding.prompt_ref.digest, reply).as_bytes(),
        ));
        DidEnvelope::reply(
            reply_did, reply_from, reply_to, binding, reply, resolver, key_store,
        )
    }

    /// Forward an already wrapped DID prompt to a DID-aware Ollama fork.
    pub fn chat_wrapped_prompt(&self, envelope: &DidEnvelope) -> Result<Value, DidError> {
        let body = json!({
            "model": self.model,
            "stream": false,
            "did_envelope": envelope
        });
        self.post_chat(&body)
    }
}

fn ollama_reply_content(response: &Value) -> Result<&str, DidError> {
    response
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .ok_or(DidError::MissingOllamaReply)
}
