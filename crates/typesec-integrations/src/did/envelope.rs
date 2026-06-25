//! DID message bodies, references, and the encrypted envelope type.

use serde::{Deserialize, Serialize};

use super::crypto::{
    canonical_typedid_conversation, hex_encode, random_nonce, sha256_tagged, unix_time,
};
use super::document::DidResolver;
use super::error::DidError;
use super::gateway::{VerifiedDidPrompt, VerifiedTypeDidMessage};
use super::identifier::Did;
use super::keystore::DidKeyStore;
use super::typedid::{TypeDidConversation, TypeDidMode};

/// Message metadata that policy engines evaluate before payload use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidMessageBody {
    /// Requested Typesec action, such as `ai:infer`.
    pub action: String,
    /// Resource identifier for policy evaluation.
    pub resource: String,
    /// Payload privacy label, such as `secret`.
    pub privacy: String,
    /// Prompt envelope this message is bound to, for reply envelopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<DidMessageReference>,
}

impl DidMessageBody {
    /// Create a prompt body for AI inference.
    pub fn infer_prompt(resource: impl Into<String>) -> Self {
        Self {
            action: "ai:infer".to_owned(),
            resource: resource.into(),
            privacy: "secret".to_owned(),
            reply_to: None,
        }
    }

    /// Create a reply body that inherits the prompt's policy-visible metadata.
    pub fn reply_to_prompt(prompt: &VerifiedDidPrompt) -> Self {
        Self {
            action: prompt.body.action.clone(),
            resource: prompt.body.resource.clone(),
            privacy: prompt.body.privacy.clone(),
            reply_to: Some(prompt.prompt_ref.clone()),
        }
    }

    /// Create a general agent message body.
    pub fn agent_message(resource: impl Into<String>, privacy: impl Into<String>) -> Self {
        Self {
            action: "agent:message".to_owned(),
            resource: resource.into(),
            privacy: privacy.into(),
            reply_to: None,
        }
    }

    /// Create an agent delegation body.
    pub fn agent_delegate(resource: impl Into<String>, privacy: impl Into<String>) -> Self {
        Self {
            action: "agent:delegate".to_owned(),
            resource: resource.into(),
            privacy: privacy.into(),
            reply_to: None,
        }
    }
}

/// The prompt context a reply envelope is bound to.
#[derive(Debug, Clone)]
pub struct DidReplyBinding {
    /// Policy-visible metadata of the prompt being answered.
    pub prompt_body: DidMessageBody,
    /// Stable reference to the signed prompt envelope.
    pub prompt_ref: DidMessageReference,
}

impl DidReplyBinding {
    /// Bind a reply to a verified prompt.
    pub fn for_prompt(prompt: &VerifiedDidPrompt) -> Self {
        Self {
            prompt_body: prompt.body.clone(),
            prompt_ref: prompt.prompt_ref.clone(),
        }
    }
}

/// Stable reference to a DID message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidMessageReference {
    /// Referenced DID message id.
    pub id: String,
    /// SHA-256 digest of the referenced signed envelope.
    pub digest: String,
}

/// Encrypted DID message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidEnvelope {
    /// Message id.
    pub id: String,
    /// Message type URI.
    #[serde(rename = "type")]
    pub message_type: String,
    /// Sender DID.
    pub from: Did,
    /// Recipient DIDs.
    pub to: Vec<Did>,
    /// Creation time as unix seconds.
    pub created_time: u64,
    /// Expiration time as unix seconds.
    pub expires_time: u64,
    /// Policy-visible message metadata.
    pub body: DidMessageBody,
    /// Optional TypeDID conversation/profile metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typedid: Option<TypeDidConversation>,
    /// Key id used for authentication.
    pub kid: String,
    /// Hex-encoded nonce.
    pub nonce: String,
    /// Hex-encoded ciphertext.
    pub ciphertext: String,
    /// Hex-encoded signature over the envelope signing input.
    pub signature: String,
}

impl DidEnvelope {
    /// Create an encrypted prompt envelope.
    pub fn prompt(
        id: impl Into<String>,
        from: Did,
        to: Did,
        body: DidMessageBody,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let id = id.into();
        let now = unix_time();
        let recipient_document = resolver.resolve(&to)?;
        let recipient_key = recipient_document.key_agreement_key()?;
        let sender_document = resolver.resolve(&from)?;
        let kid = sender_document
            .authentication
            .first()
            .cloned()
            .ok_or(DidError::MissingAuthentication)?;
        let nonce = random_nonce()?;
        let ciphertext = key_store.encrypt_for(
            &from,
            &recipient_key.public_key()?,
            plaintext.as_ref(),
            &nonce,
        )?;
        let mut envelope = Self {
            id,
            message_type: "https://typesec.dev/did/message/v1/prompt".to_owned(),
            from,
            to: vec![to],
            created_time: now,
            expires_time: now + 300,
            body,
            typedid: None,
            kid,
            nonce: hex_encode(&nonce),
            ciphertext,
            signature: String::new(),
        };
        envelope.signature = key_store.sign(&envelope.from, envelope.signing_input().as_bytes())?;
        Ok(envelope)
    }

    /// Create an encrypted reply envelope bound to a verified prompt envelope.
    pub fn reply(
        reply_did: Did,
        from: Did,
        to: Did,
        binding: DidReplyBinding,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let DidReplyBinding {
            prompt_body,
            prompt_ref,
        } = binding;
        let now = unix_time();
        let recipient_document = resolver.resolve(&to)?;
        let recipient_key = recipient_document.key_agreement_key()?;
        let sender_document = resolver.resolve(&from)?;
        let kid = sender_document
            .authentication
            .first()
            .cloned()
            .ok_or(DidError::MissingAuthentication)?;
        let id = reply_did.to_string();
        let nonce = random_nonce()?;
        let ciphertext = key_store.encrypt_for(
            &from,
            &recipient_key.public_key()?,
            plaintext.as_ref(),
            &nonce,
        )?;
        let mut envelope = Self {
            id,
            message_type: "https://typesec.dev/did/message/v1/reply".to_owned(),
            from,
            to: vec![to],
            created_time: now,
            expires_time: now + 300,
            body: DidMessageBody {
                action: prompt_body.action.clone(),
                resource: prompt_body.resource.clone(),
                privacy: prompt_body.privacy.clone(),
                reply_to: Some(prompt_ref),
            },
            typedid: None,
            kid,
            nonce: hex_encode(&nonce),
            ciphertext,
            signature: String::new(),
        };
        envelope.signature = key_store.sign(&envelope.from, envelope.signing_input().as_bytes())?;
        Ok(envelope)
    }

    /// Create an encrypted TypeDID agent-message envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn typedid(
        id: impl Into<String>,
        from: Did,
        to: Did,
        body: DidMessageBody,
        typedid: TypeDidConversation,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let mut envelope = Self::prompt(id, from, to, body, plaintext, resolver, key_store)?;
        envelope.message_type = "https://typesec.dev/did/message/v1/typedid".to_owned();
        envelope.typedid = Some(typedid);
        envelope.signature = key_store.sign(&envelope.from, envelope.signing_input().as_bytes())?;
        Ok(envelope)
    }

    /// Create an encrypted TypeDID reply envelope bound to a verified request.
    pub fn typedid_reply(
        id: impl Into<String>,
        from: Did,
        to: Did,
        request: &VerifiedTypeDidMessage,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let mut body = request.body.clone();
        body.reply_to = Some(request.message_ref.clone());
        let conversation = TypeDidConversation {
            conversation_id: request.conversation.conversation_id.clone(),
            mode: TypeDidMode::RequestReply,
            profile: request.conversation.profile.clone(),
            protocol: request.conversation.protocol.clone(),
            expires_at: request.conversation.expires_at,
        };
        Self::typedid(
            id,
            from,
            to,
            body,
            conversation,
            plaintext,
            resolver,
            key_store,
        )
    }

    /// Stable reference to this signed envelope for reply binding.
    pub fn reference(&self) -> DidMessageReference {
        let seed = format!("{}\n{}", self.signing_input(), self.signature);
        DidMessageReference {
            id: self.id.clone(),
            digest: hex_encode(&sha256_tagged(
                b"typesec-did-envelope-reference",
                seed.as_bytes(),
            )),
        }
    }

    /// Canonical bytes the sender signs and the recipient verifies.
    ///
    /// This MUST cover every security-relevant field of the envelope. In
    /// particular `kid` (which key authenticates the sender) and `nonce` (which
    /// drives the AEAD) are included so they cannot be swapped without breaking
    /// the signature. When adding a field to [`DidEnvelope`], add it here too.
    pub(super) fn signing_input(&self) -> String {
        let reply_to = self
            .body
            .reply_to
            .as_ref()
            .map(|reference| format!("{}\n{}", reference.id, reference.digest))
            .unwrap_or_default();
        let base = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.id,
            self.message_type,
            self.from,
            self.to
                .iter()
                .map(Did::as_str)
                .collect::<Vec<_>>()
                .join(","),
            self.created_time,
            self.expires_time,
            self.body.action,
            self.body.resource,
            self.body.privacy,
            reply_to,
            self.kid,
            self.nonce,
        );
        if let Some(typedid) = self.typedid.as_ref() {
            format!(
                "{}\n{}\n{}",
                base,
                canonical_typedid_conversation(typedid),
                self.ciphertext
            )
        } else {
            format!("{}\n{}", base, self.ciphertext)
        }
    }
}
