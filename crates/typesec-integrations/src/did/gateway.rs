//! Envelope-verifying gateways and the verified-message/attestation types.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use typesec_core::{SecureValue, resource::GenericResource, secure_value::Secret};

use super::crypto::{hex_decode, unix_time};
use super::document::DidResolver;
use super::envelope::{DidEnvelope, DidMessageBody, DidMessageReference};
use super::error::DidError;
use super::identifier::Did;
use super::keystore::DidKeyStore;
use super::typedid::{TypeDidConversation, TypeDidMode};

/// Verified and decrypted TypeDID agent message.
#[derive(Debug)]
pub struct VerifiedTypeDidMessage {
    /// Verified DID subject.
    pub subject: Did,
    /// Stable reference to the verified envelope.
    pub message_ref: DidMessageReference,
    /// Policy-visible message metadata.
    pub body: DidMessageBody,
    /// TypeDID conversation/profile metadata.
    pub conversation: TypeDidConversation,
    /// Resource associated with the payload.
    pub resource: GenericResource,
    /// Secret opaque payload bytes.
    pub payload: SecureValue<Secret, Vec<u8>, GenericResource>,
}

/// Policy/audit-safe attestation derived from a verified TypeDID message.
///
/// This contains no plaintext payload and no raw signature material. It is the
/// compact boundary object downstream systems can persist after a
/// [`TypeDidGateway`] has verified the envelope signature, recipient, expiry,
/// conversation metadata, and payload authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDidAttestation {
    /// Verified sender DID.
    pub subject: Did,
    /// Stable signed envelope id.
    pub envelope_id: String,
    /// SHA-256 digest of the signed envelope reference.
    pub envelope_digest: String,
    /// Policy-visible requested action.
    pub action: String,
    /// Policy-visible requested resource.
    pub resource: String,
    /// Policy-visible privacy class.
    pub privacy: String,
    /// TypeDID conversation id.
    pub conversation_id: String,
    /// TypeDID transport/protocol family.
    pub protocol: String,
    /// TypeDID delivery mode.
    pub mode: TypeDidMode,
    /// Negotiated TypeDID crypto/profile id.
    pub profile: String,
    /// Conversation expiry time as unix seconds, when supplied by the sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl VerifiedTypeDidMessage {
    /// Return an audit-safe attestation for this verified message.
    pub fn attestation(&self) -> TypeDidAttestation {
        TypeDidAttestation {
            subject: self.subject.clone(),
            envelope_id: self.message_ref.id.clone(),
            envelope_digest: self.message_ref.digest.clone(),
            action: self.body.action.clone(),
            resource: self.body.resource.clone(),
            privacy: self.body.privacy.clone(),
            conversation_id: self.conversation.conversation_id.clone(),
            protocol: self.conversation.protocol.clone(),
            mode: self.conversation.mode,
            profile: self.conversation.profile.clone(),
            expires_at: self.conversation.expires_at,
        }
    }
}

/// Verified and decrypted DID prompt.
#[derive(Debug)]
pub struct VerifiedDidPrompt {
    /// Verified DID subject.
    pub subject: Did,
    /// Stable reference to the verified prompt envelope.
    pub prompt_ref: DidMessageReference,
    /// Policy-visible metadata.
    pub body: DidMessageBody,
    /// Resource associated with the payload.
    pub resource: GenericResource,
    /// Secret prompt payload.
    pub prompt: SecureValue<Secret, String, GenericResource>,
}

/// Verifies DID envelopes and converts encrypted payloads into `SecureValue`s.
pub struct DidMessageGateway {
    resolver: Arc<dyn DidResolver>,
    key_store: Arc<dyn DidKeyStore>,
    recipient: Did,
}

impl DidMessageGateway {
    /// Create a gateway for one local recipient DID.
    pub fn new(
        resolver: Arc<dyn DidResolver>,
        key_store: Arc<dyn DidKeyStore>,
        recipient: Did,
    ) -> Self {
        Self {
            resolver,
            key_store,
            recipient,
        }
    }

    /// Verify, decrypt, and protect a DID prompt envelope.
    pub fn open_prompt(&self, envelope: &DidEnvelope) -> Result<VerifiedDidPrompt, DidError> {
        let opened = self.open_bytes(envelope)?;
        let prompt = String::from_utf8(opened.plaintext).map_err(|_| DidError::InvalidUtf8)?;
        Ok(VerifiedDidPrompt {
            subject: opened.subject,
            prompt_ref: opened.message_ref,
            body: opened.body,
            prompt: SecureValue::protect(prompt, &opened.resource),
            resource: opened.resource,
        })
    }

    pub(super) fn open_bytes(&self, envelope: &DidEnvelope) -> Result<OpenedDidEnvelope, DidError> {
        if !envelope.to.iter().any(|did| did == &self.recipient) {
            return Err(DidError::WrongRecipient(self.recipient.to_string()));
        }
        let now = unix_time();
        if envelope.expires_time < now {
            return Err(DidError::Expired);
        }

        let sender_document = self.resolver.resolve(&envelope.from)?;
        let sender_key = sender_document.authentication_key(&envelope.kid)?;
        self.key_store.verify(
            sender_key,
            envelope.signing_input().as_bytes(),
            &envelope.signature,
        )?;

        // Decryption uses the sender's *key-agreement* key, which may be a
        // different key (X25519) than the authentication key (Ed25519). During
        // key rotation, older in-flight envelopes may have used a previous
        // sender agreement key, so try every non-retired key advertised by the
        // sender document.
        let sender_agreement_keys = sender_document.key_agreement_keys()?;
        let nonce = hex_decode(&envelope.nonce)?;
        let mut plaintext = None;
        for sender_agreement_key in sender_agreement_keys {
            match self.key_store.decrypt_for(
                &self.recipient,
                &sender_agreement_key.public_key()?,
                &nonce,
                &envelope.ciphertext,
            ) {
                Ok(opened) => {
                    plaintext = Some(opened);
                    break;
                }
                Err(DidError::DecryptionFailed) => {}
                Err(err) => return Err(err),
            }
        }
        let plaintext = plaintext.ok_or(DidError::DecryptionFailed)?;
        let resource = GenericResource::new(&envelope.body.resource, "did-prompt");

        Ok(OpenedDidEnvelope {
            subject: envelope.from.clone(),
            message_ref: envelope.reference(),
            body: envelope.body.clone(),
            resource,
            plaintext,
        })
    }
}

#[derive(Debug)]
pub(super) struct OpenedDidEnvelope {
    pub(super) subject: Did,
    pub(super) message_ref: DidMessageReference,
    pub(super) body: DidMessageBody,
    pub(super) resource: GenericResource,
    pub(super) plaintext: Vec<u8>,
}

/// Verifies TypeDID envelopes and protects arbitrary agent payload bytes.
pub struct TypeDidGateway {
    inner: DidMessageGateway,
}

impl TypeDidGateway {
    /// Create a TypeDID gateway for one local recipient DID.
    pub fn new(
        resolver: Arc<dyn DidResolver>,
        key_store: Arc<dyn DidKeyStore>,
        recipient: Did,
    ) -> Self {
        Self {
            inner: DidMessageGateway::new(resolver, key_store, recipient),
        }
    }

    /// Verify, decrypt, and protect a TypeDID message envelope.
    pub fn open_message(&self, envelope: &DidEnvelope) -> Result<VerifiedTypeDidMessage, DidError> {
        let conversation = envelope
            .typedid
            .clone()
            .ok_or(DidError::MissingTypeDidMetadata)?;
        let opened = self.inner.open_bytes(envelope)?;
        Ok(VerifiedTypeDidMessage {
            subject: opened.subject,
            message_ref: opened.message_ref,
            body: opened.body,
            conversation,
            payload: SecureValue::protect(opened.plaintext, &opened.resource),
            resource: opened.resource,
        })
    }
}
