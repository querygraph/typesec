//! TypeDID conversation/profile negotiation and secure-envelope transport
//! adapters.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::crypto::{contains, intersects};
use super::document::DidResolver;
use super::envelope::{DidEnvelope, DidMessageBody};
use super::error::DidError;
use super::identifier::Did;
use super::keystore::DidKeyStore;

/// TypeDID delivery mode for an agent message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeDidMode {
    /// Fire-and-forget delivery; no TypeDID reply is required.
    Send,
    /// The receiver is expected to answer with a reply-bound TypeDID envelope.
    RequestReply,
}

/// TypeDID conversation metadata bound into the envelope signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDidConversation {
    /// Stable task, session, room, or thread id from the outer protocol.
    pub conversation_id: String,
    /// Delivery mode.
    pub mode: TypeDidMode,
    /// Negotiated TypeDID profile id.
    pub profile: String,
    /// Outer protocol hint, such as `a2a`, `acp`, `band`, or `https`.
    pub protocol: String,
    /// Optional payload expiry copied from the negotiated profile or caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl TypeDidConversation {
    /// Construct TypeDID conversation metadata.
    pub fn new(
        conversation_id: impl Into<String>,
        mode: TypeDidMode,
        profile: impl Into<String>,
        protocol: impl Into<String>,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            mode,
            profile: profile.into(),
            protocol: protocol.into(),
            expires_at: None,
        }
    }

    /// Attach an absolute unix-seconds expiry to this conversation metadata.
    pub fn with_expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

/// A negotiable TypeDID security profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDidProfile {
    /// Stable profile id.
    pub id: String,
    /// Supported DID methods, such as `did:web` or `did:key`.
    #[serde(default)]
    pub did_methods: Vec<String>,
    /// Supported signing algorithms.
    #[serde(default)]
    pub signing: Vec<String>,
    /// Supported key-agreement algorithms.
    #[serde(default)]
    pub key_agreement: Vec<String>,
    /// Supported encryption profiles.
    #[serde(default)]
    pub encryption: Vec<String>,
    /// Supported outer transport bindings.
    #[serde(default)]
    pub transport_bindings: Vec<String>,
    /// Supported TypeDID send modes.
    #[serde(default)]
    pub modes: Vec<TypeDidMode>,
    /// Optional maximum encrypted payload size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<usize>,
    /// Claims required by the remote boundary.
    #[serde(default)]
    pub required_claims: Vec<String>,
    /// Policy actions this profile is willing to carry.
    #[serde(default)]
    pub policy_actions: Vec<String>,
    /// Retention posture advertised by the receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<String>,
    /// Audit posture advertised by the receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<String>,
}

impl TypeDidProfile {
    /// Default local TypeDID profile backed by the built-in Ed25519/X25519
    /// key store.
    pub fn ed25519_x25519_chacha20() -> Self {
        Self {
            id: "typedid/v1/x25519-chacha20poly1305-ed25519".to_owned(),
            did_methods: vec![
                "did:web".to_owned(),
                "did:key".to_owned(),
                "did:indy".to_owned(),
            ],
            signing: vec!["Ed25519".to_owned()],
            key_agreement: vec!["X25519".to_owned()],
            encryption: vec!["ChaCha20-Poly1305".to_owned()],
            transport_bindings: vec![
                "a2a".to_owned(),
                "acp".to_owned(),
                "band".to_owned(),
                "https".to_owned(),
                "websocket".to_owned(),
            ],
            modes: vec![TypeDidMode::Send, TypeDidMode::RequestReply],
            max_payload_bytes: Some(1024 * 1024),
            required_claims: vec![
                "org".to_owned(),
                "agent_id".to_owned(),
                "purpose".to_owned(),
            ],
            policy_actions: vec![
                "agent:message".to_owned(),
                "agent:delegate".to_owned(),
                "ai:infer".to_owned(),
            ],
            retention: Some("sender-encrypted-payload-only".to_owned()),
            audit: Some("envelope-metadata-and-policy-decision".to_owned()),
        }
    }

    /// Return true when this local profile can safely communicate with `remote`.
    pub fn is_compatible_with(&self, remote: &Self, protocol: &str, mode: TypeDidMode) -> bool {
        self.id == remote.id
            && contains(&self.transport_bindings, protocol)
            && contains(&remote.transport_bindings, protocol)
            && self.modes.contains(&mode)
            && remote.modes.contains(&mode)
            && intersects(&self.did_methods, &remote.did_methods)
            && intersects(&self.signing, &remote.signing)
            && intersects(&self.key_agreement, &remote.key_agreement)
            && intersects(&self.encryption, &remote.encryption)
    }

    /// Select the first local profile compatible with the remote boundary.
    pub fn negotiate<'a>(
        local: &'a [Self],
        remote: &[Self],
        protocol: &str,
        mode: TypeDidMode,
    ) -> Result<&'a Self, DidError> {
        local
            .iter()
            .find(|candidate| {
                remote
                    .iter()
                    .any(|other| candidate.is_compatible_with(other, protocol, mode))
            })
            .ok_or(DidError::NoCompatibleTypeDidProfile)
    }
}

/// Resolves TypeDID profiles for a remote agent or boundary.
pub trait TypeDidProfileResolver: Send + Sync {
    /// Resolve profiles advertised by `target`.
    fn resolve_profiles(&self, target: &str) -> Result<Vec<TypeDidProfile>, DidError>;
}

/// In-memory TypeDID profile resolver for examples and tests.
#[derive(Debug, Default, Clone)]
pub struct StaticTypeDidProfileResolver {
    profiles: HashMap<String, Vec<TypeDidProfile>>,
}

impl StaticTypeDidProfileResolver {
    /// Create an empty profile resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register profiles for a target DID, contact, agent card, or endpoint.
    pub fn with_profiles(
        mut self,
        target: impl Into<String>,
        profiles: Vec<TypeDidProfile>,
    ) -> Self {
        self.profiles.insert(target.into(), profiles);
        self
    }
}

impl TypeDidProfileResolver for StaticTypeDidProfileResolver {
    fn resolve_profiles(&self, target: &str) -> Result<Vec<TypeDidProfile>, DidError> {
        self.profiles
            .get(target)
            .cloned()
            .ok_or_else(|| DidError::Unresolved(target.to_owned()))
    }
}

/// Common interface for TypeDID secure-envelope transport adapters.
pub trait SecureEnvelopeAdapter {
    /// Adapter protocol name.
    fn protocol(&self) -> &str;

    /// Media type this adapter carries over its outer protocol.
    fn content_type(&self) -> &'static str {
        "application/vnd.typedid.envelope+json"
    }

    /// Wrap a payload in a TypeDID envelope for this adapter's protocol.
    fn wrap(
        &self,
        request: TypeDidWrapRequest<'_>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<DidEnvelope, DidError> {
        let profile = TypeDidProfile::negotiate(
            request.local_profiles,
            request.remote_profiles,
            self.protocol(),
            request.mode,
        )?;
        let conversation = TypeDidConversation::new(
            request.conversation_id,
            request.mode,
            profile.id.clone(),
            self.protocol(),
        );
        DidEnvelope::typedid(
            request.id,
            request.from,
            request.to,
            request.body,
            conversation,
            request.payload,
            resolver,
            key_store,
        )
    }
}

/// Inputs for wrapping a payload in a TypeDID transport adapter.
pub struct TypeDidWrapRequest<'a> {
    /// Envelope id.
    pub id: String,
    /// Sender DID.
    pub from: Did,
    /// Recipient DID.
    pub to: Did,
    /// Outer conversation/task/room/session id.
    pub conversation_id: String,
    /// Send mode.
    pub mode: TypeDidMode,
    /// Policy-visible body.
    pub body: DidMessageBody,
    /// Plaintext payload bytes.
    pub payload: &'a [u8],
    /// Local TypeDID profiles.
    pub local_profiles: &'a [TypeDidProfile],
    /// Remote TypeDID profiles.
    pub remote_profiles: &'a [TypeDidProfile],
}

/// A2A TypeDID content adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct A2aTypeDidAdapter;

impl SecureEnvelopeAdapter for A2aTypeDidAdapter {
    fn protocol(&self) -> &str {
        "a2a"
    }
}

/// ACP TypeDID content adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcpTypeDidAdapter;

impl SecureEnvelopeAdapter for AcpTypeDidAdapter {
    fn protocol(&self) -> &str {
        "acp"
    }
}

/// BAND secure-envelope adapter for TypeDID payloads.
#[derive(Debug, Default, Clone, Copy)]
pub struct BandSecureEnvelopeAdapter;

impl SecureEnvelopeAdapter for BandSecureEnvelopeAdapter {
    fn protocol(&self) -> &str {
        "band"
    }
}

/// Direct HTTPS TypeDID content adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpTypeDidAdapter;

impl SecureEnvelopeAdapter for HttpTypeDidAdapter {
    fn protocol(&self) -> &str {
        "https"
    }
}
