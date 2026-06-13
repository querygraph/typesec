//! # Agent typestate
//!
//! Rust's typestate pattern encodes state machine transitions in the type system.
//! An [`Agent<Unauthenticated>`] has no `request_capability` method — it
//! literally doesn't exist. You *must* call [`Agent::authenticate_with`]
//! (or, for tests and demos, [`Agent::authenticate_unverified`]) first, which
//! returns `Agent<Authenticated>`. Only then do the capability-requesting
//! methods become available.
//!
//! This prevents entire classes of bugs:
//! - An unauthenticated agent can't accidentally bypass auth by skipping the check.
//! - Code that accepts `Agent<Authenticated>` cannot be called with an
//!   `Agent<Unauthenticated>` — the types are incompatible.
//!
//! ## Sealed states
//!
//! The [`AgentState`] trait is sealed: external crates cannot create new states.
//! This means the only valid states are `Unauthenticated` and `Authenticated` —
//! there's no way to synthesise a fake `SuperAuthorized` state.

use std::sync::Arc;

use crate::policy::PolicyEngine;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sealed state trait for the [`Agent`] typestate machine.
///
/// Only `Unauthenticated` and `Authenticated` implement this — by design.
pub trait AgentState: private::Sealed + Send + Sync + 'static {}

mod private {
    /// Sealing trait — not exported, so nothing outside this module can implement it.
    pub trait Sealed {}
}

/// The initial agent state. No policy operations are available yet.
#[derive(Debug)]
pub struct Unauthenticated;

/// Authenticated state. Policy checks and capability requests become available.
#[derive(Debug)]
pub struct Authenticated;

impl private::Sealed for Unauthenticated {}
impl private::Sealed for Authenticated {}
impl AgentState for Unauthenticated {}
impl AgentState for Authenticated {}

/// A bearer secret (API key, signed JWT, etc.) that must not leak into logs.
///
/// Like [`SecureValue`][crate::SecureValue], `Token` redacts its contents from
/// `Debug` output and implements neither `Display` nor `PartialEq` — equality
/// against a guessed string would be a brute-force oracle, and verifiers should
/// check tokens cryptographically, not by comparison. Use
/// [`expose`][Self::expose] at the single point where the raw secret is handed
/// to a verifier.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Token(String);

impl Token {
    /// Wrap a raw secret string.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The raw secret, for handing to a credential verifier.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the token is empty (no secret was supplied).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<S: Into<String>> From<S> for Token {
    fn from(secret: S) -> Self {
        Self::new(secret)
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// Credentials used to authenticate an agent.
#[derive(Debug, Clone, Zeroize)]
pub struct Credentials {
    /// The agent's claimed identity.
    pub subject: String,
    /// An opaque bearer secret — validation is application-specific. Redacted
    /// from `Debug` output; call [`Token::expose`] to read it.
    pub token: Token,
}

impl Credentials {
    /// Create credentials with the given subject and token.
    pub fn new(subject: impl Into<String>, token: impl Into<Token>) -> Self {
        Self {
            subject: subject.into(),
            token: token.into(),
        }
    }
}

/// Verifies credentials and returns the canonical subject identity.
///
/// This is the trust root of the typestate machine: the subject string returned
/// here is what every subsequent policy check and minted capability is bound to.
/// Implementations should verify the token cryptographically (e.g.
/// `JwtAuthenticator` in `typesec-integrations`) — never trust the *claimed*
/// subject without checking it against the verified identity.
pub trait Authenticator: Send + Sync {
    /// Verify `credentials`, returning the verified subject on success.
    fn verify_credentials(&self, credentials: &Credentials) -> Result<String, AgentError>;
}

/// Error types for agent operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    /// Authentication failed.
    #[error("authentication failed: {reason}")]
    AuthFailed {
        /// Human-readable explanation.
        reason: String,
    },
    /// A capability request failed (policy denied or engine error).
    #[error("capability request failed: {0}")]
    Capability(#[from] crate::policy::CapabilityError),
}

/// An agent with a typestate parameter `S` and an attached policy engine.
///
/// - `S = Unauthenticated` — agent has been constructed but not yet authenticated.
/// - `S = Authenticated` — agent has authenticated; capability requests are allowed.
///
/// The policy engine is stored as a trait object so agents can be composed with
/// different engines (RBAC, ODRL, composed) at runtime.
pub struct Agent<S: AgentState> {
    /// The agent's authenticated identity.
    /// `None` in `Unauthenticated` state.
    pub(crate) subject: Option<String>,
    /// Policy engine used for capability checks.
    pub(crate) engine: Arc<dyn PolicyEngine>,
    /// Zero-sized phantom state parameter.
    _state: std::marker::PhantomData<S>,
}

impl<S: AgentState> std::fmt::Debug for Agent<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("subject", &self.subject)
            .field("state", &std::any::type_name::<S>())
            .finish_non_exhaustive()
    }
}

impl Agent<Unauthenticated> {
    /// Create a new unauthenticated agent with the given policy engine.
    pub fn new(engine: Arc<dyn PolicyEngine>) -> Self {
        Self {
            subject: None,
            engine,
            _state: std::marker::PhantomData,
        }
    }

    /// Authenticate the agent against a credential verifier.
    ///
    /// The [`Authenticator`] verifies the token and returns the canonical
    /// subject — the verified identity, not the claimed one — which becomes
    /// the subject for every policy check and minted capability. This is the
    /// path production code should take from `Unauthenticated` to
    /// `Authenticated`; the transition is irreversible at the type level.
    pub fn authenticate_with(
        self,
        credentials: Credentials,
        authenticator: &dyn Authenticator,
    ) -> Result<Agent<Authenticated>, AgentError> {
        let subject = authenticator.verify_credentials(&credentials)?;
        if subject.is_empty() {
            return Err(AgentError::AuthFailed {
                reason: "authenticator returned an empty subject".into(),
            });
        }

        tracing::info!(subject = %subject, "agent authenticated");

        Ok(Agent {
            subject: Some(subject),
            engine: self.engine,
            _state: std::marker::PhantomData,
        })
    }

    /// Transition to `Authenticated` *without verifying the token*.
    ///
    /// **The claimed subject is trusted as-is.** Only the shape of the
    /// credentials is checked (non-empty subject and token). This exists for
    /// examples, tests, and deployments where identity is established out of
    /// band — production code should use [`authenticate_with`][Self::authenticate_with]
    /// and a real [`Authenticator`].
    pub fn authenticate_unverified(
        self,
        credentials: Credentials,
    ) -> Result<Agent<Authenticated>, AgentError> {
        if credentials.subject.is_empty() {
            return Err(AgentError::AuthFailed {
                reason: "subject cannot be empty".into(),
            });
        }
        if credentials.token.is_empty() {
            return Err(AgentError::AuthFailed {
                reason: "token cannot be empty".into(),
            });
        }

        tracing::warn!(
            subject = %credentials.subject,
            "agent authenticated WITHOUT credential verification"
        );

        Ok(Agent {
            subject: Some(credentials.subject),
            engine: self.engine,
            _state: std::marker::PhantomData,
        })
    }
}

impl Agent<Authenticated> {
    /// The authenticated subject identity.
    pub fn subject(&self) -> &str {
        self.subject
            .as_deref()
            .expect("Authenticated agent always has a subject")
    }

    /// The policy engine attached to this agent.
    pub fn engine(&self) -> &Arc<dyn PolicyEngine> {
        &self.engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyResult;

    struct AllowAll;
    impl PolicyEngine for AllowAll {
        fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
            PolicyResult::Allow
        }
    }

    #[test]
    fn authenticate_unverified_transitions_state() {
        let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
        let creds = Credentials::new("agent:test", "secret-token");
        let auth = agent
            .authenticate_unverified(creds)
            .expect("should succeed");
        assert_eq!(auth.subject(), "agent:test");
    }

    #[test]
    fn credentials_debug_redacts_token() {
        let creds = Credentials::new("agent:test", "super-secret-bearer");
        let rendered = format!("{creds:?}");
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn credentials_can_be_zeroized() {
        let mut creds = Credentials::new("agent:test", "super-secret-bearer");

        creds.zeroize();

        assert!(creds.subject.is_empty());
        assert!(creds.token.is_empty());
    }

    #[test]
    fn empty_subject_fails_auth() {
        let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
        let creds = Credentials::new("", "token");
        assert!(matches!(
            agent.authenticate_unverified(creds),
            Err(AgentError::AuthFailed { .. })
        ));
    }

    struct FixedSubject(&'static str);
    impl Authenticator for FixedSubject {
        fn verify_credentials(&self, credentials: &Credentials) -> Result<String, AgentError> {
            if credentials.token.expose() == "valid-token" {
                Ok(self.0.to_owned())
            } else {
                Err(AgentError::AuthFailed {
                    reason: "bad token".into(),
                })
            }
        }
    }

    #[test]
    fn authenticate_with_uses_verified_subject_not_claimed() {
        let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
        // The caller claims to be admin, but the authenticator says otherwise.
        let creds = Credentials::new("agent:claimed-admin", "valid-token");
        let auth = agent
            .authenticate_with(creds, &FixedSubject("agent:verified"))
            .expect("should succeed");
        assert_eq!(auth.subject(), "agent:verified");
    }

    #[test]
    fn authenticate_with_rejects_bad_token() {
        let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
        let creds = Credentials::new("agent:any", "wrong-token");
        assert!(matches!(
            agent.authenticate_with(creds, &FixedSubject("agent:verified")),
            Err(AgentError::AuthFailed { .. })
        ));
    }
}
