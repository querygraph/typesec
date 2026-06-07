//! # Agent typestate
//!
//! Rust's typestate pattern encodes state machine transitions in the type system.
//! An [`Agent<Unauthenticated>`] has no `request_capability` method — it
//! literally doesn't exist. You *must* call [`Agent::authenticate`] first,
//! which returns `Agent<Authenticated>`. Only then do the capability-requesting
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

/// Credentials used to authenticate an agent.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// The agent's claimed identity.
    pub subject: String,
    /// An opaque token (API key, signed JWT, etc.) — validation is application-specific.
    pub token: String,
}

impl Credentials {
    /// Create credentials with the given subject and token.
    pub fn new(subject: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            token: token.into(),
        }
    }
}

/// Error types for agent operations.
#[derive(Debug, thiserror::Error)]
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

    /// Authenticate the agent, producing an `Agent<Authenticated>`.
    ///
    /// This is the *only* path from `Unauthenticated` to `Authenticated`.
    /// The typestate transition is irreversible at the type level — you can't
    /// downgrade an authenticated agent back to unauthenticated.
    ///
    /// Authentication here is intentionally minimal: we validate that the subject
    /// is non-empty and the token is present. Real implementations would verify
    /// against an identity provider.
    pub fn authenticate(
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

        tracing::info!(subject = %credentials.subject, "agent authenticated");

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
    fn authenticate_transitions_state() {
        let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
        let creds = Credentials::new("agent:test", "secret-token");
        let auth = agent.authenticate(creds).expect("should succeed");
        assert_eq!(auth.subject(), "agent:test");
    }

    #[test]
    fn empty_subject_fails_auth() {
        let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
        let creds = Credentials::new("", "token");
        assert!(matches!(
            agent.authenticate(creds),
            Err(AgentError::AuthFailed { .. })
        ));
    }
}
