//! SecureAgent — the main agent struct wiring typestate + capabilities together.

use std::sync::Arc;

use tracing::{debug, info};
use typesec_core::{
    Capability, Permission, Resource,
    policy::{CapabilityError, MintOptions, PolicyEngine, mint_capability_for_id_async},
    typestate::{Agent, AgentError, AgentState, Authenticated, Credentials, Unauthenticated},
};

/// A secure agent that ties together typestate, policy engines, and capabilities.
///
/// `S` is the typestate parameter: `Unauthenticated` or `Authenticated`.
///
/// # Why a newtype wrapper?
///
/// `typesec-core`'s `Agent` is the minimal typestate foundation. `SecureAgent`
/// adds the async `request_capability` and `execute` methods on top, keeping
/// the core crate dependency-free (no tokio).
pub struct SecureAgent<S: AgentState> {
    inner: Agent<S>,
}

impl SecureAgent<Unauthenticated> {
    /// Create a new unauthenticated agent with the given policy engine.
    pub fn new(engine: Arc<dyn PolicyEngine>) -> Self {
        Self {
            inner: Agent::new(engine),
        }
    }

    /// Authenticate the agent against a credential verifier.
    ///
    /// On success, returns `SecureAgent<Authenticated>` whose subject is the
    /// *verified* identity returned by the authenticator. The unauthenticated
    /// agent is *consumed* — you can't hold onto the unauthenticated handle
    /// after calling this.
    pub fn authenticate_with(
        self,
        credentials: Credentials,
        authenticator: &dyn typesec_core::typestate::Authenticator,
    ) -> Result<SecureAgent<Authenticated>, AgentError> {
        let inner = self.inner.authenticate_with(credentials, authenticator)?;
        Ok(SecureAgent { inner })
    }

    /// Authenticate *without verifying the token* — the claimed subject is
    /// trusted as-is. For examples, tests, and out-of-band identity only;
    /// production code should use [`authenticate_with`][Self::authenticate_with].
    pub fn authenticate_unverified(
        self,
        credentials: Credentials,
    ) -> Result<SecureAgent<Authenticated>, AgentError> {
        let inner = self.inner.authenticate_unverified(credentials)?;
        Ok(SecureAgent { inner })
    }
}

impl SecureAgent<Authenticated> {
    /// The authenticated subject identity.
    pub fn subject(&self) -> &str {
        self.inner.subject()
    }

    /// Access the underlying policy engine.
    ///
    /// Useful for composing raw `check()` calls alongside capability-based access.
    pub fn engine(&self) -> Arc<dyn PolicyEngine> {
        self.inner.engine().clone()
    }

    /// Request a capability for permission `P` on `resource`.
    ///
    /// This is the *only* way to obtain a `Capability<P, R>` from outside
    /// `typesec-core`. The policy engine is called, the decision is logged,
    /// and either a capability or an error is returned.
    ///
    /// The capability is a zero-sized proof token — holding it means the policy
    /// engine approved the request at the time of this call.
    /// Async policy engines can do their work without blocking the executor;
    /// synchronous engines use the default async adapter in `typesec-core`.
    pub async fn request_capability<P: Permission, R: Resource>(
        &self,
        resource: &R,
    ) -> Result<Capability<P, R>, CapabilityError> {
        self.request_capability_with(resource, MintOptions::default())
            .await
    }

    /// Like [`request_capability`][Self::request_capability], but with explicit
    /// lease parameters: a custom TTL and/or a
    /// [`RevocationEpoch`][typesec_core::RevocationEpoch] binding so the
    /// capability can be invalidated mid-lease (e.g. on policy reload).
    pub async fn request_capability_with<P: Permission, R: Resource>(
        &self,
        resource: &R,
        options: MintOptions,
    ) -> Result<Capability<P, R>, CapabilityError> {
        let subject = self.subject().to_owned();
        let action = P::name();
        let resource_id = resource.resource_id().to_owned();
        let engine = self.inner.engine().clone();

        debug!(%subject, action, %resource_id, "requesting capability");

        let cap =
            mint_capability_for_id_async::<P, R>(engine.as_ref(), &subject, &resource_id, &options)
                .await?;

        info!(%subject, action, %resource_id, "capability granted");

        Ok(cap)
    }

    /// Execute an async action, requiring a valid capability as proof.
    ///
    /// The key design point: `execute` takes `cap: &Capability<P, R>` as an
    /// argument. There is no code path through `execute` that doesn't hold a
    /// capability. If you don't have a capability, you can't call this method
    /// (the type system ensures it).
    ///
    /// The phantom types prove the *kind* of access; two runtime checks bind
    /// the proof to this call: the capability must have been minted for this
    /// agent's subject (no confused-deputy use of another agent's token), and
    /// for this exact resource instance (a cap for `reports/q1` cannot act on
    /// `reports/q2`).
    ///
    /// This is different from:
    /// ```rust,ignore
    /// // ❌ Guard-based — the check can be skipped, the condition forgotten.
    /// if has_permission { do_thing(); }
    ///
    /// // ✅ Capability-based — the capability IS the check.
    /// agent.execute(&cap, &resource, action).await?;
    /// ```
    pub async fn execute<P, R, F, Fut>(
        &self,
        cap: &Capability<P, R>,
        resource: &R,
        action: F,
    ) -> Result<(), crate::executor::TaskError>
    where
        P: Permission,
        R: Resource,
        F: FnOnce(&R) -> Fut,
        Fut: std::future::Future<Output = Result<(), crate::executor::TaskError>>,
    {
        if cap.subject() != self.subject() {
            return Err(crate::executor::TaskError::CapabilityMismatch(format!(
                "capability was minted for subject '{}', not '{}'",
                cap.subject(),
                self.subject()
            )));
        }
        if cap.resource_id() != resource.resource_id() {
            return Err(crate::executor::TaskError::CapabilityMismatch(format!(
                "capability covers resource '{}', not '{}'",
                cap.resource_id(),
                resource.resource_id()
            )));
        }
        cap.ensure_active()?;

        info!(
            subject = %self.subject(),
            permission = %Capability::<P, R>::permission_name(),
            resource = %cap.resource_id(),
            "executing with capability"
        );

        action(resource).await
    }
}

impl<S: AgentState> std::fmt::Debug for SecureAgent<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureAgent({:?})", self.inner)
    }
}

/// Builder for [`SecureAgent`] — convenient when wiring multiple engines together.
pub struct AgentBuilder {
    engine: Option<Arc<dyn PolicyEngine>>,
}

impl AgentBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self { engine: None }
    }

    /// Set the policy engine.
    pub fn with_engine(mut self, engine: Arc<dyn PolicyEngine>) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Compose two engines: `primary` first, falling back to `fallback` on delegation.
    ///
    /// Uses [`CombineStrategy::PriorityOrder`]: the primary engine's answer wins
    /// unless it delegates, in which case the fallback is tried.
    ///
    /// For more control (e.g., `DenyOverrides`, `AllowIfAny`), build a
    /// [`typesec_core::ComposedEngine`] directly with [`typesec_core::PolicyEngineBuilder`]
    /// and pass it to [`AgentBuilder::with_engine`].
    pub fn with_composed_engine(
        self,
        primary: Arc<dyn PolicyEngine>,
        fallback: Arc<dyn PolicyEngine>,
    ) -> Self {
        self.with_composed_engine_strategy(
            primary,
            fallback,
            typesec_core::combinator::CombineStrategy::PriorityOrder,
        )
    }

    /// Compose two engines with an explicit combination strategy.
    pub fn with_composed_engine_strategy(
        mut self,
        primary: Arc<dyn PolicyEngine>,
        fallback: Arc<dyn PolicyEngine>,
        strategy: typesec_core::combinator::CombineStrategy,
    ) -> Self {
        use typesec_core::combinator::PolicyEngineBuilder;
        let engine = PolicyEngineBuilder::new()
            .add_engine(primary)
            .add_engine(fallback)
            .strategy(strategy)
            .build();
        self.engine = Some(Arc::new(engine));
        self
    }

    /// Build the agent.
    pub fn build(self) -> Result<SecureAgent<Unauthenticated>, String> {
        let engine = self.engine.ok_or("no policy engine configured")?;
        Ok(SecureAgent::new(engine))
    }
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use typesec_core::{permissions::CanRead, policy::PolicyResult, resource::GenericResource};

    struct AllowAll;
    impl PolicyEngine for AllowAll {
        fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
            PolicyResult::Allow
        }
    }

    struct DenyAll;
    impl PolicyEngine for DenyAll {
        fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
            PolicyResult::Deny("DenyAll".into())
        }
    }

    #[tokio::test]
    async fn full_flow_allow() {
        let agent = SecureAgent::new(Arc::new(AllowAll));
        let agent = agent
            .authenticate_unverified(Credentials::new("agent:test", "tok"))
            .expect("auth ok");
        let resource = GenericResource::new("reports/q1", "report");
        let cap: Capability<CanRead, GenericResource> = agent
            .request_capability(&resource)
            .await
            .expect("should get cap");
        assert_eq!(cap.subject(), "agent:test");
    }

    #[tokio::test]
    async fn denied_request_returns_error() {
        let agent = SecureAgent::new(Arc::new(DenyAll));
        let agent = agent
            .authenticate_unverified(Credentials::new("agent:test", "tok"))
            .expect("auth ok");
        let resource = GenericResource::new("reports/q1", "report");
        let result: Result<Capability<CanRead, GenericResource>, _> =
            agent.request_capability(&resource).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn execute_requires_capability() {
        let agent = SecureAgent::new(Arc::new(AllowAll));
        let agent = agent
            .authenticate_unverified(Credentials::new("agent:test", "tok"))
            .expect("auth ok");
        let resource = GenericResource::new("reports/q1", "report");
        let cap: Capability<CanRead, GenericResource> =
            agent.request_capability(&resource).await.expect("cap ok");

        let executed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let executed_clone = executed.clone();

        agent
            .execute(&cap, &resource, |_r| {
                let flag = executed_clone.clone();
                Box::pin(async move {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                })
            })
            .await
            .expect("execute ok");

        assert!(executed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn execute_rejects_capability_for_other_resource() {
        let agent = SecureAgent::new(Arc::new(AllowAll));
        let agent = agent
            .authenticate_unverified(Credentials::new("agent:test", "tok"))
            .expect("auth ok");
        let q1 = GenericResource::new("reports/q1", "report");
        let q2 = GenericResource::new("reports/q2", "report");
        let cap: Capability<CanRead, GenericResource> =
            agent.request_capability(&q1).await.expect("cap ok");

        // Same resource type, different instance — must be rejected.
        let result = agent
            .execute(&cap, &q2, |_r| Box::pin(async { Ok(()) }))
            .await;
        assert!(matches!(
            result,
            Err(crate::executor::TaskError::CapabilityMismatch(_))
        ));
    }

    #[tokio::test]
    async fn execute_rejects_capability_for_other_subject() {
        let resource = GenericResource::new("reports/q1", "report");

        // Mint a capability as agent:other...
        let other = SecureAgent::new(Arc::new(AllowAll))
            .authenticate_unverified(Credentials::new("agent:other", "tok"))
            .expect("auth ok");
        let cap: Capability<CanRead, GenericResource> =
            other.request_capability(&resource).await.expect("cap ok");

        // ...and try to use it as agent:test.
        let agent = SecureAgent::new(Arc::new(AllowAll))
            .authenticate_unverified(Credentials::new("agent:test", "tok"))
            .expect("auth ok");
        let result = agent
            .execute(&cap, &resource, |_r| Box::pin(async { Ok(()) }))
            .await;
        assert!(matches!(
            result,
            Err(crate::executor::TaskError::CapabilityMismatch(_))
        ));
    }
}
