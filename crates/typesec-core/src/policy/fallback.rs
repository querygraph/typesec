//! Two-engine fallback composition.

use std::sync::Arc;

use crate::ResourceId;

use super::{PolicyEngine, PolicyFuture, PolicyResult, RequestContext, SubjectId};

/// A two-engine fallback: tries `primary` first, then `fallback` on delegation.
///
/// Created via [`PolicyEngine::with_fallback`].
/// For multi-engine composition with configurable strategies, use
/// [`crate::combinator::ComposedEngine`] and [`crate::combinator::PolicyEngineBuilder`].
pub struct FallbackEngine<P: PolicyEngine> {
    pub(super) primary: P,
    pub(super) fallback: Arc<dyn PolicyEngine>,
}

impl<P: PolicyEngine> PolicyEngine for FallbackEngine<P> {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        self.check_with_context(subject, action, resource, &RequestContext::default())
    }

    fn check_with_context(
        &self,
        subject: &SubjectId,
        action: &str,
        resource: &ResourceId,
        ctx: &RequestContext,
    ) -> PolicyResult {
        match self
            .primary
            .check_with_context(subject, action, resource, ctx)
        {
            PolicyResult::Delegate(_) => self
                .fallback
                .check_with_context(subject, action, resource, ctx),
            other => other,
        }
    }

    fn check_with_context_async<'a>(
        &'a self,
        subject: &'a SubjectId,
        action: &'a str,
        resource: &'a ResourceId,
        ctx: &'a RequestContext,
    ) -> PolicyFuture<'a> {
        Box::pin(async move {
            match self
                .primary
                .check_with_context_async(subject, action, resource, ctx)
                .await
            {
                PolicyResult::Delegate(_) => {
                    self.fallback
                        .check_with_context_async(subject, action, resource, ctx)
                        .await
                }
                other => other,
            }
        })
    }
}
