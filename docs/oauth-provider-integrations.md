# OAuth Provider Integrations

Typesec integrates with OAuth-based systems by treating them as policy engines
or authenticators at the edge. OAuth/OIDC proves identity and stores delegated
provider authority; Typesec turns allowed decisions into typed capabilities that
the local tool code must hold.

## Crates and Features

Provider integrations live in `typesec-integrations` and are re-exported by the
facade crate behind the `integrations` feature:

```toml
typesec = { version = "0.4.0", features = ["integrations"] }
```

The integrations crate currently provides:

- `JwtAuthenticator`: verifies OIDC/JWT access tokens against a JWKS endpoint.
- `JwtClaimsEngine`: checks org-wide permissions embedded in verified token
  claims and delegates misses to a more precise engine.
- `WorkOsFgaEngine`: calls the WorkOS Authorization API for resource-scoped
  Fine-Grained Authorization checks.
- `ArcadeToolAuthEngine`: checks whether a user has authorized an external tool
  such as Gmail, Slack, or GitHub.
- `ProtectedTool`: wraps local tool handlers so invocation requires a matching
  `Capability<P, R>`.

## Recommended Composition

```text
OIDC/AuthKit access token
  -> JwtAuthenticator verifies signature, issuer, audience, expiry
  -> VerifiedSubject becomes the authenticated Typesec subject

Capability request
  -> JwtClaimsEngine handles fast org-wide permissions
  -> WorkOsFgaEngine handles app resource permissions
  -> ArcadeToolAuthEngine handles external SaaS tool authorization
  -> Allow mints Capability<P, R>
  -> ProtectedTool<P, R, _> can run
```

## WorkOS Pattern

Use WorkOS/AuthKit for identity and WorkOS FGA for resource-specific checks.
Typesec resource ids should use `resource_type/resource_external_id`, for example
`project/proj_123` or `workspace/ws_123`.

```rust
use std::sync::Arc;
use typesec::integrations::{JwtClaimsEngine, WorkOsFgaEngine};
use typesec::{PolicyEngineBuilder, CombineStrategy};

let jwt_engine = Arc::new(JwtClaimsEngine::from_permissions(
    "user_123",
    ["org:view".to_string()],
));
let workos_engine = Arc::new(WorkOsFgaEngine::new(std::env::var("WORKOS_API_KEY")?));

let engine = PolicyEngineBuilder::new()
    .add_engine(jwt_engine)
    .add_engine(workos_engine)
    .strategy(CombineStrategy::PriorityOrder)
    .build();
```

`JwtClaimsEngine` returns `Allow` only when the verified token contains the
permission. Otherwise it returns `Delegate`, so resource-level decisions can fall
through to WorkOS FGA.

## Arcade Pattern

Use Arcade for external tool authorization. Map local resource ids to Arcade
tool names, then request a typed execution capability before invoking the tool.

```rust
use std::sync::Arc;
use typesec::integrations::ArcadeToolAuthEngine;

let arcade = ArcadeToolAuthEngine::new(std::env::var("ARCADE_API_KEY")?)
    .with_tool_mapping("gmail/list", "Gmail.ListEmails");

let engine = Arc::new(arcade);
```

When Arcade reports a completed authorization, Typesec can mint the capability.
When authorization is pending, the denial reason includes the authorization URL
if the provider returned one.

## Protected Tools

`ProtectedTool` is the local last mile: a handler advertises its required
permission and resource, then refuses to invoke unless the caller supplies the
matching typed capability.

```rust
use typesec::{CanExecute, Capability, Credentials, ProtectedTool, SecureAgent, ToolFuture};
use typesec::resource::GenericResource;

fn gmail_list(_resource: &GenericResource) -> ToolFuture<'_> {
    Box::pin(async {
        // Call Arcade/MCP/tool implementation here.
        Ok(())
    })
}

let resource = GenericResource::new("gmail/list", "tool");
let tool = ProtectedTool::<CanExecute, _, _>::new(
    "gmail.list",
    "List email messages",
    resource,
    gmail_list,
);

let agent = SecureAgent::new(engine)
    .authenticate(Credentials::new("user@example.com", "verified-token"))?;
let cap: Capability<CanExecute, GenericResource> =
    agent.request_capability(&GenericResource::new("gmail/list", "tool")).await?;
tool.invoke(&agent, &cap).await?;
```

The important property is unchanged: provider checks remain runtime decisions,
but the local tool cannot run unless those decisions have been converted into a
typed Typesec capability.
