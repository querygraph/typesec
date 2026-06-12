# External Identity Integrations

Typesec integrates with external identity systems by treating them as policy
engines, authenticators, or secure-message gateways at the edge. OAuth/OIDC
proves identity and stores delegated provider authority. DID messaging proves
control of a decentralized identifier and protects payload transport. Typesec
turns allowed decisions into typed capabilities that local tool code must hold.

## Crates and Features

Provider integrations live in `typesec-integrations` and are re-exported by the
facade crate behind the `integrations` feature:

```toml
typesec = { version = "0.5.0", features = ["integrations"] }
```

The integrations crate currently provides:

- `JwtAuthenticator`: verifies OIDC/JWT access tokens against a JWKS endpoint.
- `JwtClaimsEngine`: checks org-wide permissions embedded in verified token
  claims and delegates misses to a more precise engine.
- `WorkOsFgaEngine`: calls the WorkOS Authorization API for resource-scoped
  Fine-Grained Authorization checks.
- `ArcadeToolAuthEngine`: checks whether a user has authorized an external tool
  such as Gmail, Slack, or GitHub.
- `DidResolver`, `DidKeyStore`, `DidMessageGateway`, and `DidOllamaClient`:
  verify DID-wrapped encrypted prompts and bridge them to `SecureValue` and
  Ollama.
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
    .authenticate_with(Credentials::new("user@example.com", token), &jwt_auth)?;
let cap: Capability<CanExecute, GenericResource> =
    agent.request_capability(&GenericResource::new("gmail/list", "tool")).await?;
tool.invoke(&agent, &cap).await?;
```

The important property is unchanged: provider checks remain runtime decisions,
but the local tool cannot run unless those decisions have been converted into a
typed Typesec capability.

## DID Messaging Pattern

DIDs are useful when an agent, service, or user needs a resolvable identifier
whose document advertises verification keys and service endpoints. In Typesec,
a DID proves the subject and helps decrypt the payload. It does not grant
authority by itself.

```text
DID envelope
  -> DidResolver resolves sender DID document
  -> DidKeyStore verifies the sender signature
  -> DidKeyStore decrypts the payload for the local recipient DID
  -> DidMessageGateway returns VerifiedDidPrompt
  -> VerifiedDidPrompt.prompt is SecureValue<Secret, String, GenericResource>
```

The verified DID string becomes the Typesec subject:

```text
subject:  did:key:z...
action:   ai:infer
resource: prompt/session/123
```

Policy still decides whether the prompt can be used:

```rust
use typesec::{
    AiCanInfer, CanReadSensitive, Capability, PolicyEngine,
    policy::mint_capability,
};
use typesec::integrations::{DidMessageGateway, DidOllamaClient};

let verified = gateway.open_prompt(&envelope)?;

let infer: Capability<AiCanInfer, _> =
    mint_capability(engine, verified.subject.as_str(), &verified.resource)?;
let read: Capability<CanReadSensitive, _> =
    mint_capability(engine, verified.subject.as_str(), &verified.resource)?;

let ollama = DidOllamaClient::new("http://localhost:11434", "llama3.2");
let response = ollama.chat_verified_prompt(verified, &infer, &read)?;
```

`chat_verified_prompt` is the conservative mode: Typesec verifies and decrypts
locally, then reveals the prompt only after both capabilities exist.
`chat_wrapped_prompt` is the compatibility mode for a DID-aware Ollama fork that
expects the whole envelope under the `did_envelope` field.

The included `StaticDidResolver` and `Ed25519DidKeyStore` cover local DID
examples with real signatures, key agreement, and authenticated encryption.
`DemoDidKeyStore` is a non-cryptographic test utility available only in tests or
behind the `demo-crypto` feature. Production
work should implement the same traits with DIDComm/JWE, HPKE, an HSM/KMS-backed
key store, Hyperledger Indy VDR, or a Universal Resolver client.
