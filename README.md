# typesec

**Agentic AI security using Rust's type system.**

Typesec was inspired by David Andrzejewski's Scale By the Bay talk,
["Privacy aware data science in Scala with monads and type level programming"](https://www.youtube.com/watch?v=hoVIqh1qjXM),
which connected data-science privacy work to typed information-flow control.
That talk traces part of its implementation lineage to the Haskell
[SecLib](https://hackage.haskell.org/package/seclib-0.7) security-container
library; we keep a local [cleaned transcript](docs/david-andrzejewski-scale-by-the-bay-2018-transcript.md)
as design context for this repository.

Policies are encoded in types. Violations are compile errors.

---

## The Core Idea

Most security systems check permissions at runtime:

```rust
// ❌ Guard-based — the check can be forgotten, skipped, or bypassed.
if acl.check(user, "write", resource) {
    resource.write(data);
}
```

`typesec` encodes permissions as *types*. If your code doesn't hold a
`Capability<CanWrite, Report>`, the write method doesn't exist in your API:

```rust
// ✅ Type-level — the capability IS the proof. No check can be skipped.
fn write(cap: Capability<CanWrite, Report>, report: &Report) {
    // `cap` existing in scope means the policy engine approved this.
    // There is no other code path to this function.
}
```

The `Capability<P, R>` struct is **unforgeable**:
- Its constructor is `pub(crate)` — only the policy engine can create one.
- Its type parameters `P` and `R` are phantom types — `Capability<CanRead, Report>`
  and `Capability<CanWrite, Report>` are *different types*.
- The [`Permission`] trait is sealed — you can't create new permissions outside `typesec-core`.

---

## Architecture

```
typesec           ← facade crate re-exporting the common API
typesec-core      ← traits, phantom types, Capability, PolicyEngine, typestate
typesec-rbac      ← YAML RBAC → runtime engine + codegen
typesec-odrl      ← YAML ODRL → constraint evaluation + audit log
typesec-agent     ← SecureAgent: authenticate + request_capability + execute
typesec-integrations ← JWT/OIDC, WorkOS FGA, Arcade-style tool auth, DID messaging
typesec-macro     ← #[derive(TypesecRole)], policy! macro
typesec-cli       ← validate / check / generate / run commands
typesec-python    ← PyO3 bindings for Rust-backed Python policy gates
```

### typesec-core

The foundation. Defines:

- **`Permission`** — sealed marker trait. Implementations: `CanRead`, `CanWrite`,
  `CanDelete`, `CanExecute`, `CanDelegate`, `CanReadSensitive`, `CanWriteSensitive`,
  `AiCanInfer`, `AiCanTrain`, `AiCanExfiltrate`.

- **`Capability<P, R>`** — unforgeable proof token. `P` is a permission type, `R` is a
  resource type. Holding one means a `PolicyEngine` approved the access.

- **`SecureValue<L, T, R>`** — opaque labeled data, inspired by information-flow
  security libraries such as SecLib. Code can transform the contained `T` with
  `map` and `zip`, but cannot extract protected values without a typed
  capability. Combining values keeps the more restrictive privacy label.

- **`Agent<S>`** — typestate machine. `S ∈ {Unauthenticated, Authenticated}`. The
  `AgentState` trait is sealed; you can't forge states.

- **`PolicyEngine`** — runtime bridge. Every `check()` call logs an `AuditEvent` via
  `tracing`.

### typesec-rbac

RBAC (Role-Based Access Control) from YAML:

```yaml
roles:
  - name: analyst
    permissions: [read, read_sensitive]
    resources: ["reports/*", "metrics/*"]
  - name: admin
    inherits: [analyst]
    permissions: [delete, delegate]
    resources: ["*"]
assignments:
  - subject: "agent:data-pipeline"
    roles: [analyst]
```

`RbacEngine::from_yaml()` builds a compiled engine with flattened role inheritance.
`typesec generate` emits typed Rust structs from the YAML — renaming a role breaks
any code referencing the old name at compile time.

### typesec-odrl

ODRL (Open Digital Rights Language, W3C subset) from YAML:

```yaml
policies:
  - uid: "policy:ai-agent-001"
    type: Set
    rules:
      - type: permission
        assignee: "agent:summarizer"
        action: read
        target: "asset:customer-data"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "analytics"
      - type: prohibition
        assignee: "agent:summarizer"
        action: exfiltrate
        target: "asset:customer-data"
```

`OdrlEngine` evaluates constraints (purpose, dateTime, custom keys) at check time.
**Prohibitions always override permissions.** Every decision is logged.

### typesec-agent

```rust
// 1. Create agent (Unauthenticated).
let agent = SecureAgent::new(Arc::new(rbac_engine));

// 2. Authenticate → type transitions to Authenticated. The Authenticator
//    (e.g. JwtAuthenticator) verifies the token and returns the verified
//    subject; authenticate_unverified() exists for tests and demos.
let agent = agent.authenticate_with(Credentials::new("agent:bot", token), &jwt_auth)?;

// 3. Request a capability. Policy checked; cap minted on Allow. The check
//    runs on the blocking pool so engine I/O can't stall the executor.
let cap: Capability<CanRead, Report> = agent.request_capability(&report).await?;
// Capabilities are short-lived leases; protected APIs reject expired caps.
// request_capability_with(MintOptions { ttl, revocation }) shortens the
// lease per risk or binds the cap to a RevocationEpoch, which revoke_all()
// can invalidate mid-lease (e.g. on policy reload).

// 4. Execute. The cap is compile-time proof of permission kind; at runtime
//    it must also match this agent's subject and this exact resource id.
agent.execute(&cap, &report, |r| Box::pin(async move {
    println!("reading: {}", r.resource_id());
    Ok(())
})).await?;
```

Engines can be composed: `AgentBuilder::with_composed_engine(odrl, rbac)` tries
ODRL first, falls back to RBAC on delegation.

### typesec-integrations

OAuth proves identity and delegates authority. Typesec turns allowed provider
decisions into typed capabilities that local code must hold before it can run.

The optional `integrations` feature adds provider-facing adapters:

- **`JwtAuthenticator`** verifies OIDC/JWT access tokens against JWKS.
- **`JwtClaimsEngine`** allows fast org-wide permissions embedded in verified
  token claims and delegates misses to a precise engine.
- **`WorkOsFgaEngine`** calls WorkOS Fine-Grained Authorization for app
  resources such as `project/proj_123`.
- **`ArcadeToolAuthEngine`** checks whether a user has authorized an external
  tool such as `Gmail.ListEmails`.
- **DID messaging** verifies DID-wrapped encrypted prompts, converts plaintext
  into `SecureValue<Secret, _, _>`, and sends prompts to Ollama only after
  typed inference and sensitive-read capabilities exist.
- **`ProtectedTool`** wraps local tool handlers so invocation requires a
  matching `Capability<P, R>`.

The intended architecture is:

```text
OIDC/AuthKit token
  -> JwtAuthenticator verifies identity
  -> JwtClaimsEngine checks fast org-wide claims
  -> WorkOsFgaEngine checks resource-scoped app access
  -> ArcadeToolAuthEngine checks external SaaS tool authorization
  -> Allow mints Capability<P, R>
  -> ProtectedTool<P, R, _> can run
```

Representative composition:

```rust
let engine = PolicyEngineBuilder::new()
    .add_engine(Arc::new(JwtClaimsEngine::from_permissions(
        "user@example.com",
        ["read".to_string()],
    )))
    .add_engine(Arc::new(WorkOsFgaEngine::new(workos_api_key)))
    .add_engine(Arc::new(
        ArcadeToolAuthEngine::new(arcade_api_key)
            .with_tool_mapping("gmail/list", "Gmail.ListEmails"),
    ))
    .strategy(CombineStrategy::PriorityOrder)
    .build();
```

For decentralized-identity messaging, the shape is similar but identity and
payload protection come from a DID envelope:

```text
DID envelope
  -> DidResolver resolves sender and recipient DID documents
  -> DidKeyStore verifies the sender and decrypts for the local recipient
  -> DidMessageGateway protects plaintext as SecureValue<Secret, _, _>
  -> PolicyEngine mints AiCanInfer and CanReadSensitive capabilities
  -> DidOllamaClient can call Ollama or forward the wrapped envelope
```

The repository ships `Ed25519DidKeyStore` (Ed25519 signatures, X25519 key
agreement, ChaCha20-Poly1305 payload encryption) as the production key store,
plus `StaticDidResolver` for local resolution. A deterministic,
**non-cryptographic** `DemoDidKeyStore` exists behind the `demo-crypto`
feature for tests only. Deployments with stronger requirements can replace
these with DIDComm/JWE, HPKE, an HSM/KMS-backed key store, Hyperledger Indy
VDR, or a Universal Resolver client behind the same traits.

See [`docs/typesec-and-auth-frameworks.md`](docs/typesec-and-auth-frameworks.md),
[`docs/oauth-provider-integrations.md`](docs/oauth-provider-integrations.md),
[`docs/did-messaging.md`](docs/did-messaging.md), and
[`examples/provider_integrations.rs`](examples/provider_integrations.rs).

### typesec-macro

```rust
// Derive the Role trait from a struct + attribute:
#[derive(TypesecRole)]
#[role(permissions = "read,write", resources = "code/*")]
pub struct Engineer;

// Or use the inline DSL:
policy! {
    role Analyst {
        can [read, read_sensitive] on ["reports/*", "metrics/*"];
    }
}
```

### typesec-cli

```sh
# Validate a policy file
typesec validate --policy policies/rbac-example.yaml

# Check a single query
typesec check --policy policies/rbac-example.yaml \
    --subject agent:data-pipeline --action write --resource reports/q1

# Generate typed Rust code
typesec generate --policy policies/rbac-example.yaml --out src/policy_gen.rs

# Simulate agent execution
typesec run --policy policies/odrl-example.yaml \
    --agent agent:summarizer --task summarize --purpose analytics
```

---

## Quickstart

```sh
cargo add typesec
```

For the CLI:

```sh
cargo install typesec-cli
typesec validate --policy policies/rbac-example.yaml
```

For local development:

```sh
git clone <repo>
cd typesec
cargo build
cargo test
cargo run -p typesec-cli -- validate --policy policies/rbac-example.yaml
cargo run --example rbac_agent
cargo run --example odrl_agent
cargo run -p typesec-cli --example provider_integrations
```

For Python examples and the Rust-backed Python module, use asdf for the Python
version and uv for the virtualenv/dependencies:

```sh
asdf install
uv venv --python "$(asdf which python)"
uv sync --group dev
uv run python --version
```

For the full example catalog, install commands, and run commands, see
[`examples/README_examples.md`](examples/README_examples.md).

For Python agents, the company graph examples include a framework-neutral
Typesec gate, a LangChain-style adapter, and a Pydantic AI adapter. The native
Python module lives in `crates/typesec-python` and can be built with maturin as
`typesec_native`.

---

## Why this matters for AI agents

AI agents are long-running, autonomous, and capable of side effects. Traditional
guard-based security is fragile when:

- An agent has dozens of code paths that could access data.
- Policy logic is scattered across the codebase.
- A new capability gets added but the guard is forgotten.

With `typesec`, an agent's capabilities are part of its *type*. You can read the
type signature of a function and know exactly what it can access. You cannot
accidentally grant a capability — you have to explicitly request one from the
policy engine, which logs the decision.

The `AiCanExfiltrate` permission is especially notable: any code path that sends
data outside the system boundary must carry a `Capability<AiCanExfiltrate, _>`.
Data-leak paths are visible at compile time, not just detectable in production logs.

`SecureValue` extends that model from operations to data itself:

```rust
let email: SecureValue<Sensitive, String, CustomerRecord> =
    SecureValue::protect(customer.email, &customer);

let domain = email.map(|addr| addr.split('@').last().unwrap_or("").to_owned());

// Requires Capability<CanDeclassify, CustomerRecord> minted for this
// customer's resource id — a capability for another customer is rejected.
let public_domain = domain.declassify(&declassify_cap)?.into_public();
```

---

## License

MIT OR Apache-2.0
