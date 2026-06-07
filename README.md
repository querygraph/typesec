# typesec

**Agentic AI security using Rust's type system.**

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
typesec-macro     ← #[derive(TypesecRole)], policy! macro
typesec-cli       ← validate / check / generate / run commands
```

### typesec-core

The foundation. Defines:

- **`Permission`** — sealed marker trait. Implementations: `CanRead`, `CanWrite`,
  `CanDelete`, `CanExecute`, `CanDelegate`, `CanReadSensitive`, `CanWriteSensitive`,
  `AiCanInfer`, `AiCanTrain`, `AiCanExfiltrate`.

- **`Capability<P, R>`** — unforgeable proof token. `P` is a permission type, `R` is a
  resource type. Holding one means a `PolicyEngine` approved the access.

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

// 2. Authenticate → type transitions to Authenticated.
let agent = agent.authenticate(Credentials::new("agent:bot", "token"))?;

// 3. Request a capability. Policy checked; cap minted on Allow.
let cap: Capability<CanRead, Report> = agent.request_capability(&report).await?;

// 4. Execute. The cap is compile-time proof of permission.
agent.execute(&cap, &report, |r| Box::pin(async move {
    println!("reading: {}", r.resource_id());
    Ok(())
})).await?;
```

Engines can be composed: `AgentBuilder::with_composed_engine(odrl, rbac)` tries
ODRL first, falls back to RBAC on delegation.

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
```

For the full example catalog, install commands, and run commands, see
[`examples/README_examples.md`](examples/README_examples.md).

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

---

## License

MIT OR Apache-2.0
