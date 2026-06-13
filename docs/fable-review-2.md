# typesec — Fable Review 2

> Deep architectural review of the typesec codebase (9 crates, v0.6.0).  
> Every task below is discrete enough for Codex to implement independently.  
> Tasks are grouped by theme; priority flags are (**critical**), (**high**), or (**medium**).

---

## Architecture snapshot

| Crate | Role |
|---|---|
| `typesec-core` | Phantom-typed `Capability<P,R>`, sealed `Permission`/`AgentState`, `PolicyEngine` trait, `SecureValue`, permission lattice, combinators |
| `typesec-rbac` | YAML RBAC engine, glob patterns, role inheritance, graph-backed policies |
| `typesec-odrl` | W3C ODRL engine with constraint evaluation and structured audit events |
| `typesec-agent` | `SecureAgent<S>` async wrapper, `ProtectedTool`, `AgentBuilder` |
| `typesec-integrations` | JWT/OIDC, WorkOS FGA, Arcade, DID/Ed25519/X25519 messaging |
| `typesec-macro` | `#[derive(TypesecRole)]` and `policy! {}` DSL proc macros |
| `typesec-cli` | `validate`, `check`, `generate`, `run` subcommands |
| `typesec-python` | PyO3 `TypesecGate`/`Decision` extension module |
| `typesec` | Re-export façade |

The core design is sound: phantom types prove capability provenance at compile time, sealed traits prevent forgery, and the typestate machine (`Unauthenticated → Authenticated`) is a clean one-way door. The issues below are refinements—none are show-stoppers—but several would cause correctness or performance surprises in production.

---

## Part 1 — Rust quality tasks

### Q-1 (**critical**) `TypesecGate` rebuilds the engine on every `check()` call

**File:** `crates/typesec-python/src/lib.rs`

`TypesecGate` stores the raw YAML string and calls `check_policy(yaml, ...)` / `validate_policy(yaml, ...)` on every invocation, which re-parses the YAML and re-compiles glob patterns on every single policy decision. For Python code calling `gate.check(...)` in a hot loop this is O(policy_size) work per call, not O(1).

**Fix:** Cache the compiled engine at construction time. Store a `Box<dyn PolicyEngine>` (or an enum over the three engine types) inside `TypesecGate`. Remove the `yaml` field after construction; the engine already owns the compiled policy.

```rust
// Before:
struct TypesecGate { yaml: String, format: PolicyFormat }

// After:
struct TypesecGate { engine: Arc<dyn typesec_core::policy::PolicyEngine> }
```

The `validate_policy` call in `TypesecGate::new` already builds the engine once for validation—reuse that engine instead of dropping it.

---

### Q-2 (**critical**) `AuditSink::record` is synchronous; async sinks require workarounds

**File:** `crates/typesec-core/src/policy.rs`

```rust
pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent);
}
```

Callers that want to write audit events to a database, SIEM HTTP endpoint, or message queue must either block the calling thread or internally spin up a channel. Neither is correct for async runtimes.

**Fix:** Add an async variant alongside the sync one, defaulting to the sync path:

```rust
pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent);

    fn record_async<'a>(&'a self, event: &'a AuditEvent)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>
    {
        Box::pin(async move { self.record(event) })
    }
}
```

Update `record_audit` to call `record_async` when an async runtime is available (detect via `tokio::runtime::Handle::try_current`).

---

### Q-3 (**high**) `PolicyEngine::check` is synchronous; IO-bound engines are forced to block

**File:** `crates/typesec-core/src/policy.rs`

The `PolicyEngine` trait has a single synchronous `check()` method. The `SecureAgent::request_capability` works around this with `tokio::task::spawn_blocking`, but this means every policy check—even for engines that only do in-memory work—pays the cost of a blocking thread dispatch.

More critically, integrations like `WorkOsFgaEngine` that need to make HTTP calls to the WorkOS API must use a blocking HTTP client internally, preventing clean async composition.

**Fix:** Add an `AsyncPolicyEngine` trait as a companion:

```rust
#[async_trait::async_trait]
pub trait AsyncPolicyEngine: Send + Sync {
    async fn check_async(&self, subject: &str, action: &str, resource: &str) -> PolicyResult;
}

// Blanket impl: every sync engine is trivially async
impl<E: PolicyEngine> AsyncPolicyEngine for E {
    async fn check_async(&self, s: &str, a: &str, r: &str) -> PolicyResult {
        self.check(s, a, r)
    }
}
```

Update `SecureAgent::request_capability` to call `check_async` directly instead of wrapping in `spawn_blocking`.

---

### Q-4 (**high**) `RevocationEpoch::revoke_all` uses `Ordering::SeqCst` where `AcqRel` suffices

**File:** `crates/typesec-core/src/capability.rs`, lines 74-76 and 79-81

`SeqCst` imposes a global memory-order fence that costs an `MFENCE` instruction on x86 (expensive compared to `LOCK XADD`). The semantics here only require that writes to the epoch counter are visible before reads—`AcqRel` on fetch_add and `Acquire` on load is correct and 2-3× cheaper on contended paths.

**Fix:**
```rust
pub fn revoke_all(&self) { self.0.fetch_add(1, Ordering::AcqRel); }
pub fn current(&self) -> u64 { self.0.load(Ordering::Acquire); }
```

---

### Q-5 (**high**) `AuditEvent.timestamp` is a raw `String`, not a typed time

**File:** `crates/typesec-core/src/policy.rs`, line 80

```rust
pub timestamp: String,  // ISO-8601
```

Downstream consumers that want to filter, sort, or bucket events by time must re-parse the string. This is error-prone and slow at scale.

**Fix:** Change the field to `chrono::DateTime<chrono::Utc>` (already in the dependency graph via `now_iso8601()` in the same file). Update `now_iso8601()` to return `DateTime<Utc>` and implement `Display`/`Serialize` with RFC-3339 formatting.

---

### Q-6 (**high**) `CapabilityError::EngineError` discards the original error source

**File:** `crates/typesec-core/src/policy.rs`, line 63

```rust
#[error("policy engine error: {0}")]
EngineError(String),
```

Wrapping to `String` loses the original error type and prevents callers from downcasting. This also makes structured error handling impossible.

**Fix:**
```rust
#[error("policy engine error: {0}")]
EngineError(#[source] Box<dyn std::error::Error + Send + Sync>),
```

Update all `CapabilityError::EngineError(format!(...))` call sites to use the new form.

---

### Q-7 (**high**) Missing `#[must_use]` on capability-minting functions and key return types

The following return values are silently ignored at no compile cost today, but ignoring them is almost always a bug:

- `mint_capability()` / `mint_capability_with()` / `mint_capability_for_id()`
- `Capability::ensure_active()`
- `RevocationEpoch::revoke_all()` (returns `u64` from `fetch_add`, callers should not need the old value)
- `PolicyResult` itself
- `SecureValue::reveal()` / `SecureValue::declassify()`

**Fix:** Add `#[must_use]` to each of the above. For `PolicyResult`, annotate the enum itself:
```rust
#[must_use = "policy decisions must be checked; an ignored result is a silent allow/deny"]
pub enum PolicyResult { ... }
```

---

### Q-8 (**high**) `SecureValue::zip` silently discards `other.resource_id`

**File:** `crates/typesec-core/src/secure_value.rs`, lines 170-183

```rust
pub fn zip<M, U>(self, other: SecureValue<M, U, R>) -> ... {
    SecureValue {
        value: (self.value, other.value),
        resource_id: self.resource_id,   // other.resource_id silently dropped
        ...
    }
}
```

If `self` and `other` come from different resource instances (e.g., `customer/1` and `customer/2`), the combined value silently inherits only `self`'s resource id. A capability for `customer/1` will then grant access to the zipped value even though half of its contents came from `customer/2`.

**Fix:** Make `zip` verify that both resource ids match, or provide a `zip_unchecked` variant for cases where the caller has intentionally combined values from different instances and understands the implications:

```rust
pub fn zip<M, U>(self, other: SecureValue<M, U, R>)
    -> Result<SecureValue<...>, SecureValueError>
{
    if self.resource_id != other.resource_id {
        return Err(SecureValueError::ResourceIdMismatch { ... });
    }
    Ok(SecureValue { value: (self.value, other.value), resource_id: self.resource_id, ... })
}
```

---

### Q-9 (**high**) `Token` should implement `Zeroize` and `ZeroizeOnDrop`

**File:** `crates/typesec-core/src/typestate.rs`

`Token` wraps a raw secret string (`Token(String)`). When the agent authenticates and the `Token` is dropped, the secret stays in heap memory until the allocator overwrites it. On systems with core dumps or swap, this is a leak vector.

**Fix:** Add the `zeroize` crate to `typesec-core` and derive `ZeroizeOnDrop` for `Token`:
```rust
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct Token(String);
```

Also derive `Zeroize` for `Credentials`.

---

### Q-10 (**medium**) `SubjectId` and `ResourceId` should be newtypes, not bare `String`

**File:** `crates/typesec-core/src/capability.rs`

Both `Capability.subject` and `Capability.resource_id` are `String`. At every call site, callers pass two positional strings and the types cannot prevent transposition. A `Capability` for `(subject="reports/q1", resource_id="agent:test")` is a logic error that compiles silently.

**Fix:** Introduce:
```rust
pub struct SubjectId(String);
pub struct ResourceId(String);
```

Update `Capability`, `AuditEvent`, `PolicyEngine::check()` signature, and all `mint_capability*` functions to use these newtypes. Add `From<&str>` and `Display` impls for ergonomics.

---

### Q-11 (**medium**) `allow_if_all` should return the last `Deny` when all non-delegating engines deny

**File:** `crates/typesec-core/src/combinator.rs`, lines 122-149

The current `allow_if_all` returns `Deny(...)` immediately on the first denial (short-circuits). However, the strategy's semantics are "all non-delegating engines must Allow"—when only one engine exists and it denies, the current code returns that deny correctly. But when multiple engines deny, only the first denial reason is returned and the others are discarded, making audit trails for AllowIfAll compositions harder to trace.

While this is logically correct (one Deny is sufficient), consider collecting all denial reasons into a combined message for better observability:

```rust
let mut all_denies: Vec<String> = vec![];
// ... instead of early return, collect into all_denies
if !all_denies.is_empty() {
    return PolicyResult::Deny(all_denies.join("; "));
}
```

---

### Q-12 (**medium**) `LatticeEngine` may issue N+1 inner `check()` calls

**File:** `crates/typesec-core/src/lattice.rs`, lines 175-203

When a direct check fails, `LatticeEngine` tries every higher permission that implies the requested one. For `read`, this means up to 7 additional inner `check()` calls (all the permissions that imply read). For slow engines (WorkOS FGA, JWKS), this is O(N×M) work.

**Fix:** Short-circuit as soon as any higher permission yields `Allow`. The current code already does this for the inner loop, but also document this behavior and add a note in the crate docs that `LatticeEngine` wrapping a remote engine can amplify call volume.

Additionally, make `implied_by()` public so callers can pre-compute the set and cache it.

---

### Q-13 (**medium**) `OdrlEngine` is O(rules) per check—index at construction

**File:** `crates/typesec-odrl/src/engine.rs`

Every `check()` call iterates over all policies and all rules. For large ODRL documents (hundreds of rules), this is linear in the number of rules per request.

**Fix:** At construction time, build a `HashMap<(assignee, action), Vec<&OdrlRule>>` index. Rules with glob actions/targets can be stored separately in a small fallback list. The common case (exact assignee + exact action) becomes O(1) lookup.

---

### Q-14 (**medium**) `RbacEngine` doesn't support wildcard subjects

**File:** `crates/typesec-rbac/src/engine.rs`, line 125

Subject lookup is an exact `HashMap::get(subject)`. There is no way to write a policy like `agent:*` to match all agents, or `agent:deploy-*` to match a class of deploy agents. Resource patterns support globs; subject patterns do not—this asymmetry is surprising.

**Fix:** Add a second lookup pass for subjects that contain glob characters. After the exact lookup, check a pre-compiled list of subject glob patterns:

```rust
if let Some(grants) = self.subject_grants.get(subject) { ... }
// fall through to glob-pattern subjects
for (pattern, grants) in &self.wildcard_subject_grants {
    if pattern.matches(subject) { ... }
}
```

---

### Q-15 (**medium**) Public enums lack `#[non_exhaustive]`

The following public enums will be breaking changes if a variant is added:
- `PolicyResult` (`crates/typesec-core/src/policy.rs`)
- `CapabilityError` (`crates/typesec-core/src/policy.rs`)
- `CapabilityUseError` (`crates/typesec-core/src/capability.rs`)
- `AgentError` (`crates/typesec-core/src/typestate.rs`)
- `CombineStrategy` (`crates/typesec-core/src/combinator.rs`)
- `OdrlVerdict` (`crates/typesec-odrl/src/audit.rs`)

**Fix:** Add `#[non_exhaustive]` to all of the above. Update match arms in tests to add `_ => panic!("unexpected variant")` where needed.

---

### Q-16 (**medium**) `policy!` macro generates run-together lowercase names

**File:** `crates/typesec-macro/src/lib.rs`, line 261

```rust
let name_str = name.to_string().to_lowercase();
```

`role AnalystReadOnly { ... }` becomes name `"analystreadsonly"`. This conflicts with YAML-defined roles that use `snake_case` (`"analyst_read_only"`). The mismatch means a `policy!`-defined role can never interoperate with YAML-defined policies by name.

**Fix:** Convert `PascalCase` → `snake_case` using a utility function:
```rust
fn pascal_to_snake(s: &str) -> String {
    // insert '_' before each uppercase letter (after the first), then lowercase all
}
```

---

### Q-17 (**medium**) Missing `Display` implementation on `PolicyResult`

`PolicyResult` is returned from every engine check and appears in many error messages, but it only derives `Debug`. Callers format it with `{:?}` which produces Rust debug syntax, not human-readable output.

**Fix:** Implement `std::fmt::Display`:
```rust
impl fmt::Display for PolicyResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny(reason) => write!(f, "deny: {reason}"),
            Self::Delegate(to) => write!(f, "delegate to {to}"),
        }
    }
}
```

---

### Q-18 (**medium**) `set_audit_sink` panic on poisoned `RwLock`

**File:** `crates/typesec-core/src/policy.rs`, lines 144-146

```rust
pub fn set_audit_sink(sink: Arc<dyn AuditSink>) {
    *audit_sink_cell().write().expect("audit sink lock poisoned") = sink;
}
```

If a thread panics while holding the write lock, every subsequent call to `set_audit_sink` or `record_audit` will also panic. In production this is an unrecoverable failure for the entire policy subsystem.

**Fix:** Use `RwLock::write().unwrap_or_else(|poisoned| poisoned.into_inner())` to recover from poison, logging the event rather than crashing.

---

## Part 2 — Protocol and design tasks

### D-1 (**critical**) `check_with_context` is not in the `PolicyEngine` trait

**File:** `crates/typesec-odrl/src/engine.rs`, lines 49-151

`OdrlEngine::check_with_context()` accepts a `&ConstraintContext` for per-call purpose/time context—the only way to pass ODRL constraint inputs. But this method is **not** on the `PolicyEngine` trait, so any caller using `Arc<dyn PolicyEngine>` cannot supply a context. The `PolicyEngine::check()` impl calls `check_with_context` with `self.default_context`, meaning ODRL constraints become static globals once you box the engine.

This breaks the primary use case: enforcing purpose-limited access where the purpose is a runtime value from the calling agent's request.

**Fix:** Extend `PolicyEngine` with a context-aware variant:

```rust
pub trait PolicyEngine: Send + Sync {
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        self.check_with_context(subject, action, resource, &RequestContext::default())
    }

    fn check_with_context(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        ctx: &RequestContext,
    ) -> PolicyResult {
        self.check(subject, action, resource)  // default: ignore context
    }
}
```

Define `RequestContext` in `typesec-core` (purpose, custom k/v). Migrate `ConstraintContext` in `typesec-odrl` to use or wrap `RequestContext`. Update `mint_capability_with` to accept a context parameter.

---

### D-2 (**critical**) `RevocationEpoch` is coarse-grained; no per-subject or per-capability revocation

**File:** `crates/typesec-core/src/capability.rs`

`RevocationEpoch::revoke_all()` invalidates every capability sharing that epoch. In multi-tenant deployments, revoking a single compromised agent's capabilities requires revoking all agents' capabilities simultaneously—a major blast radius.

**Fix:** Design a `CapabilityRevocationList` (CRL) alongside the epoch approach:

```rust
pub struct CapabilityRevocationList {
    revoked: RwLock<HashSet<CapabilityId>>,
}

impl CapabilityRevocationList {
    pub fn revoke(&self, id: CapabilityId) { ... }
    pub fn is_revoked(&self, id: CapabilityId) -> bool { ... }
}
```

Add a `CapabilityId` (UUID or hash of subject+resource+issued_at) to `Capability`. Update `ensure_active()` to check both the CRL and the epoch. Provide a `MintOptions::with_revocation_list(Arc<CapabilityRevocationList>)` option.

---

### D-3 (**high**) `PolicyResult::Delegate` carries only a `String`; delegation chains are untyped

When an engine returns `Delegate("fallback")`, all type/context information about why delegation occurred is lost. In a composed engine with 3 levels, the outermost code only sees the final `Deny` with a string from the deepest non-delegating engine, making it impossible to trace which engine in the chain made the decision.

**Fix:** Replace the `String` in `Delegate` with a structured type:

```rust
pub enum PolicyResult {
    Allow,
    Deny(String),
    Delegate(DelegationReason),
}

pub struct DelegationReason {
    pub engine: &'static str,   // engine type name
    pub reason: String,
    pub context: Option<String>,
}
```

---

### D-4 (**high**) No `ToolRegistry` — `ProtectedTool` instances are isolated

**File:** `crates/typesec-agent/src/tool.rs`

`ProtectedTool<P, R, F>` wraps an async function with capability-gated invocation. However, there is no central registry of tools, so there is no way to:
- List what tools an agent can call
- Revoke authorization for a specific tool at runtime
- Audit which tools were called during a session
- Build MCP-compatible tool inventories

**Fix:** Implement a `ToolRegistry`:

```rust
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn ErasedTool>>,
}

impl ToolRegistry {
    pub fn register<P, R, F>(&mut self, tool: ProtectedTool<P, R, F>) { ... }
    pub fn list_specs(&self) -> Vec<&ToolSpec> { ... }
    pub fn invoke(&self, name: &str, cap: &dyn Any, input: Value) -> BoxFuture<'_, ToolResult> { ... }
}
```

`ToolSpec` should include permission requirements so MCP clients can display authorization needs before invocation.

---

### D-5 (**high**) DID key rotation has no public API

**File:** `crates/typesec-integrations/src/did.rs`

`Ed25519DidKeyStore` manages key material for DID-based identity, but there is no public method for rotating the signing key or revoking old verification keys. Key rotation is a fundamental operational requirement for any DID-based system.

**Fix:** Add to `Ed25519DidKeyStore`:
```rust
impl Ed25519DidKeyStore {
    /// Rotate the active signing key, archiving the old key for verification of
    /// in-flight messages signed with the prior key.
    pub fn rotate_key(&mut self) -> Result<Did, DidError>;

    /// Retire a key version (mark as revoked; old signatures from it are rejected).
    pub fn retire_key(&mut self, version: u64) -> Result<(), DidError>;

    /// The current active signing key version.
    pub fn active_key_version(&self) -> u64;
}
```

Expose key rotation status via the DID document so other agents can discover the current verification method.

---

### D-6 (**high**) `SecureValue` has no reveal path for `Internal`-labeled data

**File:** `crates/typesec-core/src/secure_value.rs`

The four privacy labels are `Public`, `Internal`, `Sensitive`, `Secret`. `Public` has `into_public()`. `Sensitive`/`Secret` have `reveal()` (requires `CanReadSensitive`). But `Internal` data has **no designated reveal path**. The only way to extract `Internal` data is to hold `CanReadSensitive` (which is a higher privilege than needed) or to use `declassify()` (which requires `CanDeclassify`, even higher).

**Fix:** Add `CanReadInternal` to the permission lattice and an `into_internal()` / `reveal_internal()` method:

```rust
impl<T, R: Resource> SecureValue<Internal, T, R> {
    pub fn reveal_internal(
        self,
        cap: &Capability<CanReadInternal, R>,
    ) -> Result<T, SecureAccessError> { ... }
}
```

Add `CanReadSensitive: Implies<CanReadInternal>` to the lattice.

---

### D-7 (**high**) ODRL prohibition early-exit skips remaining permission rules for auditing

**File:** `crates/typesec-odrl/src/engine.rs`, line 97

```rust
OdrlRuleType::Prohibition if all_passed => {
    ...
    break 'policies;  // stops scanning all remaining rules
}
```

When a prohibition matches, the engine stops scanning. If a later policy in the document contained a more specific matching permission rule, it would never be evaluated—and crucially, never logged. In an audit trail, the absence of a logged permission match can be misleading: operators see a prohibition but no corresponding permit evaluation.

**Fix:** Continue scanning after a prohibition match solely for audit purposes. Collect all permission matches into a `Vec` and emit audit events for them (with status `Overridden`), then emit the prohibition verdict. The final `PolicyResult` remains `Deny`.

---

### D-8 (**medium**) `OdrlConstraint.left_operand` is a bare `String`

**File:** `crates/typesec-odrl/src/model.rs` and `constraint.rs`

The constraint operand is matched against literal strings (`"purpose"`, `"dateTime"`) in the evaluator. A typo in a YAML policy (`"purposr"`) silently produces a constraint that never matches—meaning it never constrains, which means a prohibition could silently stop prohibiting.

**Fix:** Define a typed enum:
```rust
pub enum ConstraintOperand {
    Purpose,
    DateTime,
    Count,
    Custom(String),
}
```

Implement `Deserialize` for `ConstraintOperand` that maps known strings to typed variants and unknown strings to `Custom`. The evaluator then uses exhaustive matching, making unknown operands visible at parse time.

---

### D-9 (**medium**) `policy!` macro DSL does not support role inheritance

**File:** `crates/typesec-macro/src/lib.rs`

The YAML RBAC model supports `inherits: [parent_role]` on roles. The `policy!` macro DSL has no equivalent syntax. Users who start with the macro for ergonomics can't express inheritance and must switch entirely to YAML, creating a capability gap that's not documented.

**Fix:** Extend the DSL:

```rust
policy! {
    role Reader {
        can [read] on ["docs/*"];
    }
    role Writer extends Reader {
        can [write] on ["docs/*"];
    }
}
```

In the macro expansion, collect the parent role's permissions and emit them into the child's `Role::permission_names()` / `role_patterns()` arrays (flatten at macro-expansion time, mirroring `RbacEngine::flatten_role`).

---

### D-10 (**medium**) `AgentBuilder::with_composed_engine` hardcodes `PriorityOrder`

**File:** `crates/typesec-agent/src/agent.rs`, lines 212-229

```rust
pub fn with_composed_engine(self, primary: Arc<dyn PolicyEngine>, fallback: Arc<dyn PolicyEngine>) -> Self {
    // PriorityOrder is hardcoded
    let engine = PolicyEngineBuilder::new()
        .add_engine(primary)
        .add_engine(fallback)
        .strategy(CombineStrategy::PriorityOrder)
        .build();
    ...
}
```

Users who want `DenyOverrides` (XACML security baseline) or `AllowIfAll` (zero-trust all engines must agree) for a two-engine composition have to abandon `AgentBuilder` and wire `PolicyEngineBuilder` manually. The shortcut method trains users to always use `PriorityOrder`.

**Fix:** Add an overload:
```rust
pub fn with_composed_engine_strategy(
    self,
    primary: Arc<dyn PolicyEngine>,
    fallback: Arc<dyn PolicyEngine>,
    strategy: CombineStrategy,
) -> Self { ... }
```

And deprecate `with_composed_engine` in favor of the more expressive version, or add a `strategy` parameter with `PriorityOrder` as the default.

---

### D-11 (**medium**) CLI `run` command simulates a single agent; doesn't support multi-agent composition

**File:** `crates/typesec-cli/src/commands/run.rs`

The `run` subcommand simulates a single `SecureAgent` making a request. Real deployments involve multiple agents with different roles calling each other (agent A hands a delegated capability to agent B). There is no way to simulate delegation chains or inter-agent authorization flows from the CLI.

**Fix:** Extend the `run` command to accept a `--scenario` YAML file describing a multi-step flow:

```yaml
scenario:
  - agent: "agent:summarizer"
    policy: "./policies/rbac.yaml"
    action: read
    resource: "customer-data"
    purpose: "analytics"
  - agent: "agent:reporter"
    receives_delegation_from: "agent:summarizer"
    action: write
    resource: "report/q1"
```

Each step's output (allowed/denied, capability details) feeds into the next, and the full trace is printed to stdout.

---

### D-12 (**medium**) Python `check()` free function re-parses and validates policy on every call

**File:** `crates/typesec-python/src/lib.rs`, lines 124-136

The module-level `check()` function (not the `TypesecGate` method) builds a fresh engine for every call with no caching. While the class-based `TypesecGate` is the recommended path, this free function is the simplest entry point and will be misused in hot paths.

**Fix:** Add a module-level LRU cache keyed on `(policy_yaml_hash, format)`:
```rust
use std::sync::LazyLock;
use std::collections::HashMap;

static ENGINE_CACHE: LazyLock<Mutex<HashMap<u64, Arc<dyn PolicyEngine>>>> = ...;
```

Or, more simply, add a docstring warning that the free function is for one-shot use and users should prefer `TypesecGate` for repeated checks.

---

## Part 3 — Testing tasks

### T-1 (**critical**) Add property-based tests for permission lattice laws

The `Implies<Q>` trait encodes a partial order. Partial orders have mathematical laws that are not tested:

- **Reflexivity**: every permission should imply itself (currently not even in the lattice—verify this is intentional or add it)
- **Transitivity**: if `A: Implies<B>` and `B: Implies<C>`, then `A: Implies<C>` must also be in the lattice
- **Antisymmetry**: if `A: Implies<B>` and `B: Implies<A>`, then `A == B` (i.e., no cycles)

The IMPLICATIONS static table is the ground truth for runtime lattice checks, and it's manually maintained. A typo could create an asymmetry where compile-time coerce succeeds but `LatticeEngine` runtime promotion does not.

**Fix:** Add `proptest` to `typesec-core` dev-dependencies and write:
1. A test that for every `(higher, lower)` pair in `IMPLICATIONS`, `implied_by(lower())` contains `higher()`.
2. A test that no pair `(A, B)` in IMPLICATIONS also has `(B, A)` (no cycles).
3. A test that the transitive closure is complete (if A→B and B→C, then A→C is in the table).

---

### T-2 (**high**) Add cargo-fuzz targets for YAML policy parsers

Both `RbacPolicy::from_yaml` and `OdrlDocument::from_yaml` are entry points for untrusted user input (policy files from the filesystem, REST APIs, Kubernetes ConfigMaps). They use `serde_yaml` which has had parsing vulnerabilities in the past.

**Fix:** Create `fuzz/fuzz_targets/rbac_yaml.rs` and `fuzz/fuzz_targets/odrl_yaml.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(yaml) = std::str::from_utf8(data) {
        let _ = typesec_rbac::RbacPolicy::from_yaml(yaml);
    }
});
```

Run with `cargo fuzz run rbac_yaml -- -max_total_time=300` in CI for at least 5 minutes per push.

---

### T-3 (**high**) Add cross-engine integration tests for `LatticeEngine(ComposedEngine([Rbac, Odrl]))`

No existing test exercises the full stack: `LatticeEngine` wrapping `ComposedEngine([RbacEngine, OdrlEngine])` with `DenyOverrides`. The individual engines have unit tests, but composition—where engine ordering, lattice promotion, and ODRL constraints interact—is not tested.

**Fix:** Add `crates/typesec-core/tests/engine_composition.rs` (or `crates/typesec-agent/tests/`) covering:

1. RBAC grants `write`; ODRL has no rule for `read`; `LatticeEngine` should promote `write→read` via RBAC.
2. RBAC grants `read`; ODRL prohibits `read` for purpose `"training"`; `DenyOverrides` should deny even though RBAC allows.
3. `PriorityOrder`: ODRL delegates (no matching rule), RBAC allows → Allow.
4. `AllowIfAll`: both RBAC and ODRL must allow; one Deny → Deny.

---

### T-4 (**high**) Add trybuild tests for compile-time enforcement of permission forgery prevention

The sealed trait mechanism prevents external code from implementing `Permission`. This is a critical security property that should be verified as a compile-time test, not just asserted in comments.

**Fix:** Add `trybuild` to dev-dependencies in `typesec-core` and create:

```
tests/ui/cannot_impl_permission.rs     → should fail to compile
tests/ui/cannot_construct_capability.rs → should fail to compile
tests/ui/cannot_create_new_agentstate.rs → should fail to compile
tests/ui/coerce_requires_implies.rs      → should fail (coerce without Implies bound)
```

Each file attempts the forbidden operation; `trybuild::TestCases::new().compile_fail(...)` asserts the compile error matches an expected message.

---

### T-5 (**high**) Add benchmarks for critical paths

No `benches/` directory exists. Without benchmarks, performance regressions in capability minting or RBAC checking are invisible in CI.

**Fix:** Create `crates/typesec-core/benches/policy_check.rs` and `crates/typesec-rbac/benches/rbac_check.rs` using `criterion`:

1. `bench_mint_capability_allow`: mint 1000 capabilities through an AllowAll engine.
2. `bench_rbac_check_hit`: 1000 checks that hit a matching grant.
3. `bench_rbac_check_miss`: 1000 checks against a policy with 50 roles and no match.
4. `bench_lattice_promotion`: 1000 checks requiring lattice promotion (read via write grant).
5. `bench_odrl_check_with_constraints`: 1000 checks through a 10-rule ODRL document with purpose constraint.
6. `bench_composed_engine_deny_overrides`: `ComposedEngine([RbacEngine, OdrlEngine], DenyOverrides)` × 1000.

Register benchmarks in Cargo.toml and add a `cargo bench` step to CI that fails if any benchmark regresses by >20%.

---

### T-6 (**medium**) Add tests for `SecureValue::zip` resource-id mismatch (after D-3 fix)

Once the `zip` safe-by-default fix (Q-8 / D-3) lands, add tests:

1. `zip_same_resource_ids_succeeds` — both values from same instance, result is OK.
2. `zip_different_resource_ids_fails` — different instances, result is Err.
3. `zip_label_promotion` — `Public.zip(Secret)` → `Secret` label.
4. `zip_preserves_resource_id` — result's resource_id matches both inputs.

---

### T-7 (**medium**) Test RBAC cycle detection at engine construction time

**File:** `crates/typesec-rbac/src/model.rs`

`RbacPolicy::validate()` detects cycles in role inheritance and returns an error. The `RbacEngine::new()` calls `validate()` and propagates the error. But there are no tests that verify this path exercised in `RbacEngine::new()` specifically (only in the model's own tests, if they exist).

**Fix:** Add to `crates/typesec-rbac/src/engine.rs` tests:

```rust
#[test]
fn cyclic_role_inheritance_fails_engine_construction() {
    let yaml = r#"
roles:
  - name: a
    inherits: [b]
    permissions: [read]
    resources: ["*"]
  - name: b
    inherits: [a]
    permissions: [write]
    resources: ["*"]
assignments:
  - subject: "agent:x"
    roles: [a]
"#;
    assert!(RbacEngine::from_yaml(yaml).is_err());
}
```

---

### T-8 (**medium**) Test Python bindings round-trip for all three engine formats

**File:** `crates/typesec-python/src/lib.rs`

The Python module has no Rust unit tests (it relies on Python-level testing, which isn't checked in). Add Rust-level tests in the same file covering:

1. `TypesecGate` with RBAC policy: allow, deny, and unknown subject.
2. `TypesecGate` with ODRL policy: allow with matching purpose, delegate without purpose.
3. `TypesecGate` with graph policy: basic allow path.
4. `validate()` free function rejects malformed YAML.
5. `check()` free function returns correct `Decision.allowed` values.
6. `require()` raises `PyPermissionError` on deny.

Use `pyo3::Python::with_gil(|py| { ... })` to invoke the Python methods from Rust tests.

---

## Summary of task counts by priority

| Priority | Count |
|---|---|
| Critical | 5 |
| High | 23 |
| Medium | 18 |

**Recommended implementation order for Codex:**

1. Q-1 (Python engine caching) — pure perf win, low risk
2. Q-7 (`#[must_use]`) — purely additive, no logic changes
3. Q-15 (`#[non_exhaustive]`) — purely additive
4. Q-17 (`Display` for `PolicyResult`) — purely additive
5. D-1 (`check_with_context` in trait) — unblocks real ODRL usage
6. Q-8 (`zip` safety) — correctness fix
7. T-1 (lattice property tests) — high confidence check of invariants
8. T-4 (trybuild compile-fail tests) — verify security guarantees
9. Q-2/Q-3 (async audit/engine) — larger refactor, do after above settled
10. D-2 (per-capability revocation) — significant API surface, design carefully
