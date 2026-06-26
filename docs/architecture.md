# Typesec architecture

Diagrams for the load-bearing pieces of Typesec. They render on GitHub and in any
Mermaid-aware viewer. For the prose walkthrough see the book
([`docs/book/typesec.md`](book/typesec.md)); for a runnable version of the core
loop see [`examples/core_capability.rs`](../examples/core_capability.rs).

## The capability-minting flow

The single load-bearing invariant: a `Capability` is unforgeable proof, and the
*only* production path to one is `mint_capability*`, which runs a `PolicyEngine`
and emits an audit event. A denial yields a typed error, never a capability.

```mermaid
flowchart LR
    R["Request:<br/>subject + action + resource"] --> E{"PolicyEngine<br/>check_with_context"}
    E -->|Allow| M["mint_capability*"]
    E -->|"Deny(reason)"| D["Err: CapabilityError::Denied"]
    E -->|"Delegate"| FB{"fallback engine?"}
    FB -->|yes| E
    FB -->|no| U["Err: UnhandledDelegation"]
    M --> A[("AuditEvent<br/>(always emitted)")]
    M --> C["Capability P,R<br/>unforgeable proof"]
    C --> G["guarded fn that<br/>demands Capability P,R"]

    classDef ok fill:#e6ffed,stroke:#2da44e;
    classDef bad fill:#ffebe9,stroke:#cf222e;
    class M,C,G ok;
    class D,U bad;
```

The proof cannot exist without a policy decision, and the privileged function
cannot be reached without the proof.

## Workspace layering

Nine crates. Everything is built on `typesec-core`; the umbrella `typesec` crate
re-exports the rest behind feature flags.

```mermaid
flowchart TD
    core["typesec-core<br/>Capability · PolicyEngine · SecureValue · typestate · glob"]
    macro["typesec-macro<br/>#derive(TypesecRole) · policy!"]
    rbac["typesec-rbac<br/>RBAC + Graph engines"]
    odrl["typesec-odrl<br/>ODRL engine + audit"]
    agent["typesec-agent<br/>SecureAgent · ProtectedTool"]
    integ["typesec-integrations<br/>JWT · WorkOS · Arcade · DID/TypeDID"]
    cli["typesec-cli<br/>validate · check · generate · run"]
    py["typesec-python<br/>PyO3 bindings"]
    facade["typesec<br/>(feature-gated facade)"]

    macro --> core
    rbac --> core
    odrl --> core
    integ --> core
    agent --> core
    agent --> rbac
    agent --> odrl
    py --> core
    py --> rbac
    py --> odrl
    cli --> core
    cli --> rbac
    cli --> odrl
    cli --> agent
    cli --> integ
    facade --> core
    facade --> rbac
    facade --> odrl
    facade --> agent
    facade --> integ
    facade --> macro
```

## One policy contract, many engines

Every engine implements the same `check_with_context` → `Allow | Deny |
Delegate` interface, so they compose. `ComposedEngine` folds several engines
under a strategy (priority, deny-overrides, allow-if-any); `FallbackEngine`
chains a primary to a secondary on `Delegate`.

```mermaid
flowchart TD
    I["PolicyEngine check_with_context<br/>→ Allow | Deny(reason) | Delegate(reason)"]
    rbac["RbacEngine<br/>roles + inheritance + glob"] --> I
    gpe["GraphPolicyEngine<br/>typed graph + deny-overrides"] --> I
    odrl["OdrlEngine<br/>permission/prohibition/duty + constraints"] --> I
    prov["Provider engines<br/>JWT · WorkOS · Arcade"] --> I
    composed["ComposedEngine / FallbackEngine<br/>combine the above"] --> I
```

## The agent typestate

`SecureAgent<S>` is a typestate machine. The capability-requesting and
`execute` methods exist *only* on the `Authenticated` state — an unauthenticated
agent literally has no such methods to call.

```mermaid
stateDiagram-v2
    [*] --> Unauthenticated
    Unauthenticated --> Authenticated: authenticate_with
    Authenticated --> Authenticated: request_capability
    Authenticated --> Authenticated: execute
    note right of Unauthenticated
      request_capability and execute do not
      exist on this state — calling them is
      a compile error
    end note
```

## DID / TypeDID agent-to-agent messaging

When agents collaborate, a prompt is sealed into a DID envelope whose ciphertext
is AEAD-bound to its routing/timing identity. The gateway verifies signature,
replay, and expiry, then the plaintext is revealed only under a typed
capability — and an audit-safe attestation records who did what to which
resource, without exposing the payload.

```mermaid
sequenceDiagram
    participant A as Agent A (sender)
    participant G as TypeDID Gateway (recipient)
    participant P as PolicyEngine
    A->>A: seal(prompt) → DID envelope<br/>(Ed25519 sign + ChaCha20-Poly1305, AAD-bound)
    A->>G: envelope
    G->>G: verify signature · reject replay · check expiry
    G->>P: mint_capability(subject, action, resource)
    P-->>G: Allow → Capability
    G->>G: reveal payload under the capability
    G-->>A: audit-safe attestation<br/>(subject, action, resource, privacy — no payload)
```
