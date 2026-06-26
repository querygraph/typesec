# Announcing Typesec: authority you can't forget at the call site

*June 2026 — Typesec 0.10.0 "Murano"*

Most authorization systems answer a question — *is this allowed?* — and then trust
every line of code after the check to remember the answer. The check and the
privileged action drift apart. A new code path forgets the guard. A refactor
moves the call. The audit log says "allowed" while the wrong thing happens.

**Typesec** is a type-safe security framework for Rust that closes that gap. It
turns authority into a value the compiler tracks: a function that does something
privileged *demands a capability as an argument*, and the only way to get one is
to pass a policy check. Forgetting the guard becomes a type error, not a
production incident.

## The load-bearing idea

A `Capability<P, R>` is unforgeable proof that permission `P` was granted over
resource `R`. It has **no public constructor**. The only way to mint one in
production is `mint_capability*`, which runs a `PolicyEngine`, and — on success —
emits an audit event. `Permission`, `AgentState`, and `PrivacyLevel` are sealed
traits, and a suite of compile-fail tests stands guard so the boundary can't be
bypassed even by accident.

The payoff: provider authorization isn't merely *observed*, it *becomes* a typed
capability required by the handler. You cannot call the privileged path without
proof, and the proof cannot exist without a policy decision and an audit trail.

## What's inside

- **One policy contract, many engines.** Every engine implements the same
  `check_with_context → Allow | Deny | Delegate` interface: an **RBAC** engine
  (role inheritance + glob patterns), an **ODRL** engine (permission /
  prohibition / duty, constraints, full audit trail), and a **graph** engine
  that compiles policy into a typed graph with deny-overrides semantics.
- **Typestate agents.** `SecureAgent<S>` and `ProtectedTool` push authorization
  into the type state of an agent, so a tool can only fire once the agent holds
  the capability it requires.
- **Integrations, not replacements.** JWT/OIDC, WorkOS FGA, Arcade tool auth, and
  Pydantic AI all feed the *same* `PolicyEngine` boundary. Typesec sits under
  your existing OAuth stack and makes the local last mile impossible to skip.
- **DID / TypeDID messaging.** Real cryptography (Ed25519 / X25519 /
  ChaCha20-Poly1305): agent-to-agent envelopes whose ciphertext is AEAD-bound to
  their routing and timing identity, with replay protection and audit-safe
  attestations that expose *who did what to which resource* without revealing the
  payload.
- **Typed privacy labels.** `SecureValue<L, T, R>` classifies data at the type
  level, so a value's privacy level travels with it.
- **CLI + Python bindings.** `typesec validate / check / generate / run` gives CI
  a policy gate with honest exit codes, and PyO3 bindings put the same checks in
  front of non-Rust agents.

## Typesec in querygraph

Typesec and the **Grust** typed-graph engine ship from the same home,
[querygraph](https://github.com/querygraph). Typesec's graph policy engine builds
directly on Grust's typed graph: policies lower through Zod-validated schemas into
a Grust graph, deny-overrides resolution decides the verdict, and `grust-cypher`
can apply Cypher DDL constraints or run an *authorized* Cypher mutation through
the same graph-store boundary. The result is graph-shaped authorization — roles,
resources, and relationships as a typed graph — with the same unforgeable
capability at the end of it. (Typesec 0.10.0 tracks Grust 0.11.0, "Crab.")

## Typesec in lakecat

In **lakecat**, Typesec guards data-catalog resources — tables and datasets named
like `lakecat:table:events`. A reader doesn't get the table by asking nicely; it
gets a `Capability` minted against the catalog's policy, and the typed value it
reads back carries its privacy label. When agents collaborate over that data,
TypeDID envelopes carry an **audit-safe attestation** of the authorized action —
subject, action, resource, privacy level, protocol — so the catalog has a
verifiable record of every cross-agent access without ever exposing the payload
or the signing material.

## Try it

Typesec 0.10.0 is published on crates.io:

```toml
[dependencies]
typesec = { version = "0.10.0", features = ["integrations"] }
```

- **The book** — the full design narrative, worked examples, and design
  tradeoffs: `docs/book/typesec.md` (also built as EPUB / PDF / MOBI under
  `docs/book/dist/`).
- **Where Typesec fits under OAuth/FGA stacks:**
  `docs/typesec-and-auth-frameworks.md`.
- **Agent-to-agent messaging:** `docs/typedid-agent-communications.md`,
  `docs/did-messaging.md`, and `docs/typedid-ecosystem.md`.
- **Graph policy end to end:** `docs/company-graph-grust-sail.md`.
- **Provider integrations:** `docs/oauth-provider-integrations.md`.

The check is the easy part. Typesec makes sure the line of code *after* the
check can't forget what it said.
