# Changelog

All notable changes to this repository are recorded here. Keep entries grouped
by release version, then by the date the logical change landed.

## Unreleased

### 2026-06-13

- Added RBAC wildcard subject assignments with compiled glob validation, typed
  ODRL constraint operands, prohibition-overridden ODRL audit events, and
  snake_case role names for multiword `policy!` roles.
- Added forward-compatible public policy enums and structured delegation
  reasons so CLI, Python, audit, and composed-engine output can report which
  engine abstained and why.
- Hardened runtime security internals with typed UTC audit timestamps,
  source-preserving engine errors, zeroizing bearer tokens and credentials, and
  Python free-function documentation that steers repeated checks to
  `TypesecGate`.
- Added a core `RequestContext` path for purpose/custom request metadata,
  plumbed it through policy minting, fallback/composed/lattice engines, ODRL,
  CLI checks/runs, and Python policy gates.
- Added compile-fail tests for sealed permissions, sealed agent states,
  private capability construction, and invalid upward capability coercion.
- Added lattice invariant tests and cross-engine integration coverage for
  lattice promotion over composed engines, request-context-aware ODRL
  prohibitions, `PriorityOrder`, and `AllowIfAll`.
- Improved composition observability by collecting all `AllowIfAll` denial
  reasons and documenting lattice promotion call amplification.
- Cached compiled policy engines inside the Python `TypesecGate` so repeated
  checks no longer reparse policy YAML, while preserving per-call ODRL purpose
  context.
- Hardened `SecureValue::zip` to reject values from different resource ids
  instead of silently inheriting the left-hand resource id.
- Added policy decision ergonomics and guardrails: `PolicyResult` display
  formatting, `#[must_use]` annotations for policy decisions and capability
  use paths, audit-sink lock poisoning recovery, cheaper revocation epoch
  atomics, and explicit agent-builder composition strategies.
- Added regression coverage for Python RBAC/ODRL/graph gates and RBAC cyclic
  inheritance rejection during engine construction.

## 0.6.0

### 2026-06-12

- Added a TypeDID ecosystem strategy covering LangChain, Pydantic AI, MCP,
  BAND, WorkOS, and Arcade, plus Python framework-adapter examples and smoke
  tests that use `typesec check --json` as the policy seam.
- Added repository guidance requiring completed units of work to be
  changelogged and committed separately before starting work from a new prompt.
- Implemented TypeDID agent communications with DID-wrapped send and
  request/reply modes, secure profile negotiation, A2A/ACP/BAND/HTTPS
  adapters, examples, tests, and documentation.
- Updated TypeSec's `grust-graph` dependency and user-facing example snippets
  from 0.6.0 to 0.6.2.
- Prepared the 0.6.0 release by bumping workspace crate versions, Python
  package metadata, release-facing docs, and generated book artifacts; verified
  the release-prep path with workspace metadata, build, test, Python smoke,
  DID/TypeDID examples, book validation, and package checks.

### 2026-06-12 (Claude follow-up after the 0.5.0 hardening pass)

All changes below were made *after* commit `16cf54c` ("Add changelog and
repository guidance") and address the review concerns that remained open after
the "Harden Typesec credential and capability boundaries" commit (`60f59c5`):
remaining dependency hygiene, bearer-token log leakage, blocking HTTP inside
async capability requests, fixed capability TTLs, and the lack of mid-lease
revocation.

- **Mid-lease capability revocation** (`typesec-core`): added
  `RevocationEpoch` (a cheap, cloneable shared atomic counter) in
  `crates/typesec-core/src/capability.rs`. Capabilities minted with one record
  the counter value at mint time; `RevocationEpoch::revoke_all()` bumps the
  counter and every previously minted capability then fails
  `Capability::ensure_active()` with the new
  `CapabilityUseError::Revoked { minted_epoch, current_epoch }` variant.
  `Capability::is_revoked()` is the non-erroring probe. Capabilities minted
  without an epoch are never revoked (TTL still applies). This closes the
  TOCTOU window the TTL alone could not: policy reloads can now kill live
  capabilities immediately.
- **Configurable capability TTL** (`typesec-core`): added
  `policy::MintOptions { ttl, revocation }` (defaults:
  `DEFAULT_CAPABILITY_TTL` = 300 s, no revocation) plus
  `mint_capability_with(engine, subject, &resource, &options)` and
  `mint_capability_for_id(engine, subject, resource_id, &options)`. Plain
  `mint_capability` is unchanged in behavior and now delegates to
  `mint_capability_for_id` with defaults. The `_for_id` variant exists so
  async callers can move owned strings onto a blocking thread; the minted
  capability is bound to the given id exactly as before, and all consumption
  sites (`execute`, `reveal`, `declassify`) still compare ids at use time.
  Internally, `Capability::new_minted(subject, id, issued_at, ttl, revocation)`
  is now the single production constructor; `new_unchecked` /
  `new_with_issued_at` are `#[cfg(test)]`-only. `coerce`/`coerce_ref` now go
  through a private `Capability::derive`, which preserves the *full* lease
  (issue time, expiry, and revocation binding) so a downgraded capability is
  never longer-lived than its source — previously `coerce_ref` re-derived
  expiry from the default TTL.
- **Bearer tokens no longer leak through `Debug`** (`typesec-core`,
  `typesec-integrations`): `typestate::Credentials.token` changed from
  `String` to the new `typestate::Token` newtype, which redacts its contents
  from `Debug` (prints `Token(<redacted>)`) and intentionally implements
  neither `Display` nor `PartialEq` (equality against a guess would be a
  brute-force oracle — same rationale as `SecureValue`). Call
  `Token::expose()` at the single point a verifier needs the raw secret;
  `Token::is_empty()` covers the shape check. `Credentials::new` still accepts
  `impl Into<String>`-ish arguments via `impl Into<Token>` (a blanket
  `From<S: Into<String>>` exists), so call sites did not change.
  `JwtAuthenticator::verify_credentials` was updated to
  `credentials.token.expose()`.
- **Async executor no longer blocked by policy I/O** (`typesec-agent`):
  `SecureAgent::request_capability` now runs the policy check + mint inside
  `tokio::task::spawn_blocking`, because engines may do blocking HTTP (JWKS
  fetch in `JwtAuthenticator`, WorkOS FGA via the `reqwest::blocking`-based
  `ReqwestHttpClient` in `typesec-integrations/src/http.rs`, which is
  unchanged). A `JoinError` maps to `CapabilityError::EngineError`. Also added
  `SecureAgent::request_capability_with(resource, MintOptions)` to plumb
  custom TTLs and `RevocationEpoch` bindings from the agent layer.
- **Dependency hygiene** (workspace `Cargo.toml`): `serde_yaml 0.9`
  (archived/unmaintained) replaced by the API-compatible maintained fork via
  package rename — `serde_yaml = { package = "serde_norway", version = "0.9" }`
  — so all `serde_yaml::` source paths still compile untouched. Note:
  `serde_yaml 0.9.34+deprecated` still appears in `Cargo.lock` transitively
  via `grust-core` (external sibling dependency, not fixable here).
  `thiserror` bumped `1` → `2` (no source changes needed).
- **New re-exports** from `typesec_core`: `RevocationEpoch`, `MintOptions`,
  `mint_capability_with`, `mint_capability_for_id`, `typestate::Token`.
- **New tests**: revocation-epoch invalidation and custom-TTL expiry (in both
  `capability.rs` and `policy.rs`), no-binding-never-revoked, and
  `Credentials` `Debug` redaction. Full workspace `cargo test`, `cargo clippy
  --all-targets`, and example builds pass clean.
- Deliberately **not** changed: `ReqwestHttpClient` stays a blocking client
  (now safe because agent-layer calls are wrapped in `spawn_blocking`); an
  async-native `HttpClient` trait remains possible future work.
- **Docs and book updated for the above** (per `docs/book/PUBLISH.md`):
  - `docs/book/typesec.md`: `Capability` struct listing now shows the lease
    fields (`issued_at`, `expires_at`, `revocation`) and `new_minted` as the
    hidden constructor; the Minting section documents `MintOptions`,
    `mint_capability_with`, `mint_capability_for_id`, and a `RevocationEpoch`
    example; the Typestate section replaces the stale "intentionally small
    `authenticate`" description with `authenticate_with`/`Authenticator`,
    `authenticate_unverified`, and the `Token` redaction story; the
    `typesec-agent` section documents `request_capability_with` and the
    `spawn_blocking` policy-check path; the Design Tradeoffs and Roadmap
    sections now treat in-process revocation as done and *distributed*
    revocation (policy-version binding / shared epoch service) as the next
    step; "What We Improved" gained two paragraphs covering the 0.5.0
    hardening pass and this follow-up.
  - `README.md`: the agent walkthrough notes the blocking-pool policy check
    and `request_capability_with(MintOptions)` / `RevocationEpoch`.
  - `docs/improvements.md`: moved the implemented items into "What Was
    Improved" and refocused the revocation gap on distributed epochs.
  - Rebuilt `docs/book/dist/typesec.{pdf,epub,mobi}` with `docs/book/build.sh`;
    `check_epub_metadata.sh` passes, PDF cover page has no printed number and
    body numbering starts at 1 on page 2, the `typesec (0.5.0).epub` symlink
    and `VERSION.md` are intact (built_at: 2026-06-12).

### 2026-06-12

- Added this changelog and project guidance requiring it to be maintained with
  future user-visible, release, packaging, documentation, and book-publishing
  changes.
- Added guidance to keep local auxiliary testing and verification artifacts out
  of repository commits unless explicitly promoted to tracked assets.

## 0.5.0

### 2026-06-12

- Hardened the credential and capability boundary across `typesec-core`,
  `typesec-agent`, `typesec-integrations`, and the examples.
- Added stronger runtime checks for capability subject/resource matching,
  short-lived capability leases, secure-value extraction, typestate transitions,
  JWT handling, and DID envelope processing.
- Updated agent, RBAC, ODRL, provider, DID, and company-graph examples to use
  the stricter capability model.
- Updated Typesec for `grust-graph` 0.6.0 and refreshed graph-policy examples
  and docs to match the current typed schema API.
- Rebuilt the TypeSec book artifacts and refreshed the publishing runbook for
  the current 0.5.0 book output.

### 2026-06-11

- Added DID messaging as a first-class integration boundary in
  `typesec-integrations`, including resolver, key-store, encrypted-message, and
  Ollama client abstractions.
- Added the `examples/did_messaging.rs` offline demo and documented DID,
  Hyperledger, `did:key`, `did:web`, and `did:indy` integration paths.
- Updated the facade crate, README, OAuth/provider docs, improvements notes,
  examples guide, and book manuscript for DID-backed protected inference.
- Updated Typesec for `grust-graph` 0.5.0 and rebuilt the book for the 0.5.0
  release-prep state, including Kindle metadata and generated artifacts.
- Verified the 0.5.0 release-prep path with workspace metadata, package, build,
  test, CLI example, and book-artifact checks.

## 0.4.0

### 2026-06-10

- Strengthened graph policies with typed Grust schemas and added the
  `examples/company_graph/graph_policy_schema.rs` example.
- Updated the graph-policy engine and CLI validation/check flows for the typed
  schema model.
- Released the Elmarit 0.4.0 line, moved the book source from top-level `book/`
  to `docs/book/`, and refreshed release-facing docs and examples.
- Added Kindle/catalog metadata generation for the TypeSec book while keeping
  the visible title clean.
- Added `docs/book/dist/VERSION.md`, generated build dates, and stable
  `typesec.epub` plus versioned Kindle symlink behavior.
- Added EPUB layout repair and metadata validation scripts for cover order,
  title metadata, spine order, title-page suppression, and versioned artifacts.
- Stopped numbering the standalone book cover page and documented the
  no-number cover contract.
- Added `docs/book/PUBLISH.md` as the canonical TypeSec book publishing runbook.
- Compacted EPUB/MOBI code-block spacing and added validation for the CSS rules
  that prevent blank source lines from expanding vertically.

## 0.3.0

### 2026-06-07

- Added `typesec-integrations` for provider-specific engines and adapters,
  including JWT/OIDC claims, WorkOS FGA, Arcade-style tool authorization, and a
  deterministic HTTP client boundary for tests.
- Added `ProtectedTool` in `typesec-agent` so external provider authorization
  still requires a local typed capability before a tool can run.
- Added provider composition tests and `examples/provider_integrations.rs`.
- Added provider and OAuth comparison docs explaining how WorkOS, Arcade, OIDC,
  and Typesec fit together.
- Released and published the 0.3.0 workspace crates, including
  `typesec-integrations` and `typesec-python`.
- Updated repository ownership and embedded repository URLs from
  `alexy/typesec` to `querygraph/typesec`.

## 0.2.1

### 2026-06-07

- Added graph-policy support to `typesec-rbac`, including the
  `graph_policy:` policy format and corporate graph sample policy.
- Updated `typesec check` and `typesec validate` to recognize graph-policy YAML.
- Updated company-graph docs and examples for Grust-backed policy checks.
- Added Python integration support with the `typesec-python` PyO3 crate.
- Added a shared `company_graph_core.py` layer plus LangChain-style and
  Pydantic AI adapters for Python policy gates.
- Added repo-pinned Python tooling through `.tool-versions`, `pyproject.toml`,
  `uv.lock`, and Python smoke tests.
- Made the CLI fail closed for delegated policy decisions so Python-facing gates
  cannot silently pass unresolved authorizations.

## 0.2.0

### 2026-06-06

- Added `SecureValue` for labeled protected data, including privacy-label
  combination behavior and capability-gated extraction.
- Added sensitive read/write permissions and secure-value exports through the
  facade crate.
- Updated RBAC examples and documentation to show secure values in use.
- Added the cleaned David Andrzejewski Scale By the Bay transcript as design
  context for typed information-flow control.
- Rebuilt the design book artifacts and removed repository-publishing notes
  from reader-facing book content.
- Added a separate book cover page and documented the book cover build flow.

## 0.1.0

### 2026-06-06

- Created the initial Typesec Rust workspace with `typesec-core`,
  `typesec-rbac`, `typesec-odrl`, `typesec-agent`, `typesec-macro`, and
  `typesec-cli`.
- Added unforgeable typed capabilities, sealed permissions, typestate agent
  foundations, policy engines, audit logging, RBAC YAML loading/code generation,
  ODRL constraint evaluation, and CLI commands for validate/check/generate/run.
- Added initial Rust examples for RBAC, ODRL, and Grust/Sail company-graph
  policy checks.
- Added Python smoke tests around the CLI policy boundary.
- Added the initial README, architecture docs, improvement notes, and policy
  fixtures.
- Added the TypeSec design book and generated PDF, EPUB, and MOBI artifacts.
- Organized company-graph examples under `examples/company_graph/` and added
  `examples/README_examples.md` with install/run guidance.
- Added the top-level `typesec` facade crate and prepared/published the first
  crate set.

## 0.0.0

### 2026-06-06

- Created the repository with the initial license.
