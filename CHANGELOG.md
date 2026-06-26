# Changelog

All notable changes to this repository are recorded here. Keep entries grouped
by release version, then by the date the logical change landed.

## Unreleased

### 2026-06-26 — review follow-ups

Workspace-wide quality/DRY/test-coverage review (five-area pass). Changes land as
focused commits; structure was already sound (no monoliths; tests in sibling
files), so the work is DRY consolidation, test-gap filling, and small hardening.

- **typesec-core:** re-exported `CapabilityError` and `AgentError` at the crate
  root (every public `mint_capability*` / `authenticate_*` fn can now have its
  error named by callers) plus `GenericResource`. Extracted the last inline test
  module (`permissions.rs`) into a sibling `permissions/tests.rs`. DRY: the
  sync/async mint paths now share one `audit_event` builder so they can't drift
  in which fields they record, and the three poisoned-audit-lock recovery sites
  collapse to one `recover` helper. Added the previously-missing tests for the
  async `ComposedEngine` and `FallbackEngine` drivers (the "sync/async fold can't
  diverge" guarantee was asserted but untested), the `UnhandledDelegation` mint
  path, `mint_capability_with_async`, `Capability::is_fresh`, custom
  `RequestContext` values, `DelegationReason` display, and empty-token auth
  rejection.
- **typesec-integrations:** DRY — the prompt / reply / typedid envelope
  constructors now share one private `seal()` (resolve → encrypt → sign), the
  Ollama client shares `chat_endpoint`/`chat_body`/`post_chat` helpers, and the
  two HTTP test doubles share one `canned_response` lookup. Hardening — JWT
  validation no longer seeds from the token's own `header.alg` (starts from a
  default validator and installs only the config-permitted algorithms), and the
  JWKS cache lock recovers from poisoning instead of panicking (matching the
  gateway). Tests — added coverage for the gateway guard branches on the real
  Ed25519 path (`Expired`, `WrongRecipient`, `NotYetValid`, replay), the
  `PayloadTooLarge` negotiated-cap enforcement, WorkOS/Arcade
  deny/delegate/transport/parse arms, the Ollama `MissingOllamaReply` path, and
  the keystore rotation errors (`CannotRetireActiveKey`, `MissingKeyVersion`).

### 2026-06-26

- Docs: corrected the stale "Grust is a local path dependency, not on crates.io"
  claim in `CLAUDE.md` and the book. Grust is published on crates.io (the
  `grust-*` crates are at `0.11.0`, codename Crab); the workspace pins each with
  both a `version` and a local `path`, so local builds use the sibling `../grust`
  checkout while the `version` resolves against crates.io for published/sibling-
  less builds. This is also why Typesec itself publishes to crates.io (all eight
  crates released at `0.10.0`). Rebuilt the book artifacts.

## 0.10.0 — Murano

### 2026-06-26

Codename **Murano** — the second of the Venetian-landmark release line (after
Rialto). This release tracks the Grust **0.11.0 (Crab)** dependency and bumps
the workspace.

- Bumped the Grust path dependencies (`grust-graph`, `grust-cypher`,
  `grust-sail`) from `0.10.0` to `0.11.0` (Crab). The upgrade is source-
  compatible: `cargo build --workspace` and `cargo test --workspace` are green
  with no code changes to the typesec crates.
- Bumped the workspace and all internal path-dependency constraints (and
  `crates/typesec-python/pyproject.toml`) from `0.9.0` to `0.10.0`.
- Added `RELEASES.md`: documents the `0.MINOR.0` versioning, the
  Venetian-landmark codename pool, the per-release codename log, and the
  release-cutting checklist.

## 0.9.0 — Rialto

### 2026-06-25

Codename **Rialto** (Ponte di Rialto) — the first of the Venetian-landmark
release line. A workspace-wide human-reviewability refactor (every `.rs` file is
now ≤ ~406 lines, down from a 2635-line monolith; all unit tests live in their
own files; duplicated logic consolidated), plus DID-envelope security hardening,
ODRL audit-trail completion, a batch of correctness fixes, a comprehensive book
review, and a new CI pipeline.

- Bumped the workspace and all internal path-dependency constraints to `0.9.0`.
- Added a GitHub Actions CI workflow (`.github/workflows/ci.yml`): rustfmt
  (scoped to the typesec packages so the Grust path dependency isn't reformatted),
  clippy `-D warnings`, `cargo test --workspace`, and a benchmark smoke step
  (`cargo bench -- --test` runs every Criterion bench once) so a broken bench
  fails CI instead of rotting. CI checks out a sibling `querygraph/grust` for the
  local path dependency. Added `#![allow(dead_code)]` to the shared integration-
  test `common` module (each themed test binary uses only a subset of fixtures).
- Split the remaining oversized test files and the Python impl, so every `.rs`
  file in the workspace is now reviewable in one sitting: `did/tests.rs` (713)
  into a themed `did/tests/` directory (common + demo + ed25519 + ollama +
  typedid); `typesec-agent/tests/integration.rs` (624) into `tests/common/` plus
  themed `rbac_lattice`/`odrl_constraints`/`combinators`/`typestate_audit` files
  (with the inconsistent numeric test-name prefixes dropped); and
  `typesec-python/src/lib.rs` (403 → 237) into `format`/`engine`/`decision`
  modules (tests stay inline — the crate is `cdylib`).
- Bound DID envelope ciphertext to its routing/timing identity as AEAD
  associated data: `encrypt_for`/`decrypt_for` now take an `associated_data`
  argument (the envelope's `id`/`from`/`to`/`created_time`/`expires_time`), so the
  ChaCha20-Poly1305 tag — not just the Ed25519 signature — binds the ciphertext to
  its envelope and a captured ciphertext cannot be lifted into a different one. A
  keystore-level test verifies a mismatched AAD is rejected.
- Hardened `typesec-integrations` DID envelopes: the signed `signing_input` now
  covers `kid` and `nonce` (so neither can be swapped without breaking the
  Ed25519 signature); `DidMessageGateway` rejects replays of already-opened
  envelopes (a pruned signature cache) and envelopes dated implausibly far in the
  future (clock-skew bound); and `SecureEnvelopeAdapter::wrap` enforces the
  negotiated `max_payload_bytes` (previously advertised but never checked). New
  `DidError` variants: `Replayed`, `NotYetValid`, `PayloadTooLarge`. Binding
  envelope metadata as AEAD associated data remains a future defense-in-depth
  item — the signature is the primary integrity guarantee and now covers every
  field.
- Completed the `typesec-odrl` audit trail: rules that match the target but fail
  a constraint now emit an `OdrlVerdict::ConstraintFailed` event (previously
  dropped silently), and *all* matched permissions are logged on an Allow (not
  just the last). `Duty` rules are now an explicit, documented no-op. The
  decision logic moved to a pure `build_decision` that returns the verdict plus
  the full event list, so the audit trail is unit-tested. Removed the dead
  `RuleAction::matches_action`.
- Made `#[derive(TypesecRole)]` derive role names with `pascal_to_snake` like the
  `policy!` macro, so `AnalystReadOnly` yields the same `name()` either way
  (was `to_lowercase`, giving `analystreadonly`).
- Fixed `typesec-odrl` numeric constraint comparison: ordering operators
  (`lt`/`lteq`/`gt`/`gteq`) now compare numerically when both operands parse as
  numbers, so `count lteq 5` correctly rejects a count of 10 (previously it
  compared lexicographically, where `"10" <= "5"`). String operands still order
  lexicographically. Added regression tests.
- Made `typesec run` reflect the policy decision in its exit code (0 allow /
  1 deny / 2 delegate) like `typesec check`, so a denied task no longer exits 0.
  Unified the three divergent CLI `detect_format` copies (and the engine-loading
  and request-context boilerplate) into one shared `commands::engine` module, so
  every subcommand recognises the same formats — `run` now supports graph
  policies, which it previously could not detect.
- Re-exported `TaskError` from `typesec-agent` and the `typesec` umbrella so the
  error type returned by `execute`/`invoke`/`TaskResult` can be named by callers.
- Corrected factual errors in `docs/book/typesec.md`: Grust is a local path
  dependency at 0.10 (not a published crates.io 0.9 package), so the company-graph
  example needs a sibling `../grust` checkout; `Capability`/`new_minted` carry
  `SubjectId`/`ResourceId` fields (not `String`); `typesec-integrations` has six
  modules including `pydantic_ai`; `grust-sail` is imported as its own crate, not
  via `grust::prelude`; `typesec-python`/`typesec_native` is a shipped PyO3 crate
  (not future work); `typesec check --json` is shipped and emits `decision`/
  `allowed` (not `verdict`); example invocations use `-p typesec-cli`; the
  dependency list reflects `serde_norway`, `garde`, `zeroize`, and the DID crypto
  crates. Refreshed the stale Workspace Tour example/doc/test file list.
- Pinned the toolchain to rust 1.96.0 via `rust-toolchain.toml` and refreshed the
  drifted `typesec-core` trybuild UI snapshot, so `cargo test` is green on a fresh
  checkout instead of failing on compiler-version-specific diagnostic wording.
- Began a human-reviewability refactor (see `CLAUDE.md`): moved the inline
  `typesec-core` `lattice` and `typestate` test modules into sibling
  `lattice/tests.rs` and `typestate/tests.rs` files via `#[cfg(test)] mod tests;`.
- Refactored `typesec-rbac` and `typesec-odrl` for reviewability
  (behavior-preserving, except a bench fix): split `graph_policy.rs` (1040) into a
  `graph_policy/` module (schema/authored/typed_graph/rule/engine/eval/tests, each
  ≤259 lines), `rbac/engine.rs` (451) into `engine/{pattern,flatten,tests}`, and
  `odrl/engine.rs` (456) by separating the scan from the audit/decision step.
  Unified the four duplicated role-inheritance DFS traversals into one
  `walk_inheritance` walker and merged the identical `SubjectPattern`/
  `ResourcePattern` into one `GlobPattern`. Moved inline tests to sibling files.
  Fixed the `typesec-odrl` bench, which used `left_operand`/`right_operand` and
  omitted the required `type:` field and so panicked on every run.
- Refactored `typesec-integrations` for reviewability (behavior-preserving):
  split the 2635-line `did.rs` into a `did/` module (11 production files, each
  ≤386 lines, plus `did/tests.rs`) and `jwt.rs` (559) into a `jwt/` module;
  extracted a shared `ProviderHttpEngine`/`bearer_post` helper so `workos.rs` and
  `arcade.rs` no longer duplicate the bearer-auth HTTP shell; moved all inline
  test modules to sibling files; and gave `ReqwestHttpClient` a 30s request
  timeout (was unbounded). Public API unchanged; 34 tests green, clippy clean.
- Moved the inline `typesec-agent` `agent.rs` and `tool.rs` test modules into
  sibling `agent/tests.rs` and `tool/tests.rs` files (`agent.rs` 373 → 255,
  `tool.rs` 326 → 205).
- Split `typesec-macro` `lib.rs` (441 lines) into `lib.rs` (91, the proc-macro
  entry points) plus `shared.rs` (permission validation + name casing),
  `role_derive.rs`, `policy_dsl.rs`, and `tests.rs`; corrected the derive doc
  example to show the actual lower-cased `name()` output.
- Split `typesec-core` `policy.rs` (989 lines) into `policy.rs` (191, the engine
  traits + wiring) plus focused `policy/` submodules: `subject`, `result`,
  `error`, `audit`, `mint`, `fallback`, and `tests`. Unified the identical
  `SubjectId`/`ResourceId` newtypes behind a single `string_newtype!` macro
  (`string_id.rs`), deduplicated the sync/async mint terminal step into one
  `finish_mint` helper, and corrected the stale `new_unchecked` flow comment.
- Consolidated `typesec-core` `combinator.rs` (624 lines) to 314: replaced the
  eight near-duplicate sync/async strategy functions with one shared `Verdicts`
  accumulator (decision logic written once, driven by trivial sync/async loops),
  preserving short-circuit semantics; moved tests to `combinator/tests.rs`.
- Removed the unused `serde` dependency from `typesec-core`.
- Split `typesec-core` `secure_value.rs` (485 lines) into `secure_value.rs` (186)
  plus `secure_value/label.rs` (the privacy-label lattice and `Join`),
  `secure_value/error.rs`, and `secure_value/tests.rs`; re-exported the
  previously unreachable `SecureValueError` from the crate root.
- Split `typesec-core` `capability.rs` (531 lines) into `capability.rs` (306) plus
  `capability/revocation.rs` (the `RevocationEpoch`/`CapabilityRevocationList`/
  `CapabilityUseError` primitives) and `capability/tests.rs`; fixed a broken
  `mint_capability` intra-doc link and the stale "only constructor is
  `new_unchecked`" prose.
- Added `CLAUDE.md` capturing the workspace architecture, a human-reviewability
  standard (file-size budget, tests in their own files, DRY), a full review of
  every crate and the book, and a phased refactor plan toward that standard.
- Added Pydantic AI v2 capability metadata for Typesec-protected tools in
  `typesec-integrations`, plus Python adapter examples and tests that map a
  TypeDID policy gate into a deferred Pydantic AI capability bundle.
- Added a complete Python Pydantic AI v2 capability example that runs a real
  `Agent` with `TestModel`, exercises an allowed TypeDID payload, and verifies
  a denied subject is blocked before tool execution.
- Updated local Grust path dependency constraints from `0.9.0` to `0.10.0`
  so Cargo-backed checks resolve against the sibling Grust checkout.
- Consolidated book metadata and cover publishing guidance into
  `docs/book/PUBLISH.md`, then archived superseded status notes under
  `docs/completed/`.

## 0.8.0

### 2026-06-17

- Bumped workspace crate versions, internal dependency constraints, Python
  package metadata, and user-facing dependency examples to `0.8.0`.
- Updated the local Grust facade dependency from `0.7.0` to `0.9.0`, added the
  published `grust-cypher` and `grust-sail` crates as direct dependencies, and
  added company-graph helpers and examples that apply Grust Cypher DDL
  constraints before using Cypher mutation syntax for an authorized graph write.
- Rebuilt the book artifacts with the Grust 0.9 company-graph documentation.
- Added audit-safe TypeDID attestations derived from verified TypeDID messages,
  giving downstream systems a payload-free proof summary to persist after
  TypeSec verifies the envelope.
- Updated the `grust-graph` dependency and user-facing Grust examples from
  `0.6.2` to `0.7.0`.
- Rebuilt the book artifacts for `typesec (0.7.0)` and delivered the versioned
  EPUB to iCloud Books.

## 0.7.0

### 2026-06-13

- Bumped workspace crate versions, internal dependency constraints, Python
  package metadata, and user-facing dependency examples to `0.7.0`; crates are
  prepared locally but not published.
- Added per-capability revocation with `CapabilityId`,
  `CapabilityRevocationList`, and `MintOptions::with_revocation_list`, allowing
  one live proof to be revoked without bumping a shared revocation epoch.
- Added `SubjectId` and `ResourceId` newtypes across capabilities, audit
  events, policy engines, minting helpers, CLI checks, Python gates, examples,
  and integration policy engines so subject/resource parameters no longer
  collapse into interchangeable strings.
- Added property-based permission lattice law tests with `proptest` to exercise
  runtime implication lookup, cycle prevention, and transitive-closure coverage.
- Exercised the PyO3 `typesec_native` module surface from Rust tests so
  `TypesecGate`, `check`, `validate`, and permission errors are verified
  through Python-callable bindings for RBAC, ODRL, and graph policies.
- Added `policy!` role inheritance with `role Child extends Parent`, flattening
  inherited permissions and resource patterns during macro expansion.
- Added DID key rotation for `Ed25519DidKeyStore`, including active key version
  reporting, rotation-aware DID documents, in-flight verification for previous
  keys, and retired-key rejection.
- Added a `ToolRegistry` for named `ProtectedTool` discovery and erased
  invocation, and tightened protected-tool runtime checks for subject, resource,
  and capability freshness.
- Added `typesec run --scenario` for YAML-described multi-agent traces with
  per-step action/resource checks and optional expected results.
- Added Criterion benchmark targets for core policy paths, RBAC checks, and
  ODRL constraints, plus cargo-fuzz targets for RBAC and ODRL YAML parsing.
- Added RBAC wildcard subject assignments with compiled glob validation, typed
  ODRL constraint operands, prohibition-overridden ODRL audit events, and
  snake_case role names for multiword `policy!` roles.
- Added forward-compatible public policy enums and structured delegation
  reasons so CLI, Python, audit, and composed-engine output can report which
  engine abstained and why.
- Added async policy and audit surfaces plus async capability-minting helpers;
  `SecureAgent::request_capability` now awaits that path directly instead of
  dispatching every policy check through Tokio's blocking pool.
- Added `CanReadInternal`, a lattice relationship below sensitive-read, and
  `SecureValue<Internal>::reveal_internal` so internal data has a least-privilege
  reveal path distinct from sensitive and secret data.
- Indexed ODRL rules by assignee and action at engine construction so common
  exact checks avoid scanning unrelated rules while preserving `use` wildcard
  action behavior.
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
