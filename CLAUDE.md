# Typesec — agent context

Type-safe security framework for Rust: capabilities, permission lattices, policy
engines (RBAC / ODRL / graph), agent typestate, and provider integrations
(OAuth/JWT, WorkOS, Arcade, Pydantic AI, DID/TypeDID messaging). Workspace at
v0.9.0, edition 2024. A companion book ships from `docs/book/typesec.md`.

`AGENTS.md` holds the baseline working agreement (changelog discipline,
prompt-boundary commits, artifact hygiene). This file extends it with
architecture, the human-reviewability standard this codebase is held to, and a
living record of review findings + the refactor plan toward that standard.

## Architecture

Nine workspace crates (`Cargo.toml` `members`), `fuzz/` is excluded.

```
typesec-core      foundation: Capability<P,R>, Permission markers (sealed),
                  Implies lattice, SecureValue<L,T,R>, PolicyEngine trait,
                  PolicyResult, mint_capability*, audit, combinators, typestate
   ├─ typesec-rbac        RbacEngine (role inheritance + glob) + GraphPolicyEngine
   │                      (grust/grust-cypher typed graph, deny-overrides) + codegen
   ├─ typesec-odrl        OdrlEngine (permission/prohibition/duty, constraints, audit)
   ├─ typesec-agent       SecureAgent<S> typestate, ProtectedTool, ToolRegistry
   ├─ typesec-integrations  HttpClient, JWT/OIDC, WorkOS, Arcade, Pydantic AI,
   │                        DID/TypeDID (real ed25519/x25519/chacha20poly1305 crypto)
   └─ typesec-macro        #[derive(TypesecRole)], policy! DSL
typesec-cli       validate / check / generate / run (clap)
typesec-python    typesec_native PyO3 cdylib (maturin)
typesec           umbrella facade re-exporting the above (feature-gated)
```

**The load-bearing invariant:** a `Capability<P,R>` is unforgeable proof. It has
no public constructor — the only production path is `mint_capability*`
(`typesec-core/src/policy.rs`), which runs a `PolicyEngine` and emits an audit
event. `Permission`, `AgentState`, and `PrivacyLevel` are sealed traits. The
compile-fail tests in `typesec-core/tests/ui/` are the guard that these
boundaries can't be bypassed; treat them as load-bearing, not incidental.

`PolicyEngine::check_with_context -> PolicyResult { Allow | Deny(String) |
Delegate(DelegationReason) }` is the shared contract every engine implements.

## Build / test / verify

```bash
cargo build --workspace
cargo test  --workspace          # see baseline caveats below
cargo bench -p typesec-{core,rbac,odrl}
cargo fuzz run rbac_yaml         # from fuzz/ (excluded crate)
```

Python bindings: `maturin develop` in `crates/typesec-python` (see README).
The book renders via `docs/book/build.sh` (Pandoc → EPUB/PDF/MOBI; see
`docs/book/PUBLISH.md`). Toolchain: rustc 1.96, pinned via `rust-toolchain.toml`.
CI (`.github/workflows/ci.yml`) runs fmt/clippy/test + a bench smoke.

### Baseline caveats — both resolved 2026-06-25
- **Trybuild snapshot drift (FIXED):** added `rust-toolchain.toml` pinning rustc
  1.96.0 so `tests/ui/*.stderr` snapshots are reproducible, and refreshed the
  drifted `cannot_create_new_agentstate.stderr`. `cargo test --workspace` is now
  green on a fresh checkout. Bump the pin deliberately and refresh snapshots
  with `TRYBUILD=overwrite`.
- **odrl bench panic (FIXED):** `benches/odrl_check.rs` used
  `left_operand`/`right_operand` and omitted the required `type:` field; both
  corrected so it parses and runs. Benches now run in CI as a smoke step
  (`cargo bench -- --test`).

## Human-reviewability standard (the goal this repo is held to)

Code here must be reviewable by a human in one sitting, file by file. Concretely:

1. **No monolithic files.** Target ≤ ~400 lines per source file; hard-look at
   anything over ~500. A file should have one reason to exist. When a file grows
   past budget, split it into a `name/` module directory with cohesive sub-files
   and a thin `mod.rs` that only declares modules + re-exports the public API.
2. **Tests live in their own files.** No large inline `#[cfg(test)] mod tests` at
   the bottom of a source file. Use the idiomatic pattern: in `foo.rs` (or
   `foo/mod.rs`) write `#[cfg(test)] mod tests;` and put the tests in
   `foo/tests.rs`. This keeps the source body reviewable while preserving access
   to private items via `use super::*`. *Exceptions, documented inline:*
   `typesec-python` is `cdylib`-only (can't be linked by an external `tests/`
   harness) and `typesec-macro` tests reach private fns — keep those inline or
   as `#[path]`-included child modules, not external integration tests.
3. **DRY — one home for each idea.** No copy-pasted match arms, no twin
   sync/async bodies that can silently diverge, no N-th reimplementation of glob
   matching or role-inheritance traversal. Shared logic gets one home (a helper,
   a macro, or a shared module).
4. **Clear reuse over re-derivation.** Identical newtypes, identical provider
   HTTP shells, identical CLI format-detection should be generated or shared, not
   retyped.
5. **Public API completeness.** Every error type a public fn can return must be
   nameable by callers (re-exported). Doc intra-links must resolve.

Every refactor commit keeps `cargo build --workspace` + `cargo test --workspace`
green (modulo the trybuild caveat) and carries its `CHANGELOG.md` entry, per
`AGENTS.md`. Refactors are behavior-preserving unless a finding below is an
explicit correctness fix — those are called out and get their own commit.

## Review findings (2026-06-25)

Full per-crate review on file. Severity: **[C]** correctness, **[S]** security,
**[D]** DRY/dup, **[M]** monolith, **[X]** dead code, **[B]** book/docs.

### Correctness & security (fix with their own commits + changelog)
- **[C] ODRL numeric operators compare as strings** — `typesec-odrl/src/constraint.rs`
  routes `count` and numeric operands through `evaluate_string_op`, so
  `count lteq "5"` with actual `"10"` does `"10" <= "5"` lexicographically →
  wrong `true`. Real evaluation bug.
- **[C] ODRL audit trail is incomplete** — `OdrlVerdict::ConstraintFailed`
  (`audit.rs`) is never emitted; a permission whose constraint fails is silently
  dropped (`engine.rs` `_ => {}`). And on success only the last matched
  permission (`.pop()`) is logged, not all. The audit trail is the crate's
  selling point and misses its two most important events.
- **[C] ODRL `Duty` rules are silently ignored** — parsed and indexed but the
  engine match has no arm; either evaluate, reject at load, or document as no-op.
- **[C] CLI `run` ignores policy denials** — every task arm does
  `let _ = simulate_task(...)` and returns `Ok(())`, so `typesec run --task
  exfiltrate` exits 0 even when DENIED. `check` correctly maps Allow/Deny/Delegate
  → exit 0/1/2. Unsafe for CI gating; make `run`'s exit contract match `check`.
- **[C] `detect_format` diverges across CLI subcommands** —
  `check.rs`/`validate.rs`/`run.rs` (and a 4th copy in `typesec-python`) detect
  formats differently: `run` can't see `graph` policies at all; `validate`
  requires `roles:`+`assignments:` while `check`/`run` need only `roles:`. Same
  file routes differently per subcommand. Unify into one detector.
- **[C] typesec-macro derives two different role names** —
  `#[derive(TypesecRole)]` uses `to_lowercase()` (`AnalystReadOnly` →
  `analystreadonly`) but `policy!` uses `pascal_to_snake` (→ `analyst_read_only`).
  Latent mismatch when names are compared to policy strings. Pick one.
- **[S] DID envelope auth gaps** (`typesec-integrations/src/did.rs`): AEAD
  `encrypt_for` passes no associated data, and `signing_input()` omits `kid`
  (and any future field is silently unauthenticated); no replay protection
  (`created_time` signed but never checked, 300s window replayable); negotiated
  `max_payload_bytes` is advertised but never enforced (also dead field).
- **[S] No reqwest timeout** — `ReqwestHttpClient` uses `Client::new()`; a slow
  JWKS/WorkOS/Arcade/Ollama endpoint hangs a thread indefinitely. One-line fix.
- **[S] JWT alg from header** — `Validation::new(header.alg)` then overrides with
  trusted config; correct today but fragile, one refactor from trusting the
  header. Note for hardening, not an active hole.
- **[C] typesec-agent `TaskError` not re-exported** (agent crate + umbrella), so
  the public error of `execute`/`invoke`/`TaskResult` can't be named downstream.
  `TaskError::ActionFailed` is also never constructed (dead variant).
- **[C] Doc/API nits in core**: `SecureValueError` not re-exported from
  `lib.rs` though returned by public `zip`; broken intra-doc link
  `PolicyEngine::mint_capability` (it's a free fn); stale "only constructor is
  `new_unchecked`" prose (production path is `new_minted`).

### DRY / duplication [D]
- **core**: `SubjectId` (`policy.rs`) and `ResourceId` (`resource.rs`) are
  near-identical newtypes (~50 dup lines) → `string_newtype!` macro. `combinator.rs`
  has every strategy written twice (sync + async, ~120 lines) that can collapse
  to pure combiners over a verdict slice + one async collector;
  `PolicyResult::delegate("composed", "all engines delegated")` literal ×8.
  `mint_capability_for_id` / `_async` share an identical terminal `match` +
  audit-event block. Poisoned-lock `unwrap_or_else` recovery ×3.
- **integrations**: `workos.rs` and `arcade.rs` are near-identical PolicyEngine-
  over-HTTP shells (same fields, same `Bearer` header, same post→parse→PolicyResult
  block) → extract a `ProviderHttpEngine`/`bearer_post` helper. DID `prompt`/`reply`
  envelope constructors share ~40 lines. Test doubles in `http.rs` duplicate the
  HashMap-lookup ×4.
- **rbac**: role-inheritance DFS reimplemented **4×** (`engine.rs` `flatten_role`,
  `codegen.rs` `collect_all_permissions`/`collect_all_resources`, `model.rs`
  `check_cycle`) + O(roles²) linear `find` per step → one generic walker over a
  `HashMap<&str,&RoleDefinition>`. `SubjectPattern`/`ResourcePattern` are
  byte-identical → one `GlobPattern`.
- **rbac↔odrl**: three glob-match reimplementations; odrl recompiles the glob on
  every check (rbac compiles once at load — odrl should too).
- **cli**: `detect_format` ×3 (divergent, see [C]); engine-loading `from_yaml +
  map_err(anyhow!)` ×~8; `RequestContext` purpose-building ×4; `run.rs` task
  `match` arms near-identical ×4; agent/tool capability guards duplicated.
- **python**: `Decision { … }` struct literal built 4× in `decision_from_result`.

### Monolithic files [M] (decomposition map in next section)
`did.rs` 2635 · `graph_policy.rs` 1040 · `policy.rs` 989 · `combinator.rs` 624 ·
`agent/tests/integration.rs` 624 · `jwt.rs` 559 · `capability.rs` 531 ·
`lattice.rs` 492 · `secure_value.rs` 485 · `odrl/engine.rs` 456 · `rbac/engine.rs`
451 · `macro/lib.rs` 441 · `python/lib.rs` 403 · `agent.rs` 373 · `tool.rs` 326 ·
`cli/run.rs` 311. ~4,800 lines of these are inline test modules.

### Dead code [X]
`serde` dep unused in core; `RuleAction::matches_action` + `OdrlVerdict::ConstraintFailed`
(odrl); `TaskError::ActionFailed` (agent); `TypeDidProfile::max_payload_bytes` +
unenforced profile metadata fields (integrations); `apply_company_graph_cypher_constraints`
+ Cypher DDL exports (rbac, no callers); `#![allow(missing_docs)]` blanket on
`graph_policy.rs` hides undocumented public API.

### Book / docs [B] (`docs/book/typesec.md`)
- **Grust is a local path dep at 0.10.0**, not "published crates.io at 0.9" as the
  book claims repeatedly (Workspace Tour, "What We Improved", Design Tradeoffs).
  The company-graph example needs a sibling `../grust` checkout — not reproducible
  off this machine. Largest factual error.
- `Capability`/`new_minted` shown with `String` fields — actually `SubjectId`/
  `ResourceId`.
- Roadmap still lists `typesec check --json` as future work — it's shipped; the
  JSON sample shows a `verdict` field that doesn't exist (it's `decision`/`allowed`).
- `typesec-python` is a built crate but framed as hypothetical future PyO3 work.
- "five modules" in integrations → six (`pydantic_ai` missing).
- `grust-sail` is a separate crate, not pulled via `grust::prelude`.
- Dependency list omits `garde`, `zeroize`, `chrono`, DID crypto crates; lists
  `serde_yaml` (now `serde_norway`). Some example invocations miss `-p typesec-cli`.
- The OAuth/DID chapter (~430 lines, 24% of book) carries VON/Indy ops-runbook
  detail that belongs in `docs/did-messaging.md`.
- Structure: keep the single Pandoc manuscript (don't migrate to mdBook — it
  would break the EPUB/PDF/MOBI pipeline); optionally split into per-chapter `.md`
  concatenated by `build.sh`.

## Refactor plan (decomposition map + order)

Execute as separate commits, each green + changelogged. Order is chosen so
behavior-preserving structural splits land first (low risk, high readability),
then DRY, then correctness fixes get isolated commits, then the book.

**Test extraction pattern** for every file below: add `#[cfg(test)] mod tests;`
and move the inline module to `tests.rs` beside the source (or in the new module
dir). Carry shared test fixtures (the repeated `AllowAll`/`DenyAll` engines,
JWKS/token builders) into a `#[cfg(test)]` test-support module.

### Phase A — typesec-core (foundation, do first)
- `policy.rs` 989 → `policy/{mod,subject,result,error,audit,mint,fallback}.rs` +
  `policy/tests.rs`.
- `combinator.rs` 624 → collapse sync/async twins; `combinator/{mod,strategies}.rs`
  + tests.
- `capability.rs` 531 → `capability/{mod,revocation}.rs` + tests.
- `secure_value.rs` 485 → `secure_value/{mod,label,error}.rs` + tests.
- `lattice.rs` 492 → extract tests (no split needed).
- `typestate.rs` 333 → extract tests.
- DRY: `string_newtype!` for `SubjectId`/`ResourceId`; shared `#[cfg(test)]`
  test engines. Drop unused `serde` dep. Fix the doc/re-export nits.

### Phase B — typesec-integrations (worst monolith)
- `did.rs` 2635 → `did/{mod,identifier,document,keystore,keystore_demo,envelope,
  gateway,typedid,ollama,error,crypto}.rs` + `did/tests/`.
- `jwt.rs` 559 → `jwt/{mod,config,claims,authenticator,engine}.rs` + tests.
- DRY: `ProviderHttpEngine`/`bearer_post` shared by `workos.rs`+`arcade.rs`;
  dedup `http.rs` test doubles. Add reqwest timeout (security).

### Phase C — typesec-rbac / typesec-odrl
- `graph_policy.rs` 1040 → `graph_policy/{mod,schema,authored,typed_graph,rule,
  engine,eval}.rs` + tests. (`schema.rs` + `eval.rs` are the cleanest first cuts.)
- `rbac/engine.rs` 451 → `engine/{mod,pattern,flatten}.rs` + tests.
- `odrl/engine.rs` 456 → `engine/{mod,index,resolve}.rs` + tests (separate
  decision from audit-logging).
- DRY: one inheritance walker; one `GlobPattern`; shared glob helper (odrl
  compiles at load).
- Correctness commits: numeric operators; audit completeness; `Duty` semantics.

### Phase D — typesec-agent / cli / macro / python
- `agent/tests/integration.rs` 624 → `tests/common/` + per-theme test files;
  fix broken 01–13 numbering.
- `macro/lib.rs` 441 → `{lib,role_derive,policy_dsl,shared}.rs`; reconcile the two
  name derivations (correctness).
- `python/lib.rs` 403 → `{lib,format,engine,decision}.rs` (tests stay inline,
  cdylib); collapse 4× `Decision` literal; re-export `TaskError`.
- `agent.rs`/`tool.rs` → extract `builder.rs`/`registry.rs` + test files; shared
  capability guard.
- `cli/run.rs` 311 → `run/{mod,scenario}.rs` + shared `commands/engine.rs`
  (unify `detect_format`, engine-loading, purpose-building); fix `run` exit codes.

### Phase E — book & docs
Apply the [B] fixes; fix the odrl bench YAML and add a `rust-toolchain.toml` pin
(unblocks the trybuild snapshot). Update `CHANGELOG.md` throughout.

## Progress (2026-06-25)

Done — `cargo test --workspace` fully green; every `.rs` file is now ≤ ~406 lines
(was up to 2635; the largest is `did/keystore.rs`), all unit tests live in
sibling files:
- [x] Review of all crates + the book; this file written.
- [x] Toolchain pinned; trybuild + odrl bench fixed.
- [x] **Phase A — typesec-core:** `policy.rs` 989→191 (+6 submodules),
  `combinator.rs` 624→314 (8 strategy fns → one `Verdicts`), `secure_value.rs`
  485→186, `capability.rs` 531→306, tests extracted from `lattice`/`typestate`;
  `string_newtype!` unifies `SubjectId`/`ResourceId`; `serde` dep dropped; doc
  fixes + `SecureValueError` re-exported.
- [x] **Phase B — typesec-integrations:** `did.rs` 2635 → a `did/` module of 11
  files (≤386) + `did/tests.rs`; `jwt.rs` 559 → `jwt/`; shared
  `ProviderHttpEngine` dedups workos/arcade; reqwest 30s timeout.
- [x] **Phase C — typesec-rbac/odrl:** `graph_policy.rs` 1040 → `graph_policy/`
  (≤259); both engines split; one `walk_inheritance` replaces 4 DFS copies; one
  `GlobPattern`.
- [x] **Phase D (partial):** `typesec-macro/lib.rs` 441→91 (+modules);
  `agent.rs`/`tool.rs` tests extracted; CLI `commands::engine` unifies
  `detect_format`/loading/exit-codes.
- [x] **Correctness:** odrl numeric operators; `run` exit codes + graph support;
  `TaskError` re-exported; odrl bench.
- [x] **Phase E (book):** factual fixes (Grust path-dep, `Capability` types,
  `--json`, six integration modules, `typesec-python`, deps list, file list).

Follow-ups (completed 2026-06-25):
- [x] **odrl audit completeness:** `ConstraintFailed` events now emitted; all
  matched permissions logged; `Duty` is an explicit documented no-op; decision
  logic moved to a pure, unit-tested `build_decision`.
- [x] **macro name consistency:** `#[derive(TypesecRole)]` now uses
  `pascal_to_snake` like `policy!`.
- [x] **DID security hardening:** `signing_input` covers `kid`+`nonce`; gateway
  rejects replays + future-dated envelopes; `max_payload_bytes` enforced at
  `wrap`; **AEAD associated-data binding** ties the ciphertext to the envelope's
  routing/timing identity at the ChaCha20-Poly1305 layer (a second binding under
  the signature), with a keystore-level rejection test.
- [x] **Dead code:** removed `RuleAction::matches_action` (genuinely dead).
  *Corrected over-flags:* `TaskError::ActionFailed` is user-facing API (users
  return it from `execute`'s closure); the rbac Cypher DDL helpers are used by
  `examples/company_graph/graph_policy_schema.rs`; `TypeDidProfile` metadata
  fields are protocol descriptors — all kept.
- [x] Split the two large *test* files (`did/tests.rs` 713 → 6 themed files;
  `agent/tests/integration.rs` 624 → `tests/common/` + 4 themed files, broken
  numbering fixed) and the `typesec-python` impl (`lib.rs` 403 → 237 +
  `format`/`engine`/`decision`). **Every `.rs` file in the workspace is now
  ≤ ~406 lines** (the largest is `did/keystore.rs`).

All review-derived follow-ups are now done. CI lives in
`.github/workflows/ci.yml` (fmt scoped to typesec to skip the Grust path dep,
clippy `-D warnings`, `cargo test --workspace`, and a bench smoke via
`cargo bench -- --test`). CI must check out a sibling `querygraph/grust` for the
path dependency — see the workflow comments for the ref/token notes.

## Releases

Versioning is `0.MINOR.0` (a minor bump per release; in 0.x, minor may include
breaking changes). Each release also gets a **codename after a Venetian
landmark**, in order. To cut a release: bump the workspace version *and* the
internal path-dep constraints (they must match or cargo errors), move the
`CHANGELOG.md` `Unreleased` section under the new version, rebuild the book
(`docs/book/build.sh` reads the version from `Cargo.toml`), then tag `vX.Y.Z`
and create a GitHub release titled with the codename.

| Version | Codename |
|---|---|
| 0.9.0 | Rialto (Ponte di Rialto) |
