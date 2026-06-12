# Changelog

All notable changes to this repository are recorded here. Keep entries grouped
by release version, then by the date the logical change landed.

## Unreleased

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
