# Typesec Examples

This directory contains runnable examples for the Typesec workspace. They show
the same security idea at a few layers: typed Rust capabilities, contextual
ODRL policy, provider integrations, graph writes through Grust/Sail, and a
Python tool-gating wrapper that shells out to the Typesec CLI.

## Install Typesec From This Repository

Run these commands from a fresh checkout:

```sh
git clone git@github.com:querygraph/typesec.git
cd typesec

cargo build --workspace
cargo test --workspace
cargo install --path crates/typesec-cli
```

After `cargo install`, the `typesec` binary should be on your Cargo bin path:

```sh
typesec --help
```

If your shell cannot find `typesec`, add Cargo's bin directory to your `PATH`:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
typesec --help
```

You can also run the CLI without installing it:

```sh
cargo run -p typesec-cli -- --help
```

## Validate The Example Policies

The repository includes RBAC and ODRL policy files under `policies/`.

Installed CLI:

```sh
typesec validate --policy policies/rbac-example.yaml
typesec validate --policy policies/odrl-example.yaml
```

Without installing:

```sh
cargo run -p typesec-cli -- validate --policy policies/rbac-example.yaml
cargo run -p typesec-cli -- validate --policy policies/odrl-example.yaml
```

## Check Individual Policy Decisions

RBAC allow:

```sh
typesec check \
  --policy policies/rbac-example.yaml \
  --subject agent:data-pipeline \
  --action read \
  --resource reports/q1
```

RBAC deny:

```sh
typesec check \
  --policy policies/rbac-example.yaml \
  --subject agent:data-pipeline \
  --action write \
  --resource reports/q1
```

ODRL allow with purpose context:

```sh
typesec check \
  --policy policies/odrl-example.yaml \
  --subject agent:summarizer \
  --action read \
  --resource customer-data \
  --purpose analytics
```

ODRL prohibition:

```sh
typesec check \
  --policy policies/odrl-example.yaml \
  --subject agent:summarizer \
  --action ai:exfiltrate \
  --resource customer-data
```

The `check` command exits with status `0` for allow, `1` for deny, and `2` for
delegation.

## `rbac_agent.rs`

Path:

```text
examples/rbac_agent.rs
```

This Rust example demonstrates the basic RBAC capability flow:

1. Load an RBAC policy.
2. Authenticate an agent.
3. Request a typed capability.
4. Execute an action only after the capability exists.
5. Show that denied requests do not mint capabilities.
6. Protect sensitive report data in `SecureValue<Sensitive, _, _>`, transform it
   while opaque, and declassify only when the agent holds
   `Capability<CanDeclassify, _>`.

Run it:

```sh
cargo run -p typesec-cli --example rbac_agent
```

Check that it still compiles:

```sh
cargo check -p typesec-cli --example rbac_agent
```

## `odrl_agent.rs`

Path:

```text
examples/odrl_agent.rs
```

This Rust example demonstrates ODRL-style contextual policy. It shows how
purpose constraints affect decisions and how a prohibition can block an action
even when other access to the same target is allowed.

Run it:

```sh
cargo run -p typesec-cli --example odrl_agent
```

Check that it still compiles:

```sh
cargo check -p typesec-cli --example odrl_agent
```

## `provider_integrations.rs`

Path:

```text
examples/provider_integrations.rs
```

This Rust example demonstrates the OAuth-provider integration path without
requiring live provider credentials. It uses mocked HTTP clients to show:

1. JWT/OIDC claims granting a fast org-wide capability.
2. WorkOS FGA granting a resource-scoped app capability.
3. Arcade-style tool authorization granting an external tool execution
   capability.
4. `ProtectedTool` refusing to invoke unless the matching typed capability is
   supplied.

Run it:

```sh
cargo run -p typesec-cli --example provider_integrations
```

Check that it still compiles:

```sh
cargo check -p typesec-cli --example provider_integrations
```

## `did_messaging.rs`

Path:

```text
examples/did_messaging.rs
```

This Rust example demonstrates a DID-wrapped encrypted prompt flow without a
live ledger or Ollama server:

1. Resolve sender and recipient DID documents.
2. Verify the sender signature.
3. Decrypt the payload for the local recipient DID.
4. Protect the plaintext prompt as `SecureValue<Secret, String, GenericResource>`.
5. Require `Capability<AiCanInfer, _>` and
   `Capability<CanReadSensitive, _>` before sending plaintext to Ollama.

The example uses `StaticDidResolver` with `Ed25519DidKeyStore` for Ed25519
signatures, X25519 key agreement, and ChaCha20-Poly1305 encryption. The optional
`DemoDidKeyStore` is a non-cryptographic test fixture behind the `demo-crypto`
feature; Hyperledger Indy VDR, Universal Resolver, DIDComm/JWE, or KMS-backed
key material can plug into the same traits.

Run it:

```sh
cargo run -p typesec-cli --example did_messaging
```

Check that it still compiles:

```sh
cargo check -p typesec-cli --example did_messaging
```

See [`docs/did-messaging.md`](../docs/did-messaging.md) for the local
Hyperledger Indy/VON Network setup and the `IndyVdrResolver` adapter shape.

## Company Graph Examples

Directory:

```text
examples/company_graph/
```

The company graph examples model agents writing a company hierarchy while
Typesec gates node, relationship, and sensitive-network access.

The graph policy is:

```text
policies/graph-corporate-example.yaml
```

It defines the company hierarchy, agent-role edges, and policy predicates in one
Grust graph. The effective roles are:

- `agent:executive-chief` can write the company graph and read the sensitive
  employee network.
- `agent:hr-onboarding` can write non-executive employee nodes and reporting
  relationships.
- `agent:employee-nia` can write only her own public profile.

Validate and check the graph policy:

```sh
cargo run -p typesec-cli -- validate --policy policies/graph-corporate-example.yaml
cargo run -p typesec-cli -- check --policy policies/graph-corporate-example.yaml \
  --subject agent:hr-onboarding \
  --action write \
  --resource employee/private/employee:nia
```

The graph policy loader now uses Grust 0.5 typed graph support with Zod schemas
at the YAML/JSON boundary, and the examples write validated graphs through
Grust's typed backend path. That means the example policy is not just parsed as
a loose property graph: `Agent`, `Role`, and `Employee` nodes are typed,
`HAS_ROLE` must connect an `Agent` to a `Role`, `REPORTS_TO` must connect
`Employee` nodes, and strict employee schemas reject unexpected properties.

### Typed Graph Policy Schema

Path:

```text
examples/company_graph/graph_policy_schema.rs
```

This example focuses on the policy loader itself. It demonstrates:

1. YAML graph policy loading through the typed Grust/Zod path.
2. JSON graph policy loading through the same schema boundary.
3. A successful authorization decision from the typed JSON policy.
4. Persistence of the typed policy graph through `MemoryGraphStore::put_typed_graph`.
5. Rejection of an unknown graph node label.
6. Rejection of an extra employee property by a strict Zod schema.
7. Rejection of a `HAS_ROLE` edge whose endpoints do not match the typed graph
   model.
8. Rejection of the same endpoint mismatch by the backend `GraphSchema`.

Run it:

```sh
cargo run -p typesec-cli --example graph_policy_schema
```

Check that it still compiles:

```sh
cargo check -p typesec-cli --example graph_policy_schema
```

### Rust + Grust + Sail

Path:

```text
examples/company_graph/company_graph_grust_sail.rs
```

This example uses published Grust crates:

```toml
grust-graph = { version = "0.5.0", features = ["typed-zod-rs", "sail"] }
```

It builds a backend-neutral property graph through the `grust` facade. If a Sail
SparkConnect server is listening on `127.0.0.1:50051`, it applies the shared
company graph schema and writes the graph with `put_typed_graph`; otherwise it
still validates the graph against that schema and exercises the Typesec policy
checks.

Run it:

```sh
cargo run -p typesec-cli --example company_graph_grust_sail
```

Check that it still compiles:

```sh
cargo check -p typesec-cli --example company_graph_grust_sail
```

### Python LangChain-Style Tool Gate

Path:

```text
examples/company_graph/langchain_company_graph.py
```

This script does not require LangChain and does not call an LLM. It mirrors the
shape of a LangChain tool wrapper while keeping all reusable policy and graph
logic in:

```text
examples/company_graph/company_graph_core.py
```

The shared `TypesecGate` tries the Rust-backed `typesec_native` Python module
first and falls back to `typesec check` through the workspace CLI.

Run it with the installed CLI available for comparison:

```sh
uv run python examples/company_graph/langchain_company_graph.py
```

The script itself invokes:

```sh
cargo run -q -p typesec-cli -- check ...
```

so it also works before `cargo install` as long as it is launched from a working
Rust checkout.

### Python Pydantic AI Tool Gate

Path:

```text
examples/company_graph/pydantic_company_graph.py
```

This example uses Pydantic AI's standard `deps_type` and `RunContext` hooks. No
Pydantic fork is required: tools receive `CompanyGraphDeps`, call
`TypesecGate.arequire(...)`, and only then mutate the shared graph.

Run the deterministic tool-boundary smoke path:

```sh
uv run python examples/company_graph/pydantic_company_graph.py
```

If `pydantic-ai` is installed, the same file also defines a real
`company_graph_agent` with secured tools.

### Rust-Backed Python Package

Path:

```text
crates/typesec-python/
```

The PyO3 module exposes `typesec_native.TypesecGate`, `Decision`, `check`, and
`validate`. Build a local development wheel with:

```sh
cd crates/typesec-python
uv sync --group dev
uv run maturin develop
```

The source examples do not require this wheel; they use it automatically when
available and otherwise fall back to the CLI.

## Generate Typed RBAC Code

The CLI can generate typed Rust declarations from the RBAC example policy:

```sh
typesec generate \
  --policy policies/rbac-example.yaml \
  --out /tmp/typesec_policy_gen.rs
```

Without installing:

```sh
cargo run -p typesec-cli -- generate \
  --policy policies/rbac-example.yaml \
  --out /tmp/typesec_policy_gen.rs
```

Inspect the generated file:

```sh
sed -n '1,200p' /tmp/typesec_policy_gen.rs
```

## Run The Full Verification Set

Use this when changing examples or policy behavior:

```sh
cargo check --workspace
cargo test --workspace
cargo check -p typesec-cli --example rbac_agent
cargo check -p typesec-cli --example odrl_agent
cargo check -p typesec-cli --example graph_policy_schema
cargo check -p typesec-cli --example company_graph_grust_sail
uv run python examples/company_graph/langchain_company_graph.py
uv run python examples/company_graph/pydantic_company_graph.py
uv run python -m unittest discover -s tests/python
```
