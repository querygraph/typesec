# Typesec Examples

This directory contains runnable examples for the Typesec workspace. They show
the same security idea at a few layers: typed Rust capabilities, contextual
ODRL policy, graph writes through Grust/Sail, and a Python tool-gating wrapper
that shells out to the Typesec CLI.

## Install Typesec From This Repository

Run these commands from a fresh checkout:

```sh
git clone git@github.com:alexy/typesec.git
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

### Rust + Grust + Sail

Path:

```text
examples/company_graph/company_graph_grust_sail.rs
```

This example uses published Grust crates:

```toml
grust-graph = { version = "0.2.0", features = ["sail"] }
```

It builds a backend-neutral property graph through the `grust` facade. If a Sail
SparkConnect server is listening on `127.0.0.1:50051`, it writes the graph
through the facade's Sail adapter exports; otherwise it skips the backend write
and still exercises the Typesec policy checks.

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
shape of a LangChain tool wrapper: before a tool mutates the graph, it shells
out to `typesec check` through the workspace CLI.

Run it with the installed CLI available for comparison:

```sh
python3 examples/company_graph/langchain_company_graph.py
```

The script itself invokes:

```sh
cargo run -q -p typesec-cli -- check ...
```

so it also works before `cargo install` as long as it is launched from a working
Rust checkout.

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
cargo check -p typesec-cli --example company_graph_grust_sail
python3 examples/company_graph/langchain_company_graph.py
```
