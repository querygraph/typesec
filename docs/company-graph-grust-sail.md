# Company Graph Security Example

This example models agents writing a company hierarchy graph while Typesec gates
which nodes and relationships each agent may touch.

- Rust + Grust + Sail: `cargo run -p typesec-cli --example company_graph_grust_sail`
- Typed graph policy schema: `cargo run -p typesec-cli --example graph_policy_schema`
- Python LangChain-style wrapper: `uv run python examples/company_graph/langchain_company_graph.py`
- Python Pydantic AI wrapper: `uv run python examples/company_graph/pydantic_company_graph.py`
- Graph policy: `policies/graph-corporate-example.yaml`

The generated network is:

```text
employee:evelyn CEO
  <- REPORTS_TO employee:priya VP Engineering
      <- REPORTS_TO employee:marco Engineering Manager
          <- REPORTS_TO employee:nia Senior Software Engineer
          <- REPORTS_TO employee:omar Data Engineer
```

The graph policy makes the direction of access explicit:

- `agent:executive-chief` can write the company graph and read sensitive
  employee network data.
- `agent:hr-onboarding` can write non-executive employee nodes and reporting
  relationships, but cannot write executive-only nodes.
- `agent:employee-nia` can write only her own public profile and cannot read the
  sensitive network.

The policy file defines the protected company graph using Grust's YAML graph
format. Agent-role edges, employee nodes, and `REPORTS_TO` edges are part of the
same graph. Rules can then test graph predicates such as:

- subject has a `HAS_ROLE` edge to the required role.
- target employee node has label `Employee`.
- target employee level is not `Executive`.
- a proposed `REPORTS_TO` edge would not create a cycle.

The loader now routes YAML and JSON graph policies through Grust 0.5 typed graph
support and Zod schemas before the authorization engine sees a `Graph`. The same
company graph schema is used when examples write to Grust typed backends. The
schema example shows the important boundary checks:

- `Agent`, `Role`, and `Employee` are the accepted node labels.
- `Employee` nodes must carry the required company fields and reject extra
  fields.
- `HAS_ROLE` edges must connect `Agent -> Role`.
- `REPORTS_TO` edges must connect `Employee -> Employee`.
- YAML and JSON policies use the same typed loader.
- `MemoryGraphStore::put_typed_graph` accepts the valid policy graph and rejects
  graphs that violate the typed backend schema.

You can check the graph policy directly:

```sh
cargo run -p typesec-cli -- validate --policy policies/graph-corporate-example.yaml
cargo run -p typesec-cli -- check --policy policies/graph-corporate-example.yaml \
  --subject agent:hr-onboarding \
  --action write \
  --resource employee/private/employee:nia
cargo run -p typesec-cli --example graph_policy_schema
```

The Rust example uses Grust to construct a backend-neutral property graph. When
Sail SparkConnect is listening on `127.0.0.1:50051`, it applies the shared
company graph schema and writes the graph through
`SailGraphStore::put_typed_graph`; otherwise it still validates the graph against
that schema and demonstrates the security checks.

The Python examples share `company_graph_core.py`, which owns the in-memory
graph, employee fixture data, and `TypesecGate`. The gate tries the Rust-backed
`typesec_native` module first and falls back to the workspace CLI, so examples
can run from a checkout before the Python wheel is built.

The LangChain-style example is now just a thin adapter over that core. The
Pydantic AI example registers typed tools with `deps_type`/`RunContext`; each
tool asks Typesec for permission before mutating the graph. This uses Pydantic's
normal extension points and does not require forking Pydantic.
