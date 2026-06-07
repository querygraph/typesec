# Company Graph Security Example

This example models agents writing a company hierarchy graph while Typesec gates
which nodes and relationships each agent may touch.

- Rust + Grust + Sail: `cargo run -p typesec-cli --example company_graph_grust_sail`
- Python LangChain-style wrapper: `python3 examples/company_graph/langchain_company_graph.py`
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

You can check the graph policy directly:

```sh
cargo run -p typesec-cli -- validate --policy policies/graph-corporate-example.yaml
cargo run -p typesec-cli -- check --policy policies/graph-corporate-example.yaml \
  --subject agent:hr-onboarding \
  --action write \
  --resource employee/private/employee:nia
```

The Rust example uses Grust to construct a backend-neutral property graph. When
Sail SparkConnect is listening on `127.0.0.1:50051`, it writes the graph through
`SailGraphStore`; otherwise it skips the backend write and still demonstrates the
security checks.

The Python example is self-contained. It follows LangChain's tool-gating shape:
each graph-writing tool call first asks `typesec check` whether the agent has the
required policy capability. A denied decision raises `PermissionError` before the
tool body can mutate the graph.
