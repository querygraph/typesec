# Typesec Fuzz Targets

Run with `cargo fuzz` from the repository root:

```sh
cargo fuzz run rbac_yaml -- -max_total_time=300
cargo fuzz run odrl_yaml -- -max_total_time=300
```

The targets feed arbitrary UTF-8 into the RBAC and ODRL YAML parsers and engine
constructors. They are kept in a standalone package excluded from the workspace
so normal `cargo test --workspace` and release builds do not require libFuzzer.
