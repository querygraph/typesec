# Typesec Improvement Notes

This note reviews the first Claude draft and records the next useful upgrades.

## What Was Improved

- Upgraded the workspace package edition to Rust 2024.
- Fixed current compiler failures in lattice tests, proc-macro parsing, examples, and doctests.
- Made `cargo clippy --all-targets -- -D warnings` pass by tightening the combinator API, deriving defaults, documenting public ODRL fields, and applying current Clippy simplifications.
- Stabilized the audit integration test by using a global capture subscriber for the test binary instead of a racy thread-local subscriber.
- Added Python smoke tests around `typesec check` so Python agents can exercise policy decisions without a native binding.
- Added `typesec check --json` so Python and shell agents can consume a stable machine-readable decision without parsing human output.
- Added in-process revocation epochs and configurable capability TTLs: `MintOptions { ttl, revocation }`, `mint_capability_with`, `mint_capability_for_id`, and `RevocationEpoch::revoke_all()` invalidating live capabilities mid-lease.
- Moved bearer secrets into the redacting `Token` newtype (`Debug` prints `Token(<redacted>)`; no `Display`/`PartialEq`), read only via `expose()` at the verifier.
- Added async policy and audit paths so `SecureAgent::request_capability` can await native async engines directly while sync engines keep a default adapter.
- Replaced archived `serde_yaml` with the API-compatible `serde_norway` fork via package rename; bumped `thiserror` to 2.

## Design Gaps To Close Next

- Add compile-fail tests with `trybuild` for the central promise: unauthenticated agents cannot request capabilities, actions cannot execute without capabilities, and lower capabilities cannot coerce upward.
- Generate typed permission/resource modules from policy files, then compile downstream examples against generated code so policy renames break at compile time.
- Split policy `Deny`, `Delegate`, and constraint failure semantics more explicitly. Today `mint_capability` treats delegation as an error; composed deployments should make that fallback path first-class.
- Extend revocation from in-process epochs to distributed ones. `RevocationEpoch` now invalidates live capabilities within a process; a fleet of agents still needs policy-version binding or a shared epoch service for global revocation.
- Add an optional PyO3 crate later if Python integrations need in-process checks, but keep the CLI boundary first because it is easy to sandbox and test.

## Python And LangChain Testing

The lowest-friction Python test is a subprocess policy oracle:

1. Create an RBAC or ODRL YAML policy in a temp file.
2. Run `cargo run -q -p typesec-cli -- check --policy <file> --subject ... --action ... --resource ...`.
3. Treat exit code `0` as allow and nonzero as blocked.
4. Gate Python tool execution on that decision.

That can become a LangChain tool wrapper. In pseudocode:

```python
class TypesecGate:
    def allowed(self, subject: str, action: str, resource: str, purpose: str | None = None) -> bool:
        result = subprocess.run([...], capture_output=True, text=True)
        return result.returncode == 0

def secure_tool_call(gate: TypesecGate, subject: str, action: str, resource: str, fn):
    if not gate.allowed(subject, action, resource):
        raise PermissionError(f"{subject} cannot {action} {resource}")
    return fn()
```

Yes, we can create a LangChain agent on the fly with a Typesec security policy. The key is to wrap each side-effecting LangChain tool with a `TypesecGate` check before the tool body runs. That tests the same agentic boundary the Rust code is trying to make impossible to forget.
