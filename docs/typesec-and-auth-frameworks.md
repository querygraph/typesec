# Typesec and OAuth-Based Auth Frameworks

## Short Version

Typesec is not an OAuth or decentralized-identity replacement. It is a stronger
in-process enforcement layer that can sit behind OAuth/OIDC identity, provider
authorization, or DID-based secure messages. Arcade.dev and WorkOS are mostly
about who the actor is, which external/service resources they can reach, and how
tokens, consent, and checks are managed at runtime. DIDs add resolvable
cryptographic identifiers and encrypted message routing. Typesec is about
making the application/tool code unable to perform sensitive actions unless it
holds a typed, unforgeable capability.

That gives Typesec a crisp positioning:

> OAuth proves and delegates identity. Typesec turns authorization decisions
> into compile-time-visible authority inside agent/tool code.

The same frame applies to DIDs:

> DID messaging proves control of an identifier and protects the payload.
> Typesec decides whether that verified subject may reveal or use the payload.

## Comparison

| Dimension | Typesec | Arcade.dev | WorkOS | DIDs |
| --- | --- | --- | --- | --- |
| Primary layer | Code-level enforcement for agent/tool execution | MCP/tool runtime and delegated user auth | Identity, OAuth apps, RBAC/FGA, enterprise auth | Decentralized identity, key discovery, secure messaging |
| Core primitive | `Capability<P, R>` plus typestate `Agent<Authenticated>` | User-specific tool authorization, OAuth/API-key token management | OAuth/OIDC tokens, org claims, RBAC/FGA access checks | DID, DID document, verification methods, encrypted envelopes |
| Enforcement style | Static API shape: functions require typed capabilities | Runtime gateway/tool authorization | Runtime JWT checks and Authorization API | Cryptographic verification and decryption at the message edge |
| OAuth role | Not the core model; provider validation lives in integrations | Central: manages OAuth/API keys/user tokens for tools | Central: AuthKit/Connect use OAuth/OIDC flows | Usually orthogonal; DIDs can bridge non-OAuth identities |
| Agent fit | Strong for preventing skipped checks in Rust tools and SDKs | Strong for letting agents call SaaS tools as users | Strong for enterprise identity and app/resource authorization | Strong for portable agent/service identities and encrypted prompts |
| Fine-grained resources | RBAC, ODRL constraints, graph policy, resource types | Tool/provider scopes and gateway/tool authorization | Hierarchical resource-scoped FGA | DID URL resources and payload metadata; policy still lives elsewhere |
| Main weakness | Needs broader language/runtime story and production DID/OAuth backends | Still runtime checks; agent/tool code can misuse results unless wrapped correctly | Runtime checks can be forgotten unless every app path is disciplined | Proves control and protects messages, but does not answer app authorization alone |

## Typesec's Differentiator

Typesec's README says the core promise plainly: policies are encoded in types
and violations become compile errors, not runtime permission failures. A write
operation can require `Capability<CanWrite, Report>`, so the sensitive method is
simply unavailable unless the code has proof of authorization.

The implementation backs that up:

- Capabilities are unforgeable: private fields, a `pub(crate)` constructor, and
  sealed permissions.
- `mint_capability` is the public gated path: it calls the policy engine, logs
  the result, and only constructs a capability on `Allow`.
- Typestate prevents unauthenticated agents from requesting capabilities because
  the method is absent before authentication.
- `SecureValue` adds information-flow flavor: sensitive data can be transformed,
  but reveal/declassify requires typed authority.

## DIDs

DIDs are a good fit for portable agent and service identities. A DID resolves to
a DID document with verification methods and service endpoints. A sender can
sign an envelope, encrypt a prompt for a recipient DID, and route it without
depending on a single identity provider.

That solves a different problem than Typesec. DID verification answers:

```text
Did this controller sign the message?
Was this payload encrypted for this recipient?
Which endpoint or key does this DID document advertise?
```

Typesec answers:

```text
May this verified subject run ai:infer on prompt/session/123?
May this code reveal a SecureValue<Secret, _, _>?
May this tool exfiltrate the result?
```

The current `typesec-integrations::did` module keeps those responsibilities
separate. `DidResolver` handles DID document resolution. `DidKeyStore` handles
signing, verification, encryption, and decryption. `DidMessageGateway` converts
a verified encrypted prompt into `SecureValue<Secret, String, GenericResource>`.
`DidOllamaClient` then requires `Capability<AiCanInfer, _>` and
`Capability<CanReadSensitive, _>` before sending plaintext to Ollama.

The included resolver and key store are local test utilities. Production
integrations should plug in DIDComm/JWE, Hyperledger Indy VDR, Universal
Resolver, `did:web`, `did:key`, or KMS-backed key material behind the same
traits.

## Arcade.dev

Arcade is the closest agent-native OAuth comparison. Its docs say it handles
OAuth 2.0, API keys, and user tokens so AI agents can access external services
through tools. It stores authorization tokens and checks authorization when
executing tools. It also distinguishes server/front-door OAuth from tool-level
authorization: resource-server auth protects the MCP server, while tool-level
auth lets tools call third-party APIs on behalf of the authenticated user.

So Arcade is better than Typesec today for "connect this agent to Gmail, Slack,
or Jira safely with user consent and token management." Typesec is better for
"make it impossible for my Rust tool implementation to call `send_email` unless
a typed `CanSendEmail` proof exists."

References:

- [Arcade Authorized Tool Calling](https://docs.arcade.dev/en/guides/tool-calling/custom-apps/auth-tool-calling)
- [Arcade: Securing MCP Deployments](https://docs.arcade.dev/en/guides/create-tools/secure-your-server)

## WorkOS

WorkOS is broader enterprise auth infrastructure. OAuth Applications use the
authorization-code flow for user-authenticated web, mobile, desktop, and CLI
apps, with consent for third-party apps, PKCE for public clients, token
verification via JWKS, and `org_id` scoping in access tokens. WorkOS FGA adds
hierarchical, resource-scoped authorization with access checks like "Can this
user perform this action on this resource?"

WorkOS is better than Typesec today for enterprise login, SSO, org membership,
JWT/session handling, IdP sync, and hosted authorization APIs. Typesec is
stronger at local enforcement ergonomics: once WorkOS says "yes," Typesec can
make that "yes" a capability required by the code path.

References:

- [WorkOS OAuth Applications](https://workos.com/docs/authkit/connect/oauth)
- [WorkOS FGA Overview](https://workos.com/docs/fga/index)
- [WorkOS Access Checks](https://workos.com/docs/fga/access-checks)

## Best Strategic Framing

Typesec should not pitch itself as "instead of OAuth." The strongest frame is:

1. Use WorkOS/AuthKit/OIDC for authentication and enterprise identity.
2. Use Arcade-style runtime authorization for SaaS tool OAuth and delegated user
   tokens.
3. Use DID messaging when agents or services need portable cryptographic
   identifiers and encrypted payloads outside a single OAuth provider.
4. Use Typesec inside custom tools/agents to make authorization non-optional at
   the call site.

That makes Typesec the missing compile-time guardrail under OAuth-based agent
and DID-based agent systems: OAuth grants a token; FGA/tool auth makes a
runtime decision; DID messaging proves and decrypts a sender; Typesec prevents
the implementation from accidentally ignoring those facts.
