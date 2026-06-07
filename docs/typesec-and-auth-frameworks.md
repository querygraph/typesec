# Typesec and OAuth-Based Auth Frameworks

## Short Version

Typesec is not an OAuth replacement. It is a stronger in-process enforcement
layer that can sit behind OAuth/OIDC identity. Arcade.dev and WorkOS are mostly
about who the actor is, which external/service resources they can reach, and how
tokens, consent, and checks are managed at runtime. Typesec is about making the
application/tool code unable to perform sensitive actions unless it holds a
typed, unforgeable capability.

That gives Typesec a crisp positioning:

> OAuth proves and delegates identity. Typesec turns authorization decisions
> into compile-time-visible authority inside agent/tool code.

## Comparison

| Dimension | Typesec | Arcade.dev | WorkOS |
| --- | --- | --- | --- |
| Primary layer | Code-level enforcement for agent/tool execution | MCP/tool runtime and delegated user auth | Identity, OAuth apps, RBAC/FGA, enterprise auth |
| Core primitive | `Capability<P, R>` plus typestate `Agent<Authenticated>` | User-specific tool authorization, OAuth/API-key token management | OAuth/OIDC tokens, org claims, RBAC/FGA access checks |
| Enforcement style | Static API shape: functions require typed capabilities | Runtime gateway/tool authorization | Runtime JWT checks and Authorization API |
| OAuth role | Not the core model; current auth token validation is intentionally minimal | Central: manages OAuth/API keys/user tokens for tools | Central: AuthKit/Connect use OAuth/OIDC flows |
| Agent fit | Strong for preventing skipped checks in Rust tools and SDKs | Strong for letting agents call SaaS tools as users | Strong for enterprise identity and app/resource authorization |
| Fine-grained resources | RBAC, ODRL constraints, graph policy, resource types | Tool/provider scopes and gateway/tool authorization | Hierarchical resource-scoped FGA |
| Main weakness | Needs OAuth/IdP integration and broader language/runtime story | Still runtime checks; agent/tool code can misuse results unless wrapped correctly | Runtime checks can be forgotten unless every app path is disciplined |

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
3. Use Typesec inside custom tools/agents to make authorization non-optional at
   the call site.

That makes Typesec the missing compile-time guardrail under OAuth-based agent
systems: OAuth grants a token; FGA/tool auth makes a runtime decision; Typesec
prevents the implementation from accidentally ignoring that decision.
