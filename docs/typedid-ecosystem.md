# TypeDID Ecosystem Strategy

TypeDID should make agent communication safer without becoming another agent
framework. Its job is to be the secure envelope and policy bridge that can move
through today's agent ecosystem: LangChain, Pydantic AI, MCP, A2A, ACP, BAND,
WorkOS, Arcade, and direct HTTPS gateways.

The strategic rule is:

```text
frameworks plan, call tools, and manage state
protocols route tasks, sessions, rooms, and streams
providers authenticate users and authorize external systems
TypeDID protects cross-boundary payloads and binds them to Typesec policy
```

## Where TypeDID Fits

TypeDID sits below frameworks and above local policy enforcement:

```text
agent framework       LangChain / Pydantic AI / OpenAI Agents / CrewAI
tool protocol         MCP / Arcade / custom tools
collaboration layer   A2A / ACP / BAND
identity/authz        WorkOS / OIDC / Arcade OAuth
secure envelope       TypeDID
local proof           Typesec capabilities
```

TypeDID answers:

- Who cryptographically sent this payload?
- Who was it encrypted for?
- Which profile and protocol binding were negotiated?
- Is this send-only or request/reply?
- Is this reply bound to the exact request envelope?
- Which Typesec subject, action, and resource must be checked before reveal?

TypeDID should not own:

- Planning.
- Tool selection.
- Model routing.
- Agent memory.
- SaaS OAuth.
- Enterprise login.
- Human collaboration rooms.

## Integration Rings

### Ring 1: Core Protocol

This is where TypeDID should go deepest:

- Stable envelope schema.
- Canonical signing input.
- Reply binding.
- Profile negotiation.
- DID resolver abstraction.
- KMS/HSM-ready key-store abstraction.
- Payload privacy labels.
- Typesec subject/action/resource mapping.
- Audit metadata.
- Replay protection and expiry semantics.

### Ring 2: Framework Adapters

Adapters should be broad, thin, and idiomatic. They should avoid taking over
framework runtimes.

Targets:

- LangChain middleware and tool wrappers.
- Pydantic AI dependency/tool wrappers.
- MCP client/server authentication or envelope middleware.
- A2A content part adapter.
- ACP message attachment adapter.
- BAND secure-envelope adapter.
- OpenAI Agents SDK adapter once the stable extension points are clear.

### Ring 3: Provider Engines

Only go deep where there is a real authorization API.

- WorkOS belongs as a `PolicyEngine` because it answers app/org/resource access
  questions through FGA.
- Arcade belongs as a `PolicyEngine` because it answers external tool
  authorization questions for OAuth/API-key-backed tools.
- BAND belongs first as a secure-envelope collaboration adapter. Add a
  `BandGovernanceEngine` only if BAND exposes an explicit API for decisions
  such as "may this participant send/read/delegate in this room?"
- LangChain and Pydantic AI are not policy engines; they are framework adapter
  surfaces.

## LangChain

LangChain interop should start with middleware and tool wrapping.

Recommended pieces:

```text
TypeDIDTransport        wraps outbound framework payloads
TypeDIDToolWrapper      gates a callable before invocation
TypeDIDMiddleware       opens/gates inbound verified messages
TypeDIDMcpAuth          attaches envelope metadata to MCP HTTP calls
```

Depth target:

- Wrap outbound tool/task payloads in TypeDID.
- Verify inbound TypeDID payloads before passing them to a tool.
- Map sender DID, action, and resource into `typesec check --json` or native
  Python bindings.
- Provide a LangGraph node once a stable message-state pattern emerges.
- Do not fork LangChain's agent loop.

## Pydantic AI

Pydantic AI interop should use typed dependencies and tool wrappers.

Recommended pieces:

```text
TypeDIDDeps             resolver/gate/profile handles in deps
typedid_tool            policy-gated tool wrapper
open_typedid_message    converts a verified envelope into deps/tool input
send_typedid_reply      reply-bound response helper
```

Depth target:

- Put TypeDID identity and policy gate handles in `deps`.
- Use `RunContext` to access the verified sender and resource.
- Wrap tools so protected payloads are revealed only after policy allows.
- Keep Pydantic models for metadata and negotiation.
- Do not become a Pydantic AI transport runtime.

## MCP

MCP is the highest-leverage bridge because both LangChain and Pydantic AI can
use MCP tools.

Recommended pieces:

- TypeDID over Streamable HTTP headers for metadata and request digests.
- TypeDID envelope as a tool argument or resource blob for protected payloads.
- Server-side middleware that opens envelopes, runs Typesec policy, and passes
  protected payloads to MCP tools.
- Client-side helper that signs/encrypts requests and verifies reply binding.

## BAND

BAND should be treated as a collaboration layer, not as a TypeDID special case.

Current integration depth:

```text
BandSecureEnvelopeAdapter
  -> carries application/vnd.typedid.envelope+json through a room
  -> maps room id to TypeDID conversation_id
  -> lets BAND route and govern metadata without needing plaintext
```

Future integration depth:

```text
BandProfileResolver       discovers DIDs/profiles from contacts or rooms
BandRoomMessageEnvelope   helper for room-scoped payloads
BandGovernanceAuditSink   exports policy decisions and envelope digests
BandGovernanceEngine      only if BAND exposes explicit authorization checks
```

## Missing Features

Near-term:

- Python `typesec_typedid` helper package or module.
- Framework-neutral verified-message view for examples.
- LangChain-style middleware example.
- Pydantic AI dependency/tool example.
- MCP TypeDID auth/envelope sketch.
- `/.well-known/typedid.json` profile discovery.
- DID service endpoint profile discovery.

Protocol hardening:

- `did:key`, `did:web`, Universal Resolver, and Indy VDR resolvers.
- DIDComm/JWE and HPKE profiles.
- KMS/HSM key-store implementations.
- Nonce/message-id replay cache.
- Clock-skew and expiry policy.
- Capability binding to envelope digest, profile, and conversation id.
- Audit export for open/allow/deny/reply events.
- Multi-recipient and group-message envelopes for room fabrics.
- Streaming/session-key profile.
- Golden conformance vectors for signing input, encryption, reply binding, and
  tamper rejection.

## Implementation Posture

The right next step is not a deep framework package. It is a small, testable
adapter seam:

```text
Rust TypeDidGateway opens and verifies envelope
  -> framework-neutral VerifiedTypeDidMessageView
  -> Python adapter calls typesec check --json
  -> LangChain/Pydantic-style wrapper gates tool invocation
```

That lets the project prove the integration boundary before committing to
published framework packages.
