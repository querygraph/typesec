# TypeDID Agent Communications

TypeDID is the agent-communication profile of Typesec DID messaging. It is not
another agent protocol. It is the security envelope and policy bridge that can
travel over A2A, ACP, BAND, direct HTTP, WebSocket, queues, or a future
transport.

The core idea is:

```text
agent protocol handles discovery, tasks, rooms, streaming, and UX
TypeDID handles sender identity, recipient identity, payload protection,
reply binding, trust negotiation, and the handoff into Typesec policy
```

That keeps TypeDID small enough to compose with the protocols agents are
already adopting.

## Goals

- Wrap every cross-agent payload in a DID-signed and encrypted envelope.
- Support fire-and-forget sends and request/reply conversations.
- Let organizations negotiate the secure envelope profile before sending
  sensitive payloads across a company, cloud, tenant, or system boundary.
- Preserve the existing Typesec invariant: verified identity is not authority.
  DID verification identifies the subject; `PolicyEngine` decides what that
  subject may do.
- Integrate with A2A, ACP, BAND, and other agent transports without
  special-casing any one platform.

## Implemented Protocol Shape

TypeDID extends the existing `DidEnvelope` model with optional signed
conversation metadata. Existing DID prompt envelopes remain compatible because
the TypeDID fields are only present on TypeDID envelopes:

```text
id             envelope id
sender         sender DID
recipient      recipient DID
body.action    policy-visible action, such as ai:infer or agent:delegate
body.resource  policy-visible resource, such as task/123 or room/acme-support
body.privacy   payload label, such as public, internal, confidential, secret
body.reply_to  optional signed reference to the envelope being answered
ciphertext     encrypted protocol payload
signature      sender signature over the protected envelope
```

TypeDID envelopes add conversation metadata without making it transport
specific:

```text
conversation_id  stable conversation/task/room id from the outer protocol
mode             send | request_reply
expires_at       optional payload expiry
profile          negotiated TypeDID profile id
protocol         outer protocol hint: a2a, acp, band, http, websocket, queue
```

The encrypted payload can contain an A2A part, ACP message, BAND room message,
tool call, approval request, or Typesec-native command. `TypeDidGateway` treats
it as opaque bytes until policy permits reveal.

## Rust API

The implemented API lives in `typesec-integrations::did` and is re-exported
from `typesec_integrations`:

```text
TypeDidMode                  send | request_reply
TypeDidConversation          signed conversation/profile metadata
TypeDidProfile               negotiable secure envelope profile
TypeDidProfileResolver       profile discovery boundary
StaticTypeDidProfileResolver local deterministic profile resolver
TypeDidGateway               verifier/decrypter for opaque payloads
SecureEnvelopeAdapter        common adapter trait
A2aTypeDidAdapter            A2A content binding
AcpTypeDidAdapter            ACP content binding
BandSecureEnvelopeAdapter    generic BAND secure-envelope binding
HttpTypeDidAdapter           direct HTTPS binding
VerifiedTypeDidMessage       protected opaque payload plus policy metadata
```

Run the end-to-end example:

```sh
cargo run -p typesec-cli --example typedid_agent_communications
```

## Send Modes

### Send Only

Use this when the sender needs authenticated delivery but not a protocol-level
answer.

```text
sender resolves recipient DID
sender selects a compatible TypeDID profile
sender signs and encrypts payload
transport delivers envelope
receiver verifies, decrypts, checks policy, and processes payload
receiver may emit an audit event or transport-level ack, but no TypeDID reply is
required
```

Good fits:

- Notifications.
- Delegation events where the outer platform owns task state.
- Append-only audit or memory updates.
- Broadcasts to a governed room where replies happen as separate messages.

### Send And Get Reply

Use this when the sender expects a cryptographically bound answer.

```text
sender creates request envelope with mode=request_reply
receiver verifies, decrypts, and checks policy
receiver creates reply envelope with body.reply_to = digest(request envelope)
receiver signs and encrypts reply for the original sender
sender verifies reply signature and reply_to binding before reveal
```

This is the generalization of the existing bound Ollama reply path. The reply
must not merely reuse a conversation id; it should include a digest of the exact
request envelope so it cannot be detached and replayed as an answer to a
different request.

Good fits:

- Agent delegation where the caller needs a result.
- Cross-company tool invocation.
- Approval requests.
- Human-in-the-loop questions.
- Model gateway calls that return protected output.

## Boundary Negotiation

When agents cross a company, tenant, cloud, or regulated system boundary, the
sender should not assume the receiver accepts the same envelope format,
algorithm suite, DID method, or retention rules. Add a small discovery and
negotiation layer:

```text
TypeDIDProfile {
  id: "typedid/v1/x25519-chacha20poly1305-ed25519",
  did_methods: ["did:web", "did:key", "did:indy"],
  signing: ["Ed25519"],
  key_agreement: ["X25519"],
  encryption: ["ChaCha20-Poly1305", "DIDComm-JWE", "HPKE"],
  transport_bindings: ["a2a", "acp", "band", "https", "websocket"],
  modes: ["send", "request_reply"],
  max_payload_bytes: 1048576,
  required_claims: ["org", "agent_id", "purpose"],
  policy_actions: ["agent:message", "agent:delegate", "ai:infer"],
  retention: "sender-encrypted-payload-only",
  audit: "envelope-metadata-and-policy-decision"
}
```

Negotiation should be two-step:

1. Discovery: read a DID service endpoint, A2A Agent Card metadata, ACP
   capability metadata, BAND contact metadata, or a direct
   `/.well-known/typedid.json` profile document.
2. Agreement: choose the strongest mutually supported profile and bind the
   chosen `profile` id into the signed envelope.

If no compatible profile exists, the caller should fail closed or downgrade to a
non-sensitive, policy-approved message that asks the receiver to onboard a
compatible profile.

## A2A Integration

A2A is a good outer protocol for agent-to-agent tasks because it already covers
agent discovery, capability advertisement, synchronous request/response,
streaming, push notifications, rich parts, and long-running task lifecycle.

TypeDID should integrate with A2A as:

```text
A2A Agent Card advertises TypeDID support
A2A message part carries application/vnd.typedid.envelope+json
A2A task id maps to TypeDID conversation_id
A2A send maps to TypeDID mode=send
A2A request/response, streaming, or push maps to mode=request_reply plus
reply_to-bound envelopes for final or intermediate replies
```

The A2A server remains A2A-compliant. TypeDID is just a supported content type
and security profile. The server can reject plaintext task payloads for
protected resources while still accepting non-sensitive A2A metadata.

Suggested A2A Agent Card extension:

```json
{
  "extensions": {
    "typedid": {
      "profiles": [
        "typedid/v1/x25519-chacha20poly1305-ed25519",
        "typedid/v1/didcomm-jwe"
      ],
      "did": "did:web:agent.example.com",
      "service": "https://agent.example.com/.well-known/typedid.json",
      "modes": ["send", "request_reply"]
    }
  }
}
```

## ACP Integration

ACP is most useful when an editor or IDE talks to local or remote coding agents.
The remote-agent path is the interesting TypeDID boundary: the editor may send
repository context, diffs, task instructions, approvals, or secrets to an agent
outside the local process.

TypeDID should integrate with ACP as:

```text
ACP client or agent advertises TypeDID profiles during initialization
ACP message content can carry a TypeDID envelope as a structured attachment
ACP session id maps to TypeDID conversation_id
editor-originated approvals and repository-sensitive payloads are encrypted for
the agent DID
agent replies that include generated patches, explanations, or approval
requests can be reply_to-bound envelopes
```

The local stdio case may not need TypeDID for transport confidentiality, but it
can still use TypeDID for audit binding and policy consistency when the same
agent can later run remotely.

## BAND Integration

BAND should be treated as a collaboration fabric, not as a TypeDID special case.
Its public positioning is a shared interaction layer for multi-agent and human
collaboration, with persistent identity, rooms, routing, discovery, governance,
structured memory, and unified audit. That is exactly the layer TypeDID should
ride on top of.

The integration should be:

```text
BAND contact identity includes or links to one or more DIDs
BAND room id maps to TypeDID conversation_id
BAND message body can carry application/vnd.typedid.envelope+json
BAND routing delivers envelopes but does not need plaintext access
BAND governance can inspect envelope metadata and Typesec policy decisions
without decrypting protected payloads
```

For BAND specifically, propose a generic "secure envelope adapter" rather than
a TypeDID-only adapter:

```text
SecureEnvelopeAdapter {
  content_types: [
    "application/vnd.typedid.envelope+json",
    "application/didcomm-encrypted+json",
    "application/jose+json"
  ],
  discover(contact) -> envelope profiles
  wrap(message, recipient, profile) -> encrypted envelope
  unwrap(envelope, local_identity) -> protected payload
  policy_check(metadata, payload_resource) -> allow | deny
  audit(envelope_metadata, decision)
}
```

TypeDID would be one implementation of this adapter. BAND would not need to
know Typesec internals, and Typesec would not need BAND-specific semantics. The
contract is the envelope metadata, recipient DID, conversation id, content type,
and policy decision.

That gives BAND a clean story:

- BAND still owns rooms, routing, contact discovery, delegation lifecycle,
  governance workflows, and audit views.
- TypeDID owns cryptographic sender/recipient binding, encrypted payloads,
  reply binding, and Typesec capability handoff.
- Other secure envelope schemes can coexist beside TypeDID using the same BAND
  adapter surface.

## Typesec Implementation Plan

1. Add `TypeDidMode`, `TypeDidProfile`, and `TypeDidConversation` metadata to
   the DID message model while keeping existing prompt envelopes compatible.
2. Generalize `DidMessageBody::infer_prompt` into constructors for
   `agent:message`, `agent:delegate`, `agent:reply`, and `ai:infer`.
3. Add `TypeDidGateway` on top of `DidMessageGateway` that can open an envelope
   into a protected opaque payload plus policy-visible metadata.
4. Add transport adapters in `typesec-integrations`, not `typesec-core`:
   `A2aTypeDidAdapter`, `AcpTypeDidAdapter`, `BandSecureEnvelopeAdapter`, and
   `HttpTypeDidAdapter`.
5. Add a `TypeDidProfileResolver` that can read profiles from DID service
   endpoints, `/.well-known/typedid.json`, A2A cards, ACP capabilities, or BAND
   contact metadata.
6. Keep policy evaluation unchanged: sender DID becomes subject, body action
   becomes action, body resource becomes resource, and reveal requires the
   relevant typed capability.

## Open Design Questions

- Should profile negotiation be optimistic and cached, or should every boundary
  crossing bind a fresh profile version?
- Which payload classes require reply binding by default?
- Should BAND/a room fabric see policy decisions only, or also encrypted
  payload digests and privacy labels for governance dashboards?
- Should `did:web` be the default production DID method while `did:key` remains
  the local/test default?
- Should Typesec define a formal media type registry for TypeDID envelopes and
  payload classes?
