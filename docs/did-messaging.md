# DID Messaging Integration

Typesec treats decentralized identifiers as identity, key-discovery, and
message-routing handles. A DID does not grant authority by itself. It identifies
the subject that asks for access; the existing `PolicyEngine` still decides
whether Typesec can mint a typed capability.

The integration lives in `typesec-integrations::did` and provides:

- `Did`, `DidDocument`, `VerificationMethod`, and `DidService` for the local
  DID document model.
- `DidResolver` and `StaticDidResolver` as the resolver boundary.
- `DidKeyStore`, `Ed25519DidKeyStore`, and optional `DemoDidKeyStore` as the
  signing/encryption boundary.
- `DidEnvelope` and `DidMessageGateway` for DID-wrapped encrypted prompts.
- `DidOllamaClient` for sending verified prompts to Ollama or forwarding a
  wrapped prompt to a DID-aware Ollama fork.
- `DidMessageReference` for binding a reply envelope to the exact signed prompt
  envelope that produced it.
- TypeDID agent-communication helpers: `TypeDidMode`,
  `TypeDidConversation`, `TypeDidProfile`, `TypeDidGateway`,
  `SecureEnvelopeAdapter`, `A2aTypeDidAdapter`, `AcpTypeDidAdapter`,
  `BandSecureEnvelopeAdapter`, and `HttpTypeDidAdapter`.

`Ed25519DidKeyStore` is the default local implementation: Ed25519 signatures,
X25519 key agreement, and ChaCha20-Poly1305 payload encryption. The deterministic
`DemoDidKeyStore` is non-cryptographic and only compiled in tests or with the
`demo-crypto` feature. Production deployments can also replace the key and
resolver traits with DIDComm/JWE, HPKE, HSM/KMS-backed keys, Hyperledger Indy
VDR, or a Universal Resolver client without changing the Typesec capability path.

## Flow

```text
DID envelope arrives
  -> resolve sender DID
  -> verify envelope signature
  -> decrypt payload for the local recipient DID
  -> wrap plaintext as SecureValue<Secret, String, GenericResource>
  -> request CanReadSensitive and AiCanInfer capabilities
  -> reveal and send to Ollama only when both typed capabilities exist
```

The important invariant is unchanged: verified identity is not authorization.
The sender DID becomes the Typesec subject string, and policy still evaluates:

```text
subject = did:key:z...
action = ai:infer
resource = prompt/session/123
```

## Local DID Example

The workspace includes a runnable offline example:

```sh
cargo run -p typesec-cli --example did_messaging
```

The example creates two local `did:key` identifiers:

```rust
let alice_key = Ed25519DidKey::from_seed(b"alice");
let gateway_key = Ed25519DidKey::from_seed(b"typesec-ollama-gateway");

let alice = Did::key(alice_key.signing_public());
let gateway_did = Did::key(gateway_key.signing_public());
```

It registers local DID documents with `StaticDidResolver`:

```rust
let resolver = StaticDidResolver::new()
    .with_document(alice_key.document(alice.clone()))
    .with_document(gateway_key.document(gateway_did.clone()));
```

Then it builds a DID-wrapped prompt:

```rust
let envelope = DidEnvelope::prompt(
    "prompt-msg-1",
    alice.clone(),
    gateway_did.clone(),
    DidMessageBody::infer_prompt("prompt/session/123"),
    "Summarize this confidential report without exposing raw customer data.",
    &resolver,
    &key_store,
)?;
```

The gateway verifies and decrypts the message:

```rust
let gateway =
    DidMessageGateway::new(Arc::new(resolver), Arc::new(key_store), gateway_did);
let verified = gateway.open_prompt(&envelope)?;
```

The decrypted prompt is not returned as a normal string. It is held as:

```rust
SecureValue<Secret, String, GenericResource>
```

The example mints both capabilities before sending the prompt to an
Ollama-shaped endpoint:

```rust
let infer: Capability<AiCanInfer, _> =
    mint_capability(&policy, verified.subject.as_str(), &verified.resource)?;
let read: Capability<CanReadSensitive, _> =
    mint_capability(&policy, verified.subject.as_str(), &verified.resource)?;

let reply = ollama.chat_verified_prompt_bound(
    verified,
    gateway_did,
    &resolver,
    &key_store,
    &infer,
    &read,
)?;
```

This mirrors the production control flow even though the example uses
deterministic local keys and a recording HTTP client.

## TypeDID Agent Communications

TypeDID generalizes the DID prompt envelope for agent-to-agent communication.
It keeps A2A, ACP, BAND, HTTPS, or another protocol in charge of discovery,
tasks, rooms, sessions, streaming, and routing while TypeDID provides the
security envelope:

```text
outer protocol        -> task/session/room lifecycle
TypeDID envelope      -> sender DID, recipient DID, profile, mode, ciphertext
TypeDidGateway        -> verify, decrypt, protect opaque payload bytes
Typesec PolicyEngine  -> decide whether the verified DID can reveal/use payload
```

`TypeDidProfile::negotiate` selects a mutually supported secure profile across
a boundary. The selected profile id and protocol binding are signed inside
`TypeDidConversation`, so a relay cannot rewrite an A2A envelope into a BAND
room message or downgrade the security profile without invalidating the
signature.

TypeDID supports two modes:

```text
send           authenticated encrypted delivery; no TypeDID reply required
request_reply  receiver answers with a reply envelope bound to request digest
```

The runnable example shows A2A-style request/reply, ACP-style send-only, and a
BAND-style room message through the generic secure-envelope adapter:

```sh
cargo run -p typesec-cli --example typedid_agent_communications
```

See [`typedid-agent-communications.md`](typedid-agent-communications.md) for
the design details and adapter guidance.

## DID Shapes to Support

Use different DID methods for different deployment stages:

```text
did:key       no ledger or hosting; good for tests and generated agent keys
did:web       self-hosted public DID document at an HTTPS domain
did:indy      ledger-backed DID document over Hyperledger Indy/Indy VDR
public DID    any resolver-supported method through a Universal Resolver client
```

For `did:web`, a self-hosted resolver can fetch:

```text
https://example.com/.well-known/did.json
```

and return the same `DidDocument` model used by the local resolver. For
`did:key`, the resolver can derive the DID document directly from the method
identifier. For public DID methods, an adapter can call a Universal Resolver
HTTP endpoint and translate the returned DID document into Typesec's local
model.

## Ollama Modes

`DidOllamaClient::chat_verified_prompt` is the stricter mode. Typesec verifies
and decrypts the envelope locally, requires `Capability<AiCanInfer, _>` and
`Capability<CanReadSensitive, _>`, then sends the plaintext prompt to the local
Ollama `/api/chat` endpoint.

`DidOllamaClient::chat_verified_prompt_bound` is the audit mode. It performs
the same capability-guarded reveal and Ollama call, extracts
`message.content`, and returns a new signed/encrypted DID reply envelope instead
of loose JSON. The reply envelope gets a fresh DID-shaped id, inherits the
prompt's action, resource, and privacy label, and carries a `reply_to` reference
containing the original prompt envelope id and digest. That reference is part of
the reply signature, so changing the prompt binding invalidates the reply.

`DidOllamaClient::chat_wrapped_prompt` is the compatibility mode for an
Ollama-compatible server that expects to receive the DID envelope directly, such
as a DID-aware fork. Typesec forwards the envelope under the `did_envelope`
field while preserving the same API boundary.

## Ledger Backends

The first implementation ships the local resolver and key store. The next
ledger-backed adapters should implement the existing `DidResolver` trait:

- `DidKeyResolver` for zero-infrastructure local identities.
- `DidWebResolver` for easy self-hosted public DIDs.
- `UniversalResolverClient` for public DID method coverage.
- `IndyVdrResolver` for Hyperledger Indy VDR and local Indy test networks.

Those adapters should remain in `typesec-integrations`, not `typesec-core`, so
ledger, HTTP, and cryptography dependencies stay at the edge.

## Local Hyperledger Indy Ledger

For local Hyperledger DID testing, use a development Indy ledger and an Indy VDR
reader. The recommended local path is:

```text
VON Network      local development Indy Node network and ledger browser
Indy VDR         Rust library/proxy for reading Indy ledgers and resolving did:indy
Typesec adapter  implements DidResolver by calling Indy VDR
```

VON Network is explicitly development/test infrastructure, not a production Indy
network. It exposes a ledger browser, a `/genesis` endpoint, and a convenience
path for writing test DIDs. Indy VDR is the Rust-side ledger reader and proxy;
it can read a pool from genesis transactions and exposes read endpoints,
including `GET /1.0/identifiers/{DID or DID_URL}` for DID resolution.

### Start VON Network

From a separate working directory:

```sh
git clone https://github.com/bcgov/von-network.git
cd von-network
./manage build
REGISTER_NEW_DIDS=True ./manage start
```

When the network is healthy, the ledger browser is normally available at:

```text
http://localhost:9000
```

Fetch the genesis transactions that Indy clients need:

```sh
curl -fsS http://localhost:9000/genesis -o /tmp/von-genesis.txn
```

Use the browser's "Authenticate a New DID" interface, or the VON API, to write
a development DID/NYM to the ledger. The VON README notes that this convenience
uses a known trust-anchor DID and is only appropriate for sandbox ledgers.

You can inspect a written DID through VON's ledger browser:

```text
http://localhost:9000/browse/domain
```

### Start Indy VDR Proxy

Build Indy VDR separately:

```sh
git clone https://github.com/hyperledger-indy/indy-vdr.git
cd indy-vdr
cargo build --bin indy-vdr-proxy
```

Start the proxy against the local VON genesis file:

```sh
./target/debug/indy-vdr-proxy -p 9001 -g /tmp/von-genesis.txn
```

Smoke-test ledger reads:

```sh
curl -fsS http://localhost:9001/genesis
curl -fsS http://localhost:9001/nym/<UNQUALIFIED_DID>
```

For `did:indy` resolution, Indy VDR documents:

```text
GET /1.0/identifiers/{DID or DID_URL}
```

A public or named Indy network uses a qualified `did:indy` namespace. A local
single-ledger VON setup is often easiest to smoke-test with `/nym/<DID>` first,
then map that NYM response into the local `DidDocument` shape in an
`IndyVdrResolver`.

### Typesec Adapter Shape

The adapter does not belong in `typesec-core`. It should live in
`typesec-integrations` and implement the existing resolver trait:

```rust
pub struct IndyVdrResolver {
    base_url: String,
    http: Arc<dyn HttpClient>,
}

impl DidResolver for IndyVdrResolver {
    fn resolve(&self, did: &Did) -> Result<DidDocument, DidError> {
        // GET {base_url}/1.0/identifiers/{did}
        // or, for a local VON smoke test, GET {base_url}/nym/{unqualified_did}
        // Then translate verification methods and service endpoints into
        // Typesec's DidDocument model.
        todo!("wire Indy VDR JSON into DidDocument")
    }
}
```

Once the resolver returns a `DidDocument`, the rest of the Typesec flow does not
change:

```text
IndyVdrResolver resolves sender DID
DidKeyStore verifies/decrypts the envelope
DidMessageGateway returns VerifiedDidPrompt
PolicyEngine mints capabilities
DidOllamaClient sends the prompt
```

That separation is intentional. Hyperledger proves DID state and keys; Typesec
still decides whether the verified subject can use a protected prompt.
