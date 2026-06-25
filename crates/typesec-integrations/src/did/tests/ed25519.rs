use std::sync::Arc;

use typesec_core::{
    Capability, Resource, permissions::CanReadSensitive, policy::mint_capability,
    resource::GenericResource,
};

use super::super::*;
use super::common::*;

#[test]
fn ed25519_envelope_roundtrip() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let envelope = DidEnvelope::prompt(
        "msg-ed-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/ed"),
        "confidential prompt over real crypto",
        &resolver,
        &keys,
    )
    .expect("envelope");
    assert_ne!(envelope.ciphertext, "confidential prompt over real crypto");

    let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    let verified = gateway.open_prompt(&envelope).expect("verified prompt");
    assert_eq!(verified.subject, alice);

    let cap: Capability<CanReadSensitive, GenericResource> = mint_capability(
        &AllowAllForTest,
        verified.subject.as_str(),
        &verified.resource,
    )
    .expect("read cap");
    assert_eq!(
        verified.prompt.reveal(&cap).expect("matching resource"),
        "confidential prompt over real crypto"
    );
}

#[test]
fn ed25519_rejects_tampered_envelope() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let mut envelope = DidEnvelope::prompt(
        "msg-ed-2",
        alice,
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/ed"),
        "payload",
        &resolver,
        &keys,
    )
    .expect("envelope");
    envelope.body.resource = "prompt/session/other".to_owned();

    let gateway = DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent);
    assert!(matches!(
        gateway.open_prompt(&envelope),
        Err(DidError::InvalidSignature)
    ));
}

#[test]
fn ed25519_signature_is_not_forgeable_from_public_key() {
    // With the demo store, anyone holding the public key could mint a
    // valid signature. The Ed25519 store must not allow that.
    let (alice, _agent, resolver, _keys) = ed25519_fixture();
    let document = resolver.resolve(&alice).expect("document");
    let auth_method = &document.verification_method[0];

    // An attacker key store that does NOT hold alice's private key but
    // knows her public key cannot produce a signature that verifies.
    let attacker_key = Ed25519DidKey::from_seed(b"attacker");
    let attacker_store = Ed25519DidKeyStore::new().with_key(alice.clone(), attacker_key);
    let forged = attacker_store.sign(&alice, b"message").expect("sign");

    let honest_store = Ed25519DidKeyStore::new();
    assert!(matches!(
        honest_store.verify(auth_method, b"message", &forged),
        Err(DidError::InvalidSignature)
    ));
}

#[test]
fn ed25519_rotation_keeps_old_envelopes_until_retired() {
    let alice = Did::web("alice.example").expect("alice did");
    let agent = Did::web("agent.example").expect("agent did");
    let mut keys = Ed25519DidKeyStore::new()
        .with_key(alice.clone(), Ed25519DidKey::from_seed(b"alice-v1"))
        .with_key(agent.clone(), Ed25519DidKey::from_seed(b"agent-v1"));
    let resolver_v1 = StaticDidResolver::new()
        .with_document(keys.document(&alice).expect("alice v1 document"))
        .with_document(keys.document(&agent).expect("agent v1 document"));

    let old_envelope = DidEnvelope::prompt(
        "msg-rot-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/rot"),
        "old in-flight payload",
        &resolver_v1,
        &keys,
    )
    .expect("old envelope");
    assert_eq!(old_envelope.kid, format!("{alice}#key-1"));

    assert_eq!(
        keys.rotate_key(&alice, Ed25519DidKey::from_seed(b"alice-v2"))
            .expect("rotate alice"),
        2
    );
    assert_eq!(
        keys.rotate_key(&agent, Ed25519DidKey::from_seed(b"agent-v2"))
            .expect("rotate agent"),
        2
    );
    assert_eq!(keys.active_key_version(&alice).expect("active alice"), 2);

    let resolver_v2 = StaticDidResolver::new()
        .with_document(keys.document(&alice).expect("alice v2 document"))
        .with_document(keys.document(&agent).expect("agent v2 document"));
    let alice_doc = resolver_v2.resolve(&alice).expect("alice document");
    assert_eq!(
        alice_doc.authentication[0],
        format!("{alice}#key-signing-v2")
    );
    assert_eq!(
        alice_doc
            .verification_method
            .iter()
            .find(|method| method.id == old_envelope.kid)
            .and_then(|method| method.key_status.as_deref()),
        Some("previous")
    );

    let gateway =
        DidMessageGateway::new(Arc::new(resolver_v2.clone()), Arc::new(keys.clone()), agent);
    let verified = gateway
        .open_prompt(&old_envelope)
        .expect("old envelope remains valid while previous key is advertised");
    assert_eq!(
        verified.resource.resource_id(),
        "prompt/session/rot",
        "old payload opened after sender and recipient rotation"
    );

    let new_envelope = DidEnvelope::prompt(
        "msg-rot-2",
        alice.clone(),
        Did::web("agent.example").expect("agent did"),
        DidMessageBody::infer_prompt("prompt/session/rot-new"),
        "new payload",
        &resolver_v2,
        &keys,
    )
    .expect("new envelope");
    assert_eq!(new_envelope.kid, format!("{alice}#key-signing-v2"));
}

#[test]
fn ed25519_retired_key_rejects_old_signatures() {
    let alice = Did::web("alice-retired.example").expect("alice did");
    let agent = Did::web("agent-retired.example").expect("agent did");
    let mut keys = Ed25519DidKeyStore::new()
        .with_key(alice.clone(), Ed25519DidKey::from_seed(b"alice-retired-v1"))
        .with_key(agent.clone(), Ed25519DidKey::from_seed(b"agent-retired-v1"));
    let resolver_v1 = StaticDidResolver::new()
        .with_document(keys.document(&alice).expect("alice v1 document"))
        .with_document(keys.document(&agent).expect("agent v1 document"));
    let envelope = DidEnvelope::prompt(
        "msg-retired-1",
        alice.clone(),
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/session/retired"),
        "payload",
        &resolver_v1,
        &keys,
    )
    .expect("envelope");
    let old_method = resolver_v1
        .resolve(&alice)
        .expect("alice document")
        .authentication_key(&envelope.kid)
        .expect("old auth method")
        .clone();

    keys.rotate_key(&alice, Ed25519DidKey::from_seed(b"alice-retired-v2"))
        .expect("rotate alice");
    keys.retire_key(&alice, 1).expect("retire old alice key");

    assert!(matches!(
        keys.verify(&old_method, envelope.signing_input().as_bytes(), &envelope.signature),
        Err(DidError::RetiredKey(method)) if method == old_method.id
    ));
    let rotated_doc = keys.document(&alice).expect("rotated alice document");
    assert!(
        !rotated_doc
            .authentication
            .iter()
            .any(|kid| kid == &envelope.kid)
    );
}
