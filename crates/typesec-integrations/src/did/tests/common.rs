use typesec_core::{PolicyEngine, ResourceId, SubjectId, policy::PolicyResult};

use super::super::*;

pub(crate) struct PromptPolicy;

impl PolicyEngine for PromptPolicy {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
        if subject == "did:key:z616c696365"
            && matches!(action, "ai:infer" | "read_sensitive")
            && resource == "prompt/session/123"
        {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny("not allowed".to_owned())
        }
    }
}

pub(crate) fn fixture() -> (Did, Did, StaticDidResolver, DemoDidKeyStore) {
    let alice = Did::key(b"alice");
    let agent = Did::key(b"agent");
    let alice_key = DemoDidKeyPair::from_seed(b"alice");
    let agent_key = DemoDidKeyPair::from_seed(b"agent");
    let resolver = StaticDidResolver::new()
        .with_document(DidDocument::single_key(
            alice.clone(),
            alice_key.public_key.clone(),
        ))
        .with_document(DidDocument::single_key(
            agent.clone(),
            agent_key.public_key.clone(),
        ));
    let keys = DemoDidKeyStore::new()
        .with_key(alice.clone(), alice_key)
        .with_key(agent.clone(), agent_key);
    (alice, agent, resolver, keys)
}

pub(crate) struct AgentPolicy {
    pub(crate) allowed_subject: String,
}

impl PolicyEngine for AgentPolicy {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
        if subject == self.allowed_subject
            && matches!(
                action,
                "agent:message" | "agent:delegate" | "read_sensitive"
            )
            && resource == "room/acme-support"
        {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny("agent message denied".to_owned())
        }
    }
}

pub(crate) fn ed25519_fixture() -> (Did, Did, StaticDidResolver, Ed25519DidKeyStore) {
    let alice_key = Ed25519DidKey::from_seed(b"alice-ed25519");
    let agent_key = Ed25519DidKey::from_seed(b"agent-ed25519");
    let alice = Did::key(alice_key.signing_public());
    let agent = Did::key(agent_key.signing_public());
    let resolver = StaticDidResolver::new()
        .with_document(alice_key.document(alice.clone()))
        .with_document(agent_key.document(agent.clone()));
    let keys = Ed25519DidKeyStore::new()
        .with_key(alice.clone(), alice_key)
        .with_key(agent.clone(), agent_key);
    (alice, agent, resolver, keys)
}

pub(crate) struct AllowAllForTest;
impl PolicyEngine for AllowAllForTest {
    fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
        PolicyResult::Allow
    }
}
