use super::*;
use crate::policy::PolicyResult;
use crate::{ResourceId, SubjectId};

struct AllowAll;
impl PolicyEngine for AllowAll {
    fn check(&self, _: &SubjectId, _: &str, _: &ResourceId) -> PolicyResult {
        PolicyResult::Allow
    }
}

#[test]
fn authenticate_unverified_transitions_state() {
    let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
    let creds = Credentials::new("agent:test", "secret-token");
    let auth = agent
        .authenticate_unverified(creds)
        .expect("should succeed");
    assert_eq!(auth.subject(), "agent:test");
}

#[test]
fn credentials_debug_redacts_token() {
    let creds = Credentials::new("agent:test", "super-secret-bearer");
    let rendered = format!("{creds:?}");
    assert!(!rendered.contains("super-secret-bearer"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn credentials_can_be_zeroized() {
    let mut creds = Credentials::new("agent:test", "super-secret-bearer");

    creds.zeroize();

    assert!(creds.subject.is_empty());
    assert!(creds.token.is_empty());
}

#[test]
fn empty_subject_fails_auth() {
    let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
    let creds = Credentials::new("", "token");
    assert!(matches!(
        agent.authenticate_unverified(creds),
        Err(AgentError::AuthFailed { .. })
    ));
}

struct FixedSubject(&'static str);
impl Authenticator for FixedSubject {
    fn verify_credentials(&self, credentials: &Credentials) -> Result<String, AgentError> {
        if credentials.token.expose() == "valid-token" {
            Ok(self.0.to_owned())
        } else {
            Err(AgentError::AuthFailed {
                reason: "bad token".into(),
            })
        }
    }
}

#[test]
fn authenticate_with_uses_verified_subject_not_claimed() {
    let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
    // The caller claims to be admin, but the authenticator says otherwise.
    let creds = Credentials::new("agent:claimed-admin", "valid-token");
    let auth = agent
        .authenticate_with(creds, &FixedSubject("agent:verified"))
        .expect("should succeed");
    assert_eq!(auth.subject(), "agent:verified");
}

#[test]
fn authenticate_with_rejects_bad_token() {
    let agent = Agent::<Unauthenticated>::new(Arc::new(AllowAll));
    let creds = Credentials::new("agent:any", "wrong-token");
    assert!(matches!(
        agent.authenticate_with(creds, &FixedSubject("agent:verified")),
        Err(AgentError::AuthFailed { .. })
    ));
}
