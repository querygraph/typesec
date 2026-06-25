//! JWT claim models and the verified-subject projection.

use serde::{Deserialize, Serialize};

/// Claims Typesec cares about from an access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject identifier.
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience. Some providers encode this as a string, others as a list.
    pub aud: Audience,
    /// Expiration timestamp.
    pub exp: usize,
    /// Optional organization identifier.
    #[serde(default)]
    pub org_id: Option<String>,
    /// Optional organization membership identifier.
    #[serde(default)]
    pub organization_membership_id: Option<String>,
    /// Optional role.
    #[serde(default)]
    pub role: Option<String>,
    /// Optional permission list.
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// JWT audience represented as either a string or list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// Single audience.
    Single(String),
    /// Multiple audiences.
    Multiple(Vec<String>),
}

impl Audience {
    pub(super) fn contains(&self, needle: &str) -> bool {
        match self {
            Self::Single(value) => value == needle,
            Self::Multiple(values) => values.iter().any(|value| value == needle),
        }
    }
}

/// Verified identity extracted from an OIDC/JWT access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSubject {
    /// Subject identifier.
    pub subject: String,
    /// Optional organization identifier.
    pub org_id: Option<String>,
    /// Optional organization membership identifier.
    pub organization_membership_id: Option<String>,
    /// Role names carried by the token.
    pub roles: Vec<String>,
    /// Permission names carried by the token.
    pub permissions: Vec<String>,
}

impl VerifiedSubject {
    /// Return the best subject identifier for WorkOS FGA checks.
    pub fn workos_membership_subject(&self) -> &str {
        self.organization_membership_id
            .as_deref()
            .unwrap_or(&self.subject)
    }
}

impl From<JwtClaims> for VerifiedSubject {
    fn from(claims: JwtClaims) -> Self {
        Self {
            subject: claims.sub,
            org_id: claims.org_id,
            organization_membership_id: claims.organization_membership_id,
            roles: claims.role.into_iter().collect(),
            permissions: claims.permissions,
        }
    }
}
