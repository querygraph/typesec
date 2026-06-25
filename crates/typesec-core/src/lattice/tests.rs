use super::*;
use crate::{
    permissions::{CanRead, CanReadInternal, CanReadSensitive, CanWrite, CanWriteSensitive},
    policy::PolicyResult,
    resource::GenericResource,
};
use proptest::prelude::*;
use std::sync::Arc;

// ── Helpers ────────────────────────────────────────────────────────────────

/// An engine that grants a fixed (subject, action, resource) triple.
struct GrantOnly {
    subject: &'static str,
    action: &'static str,
    resource: &'static str,
}
impl PolicyEngine for GrantOnly {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        if subject == self.subject && action == self.action && resource == self.resource {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny(format!(
                "GrantOnly: no match for {subject}/{action}/{resource}"
            ))
        }
    }
}

// ── coerce() tests ─────────────────────────────────────────────────────────

#[test]
fn coerce_write_to_read() {
    let write_cap: Capability<CanWrite, GenericResource> =
        Capability::new_unchecked("agent:test", "data/file");
    let read_cap: Capability<CanRead, GenericResource> = write_cap.coerce();
    assert_eq!(read_cap.subject(), "agent:test");
    assert_eq!(read_cap.resource_id(), "data/file");
    assert_eq!(
        Capability::<CanRead, GenericResource>::permission_name(),
        "read"
    );
}

#[test]
fn coerce_write_sensitive_to_write() {
    let ws_cap: Capability<CanWriteSensitive, GenericResource> =
        Capability::new_unchecked("agent:admin", "sensitive/data");
    let w_cap: Capability<CanWrite, GenericResource> = ws_cap.coerce();
    assert_eq!(
        Capability::<CanWrite, GenericResource>::permission_name(),
        "write"
    );
    assert_eq!(w_cap.subject(), "agent:admin");
}

#[test]
fn coerce_write_sensitive_to_read() {
    // CanWriteSensitive → CanRead is a direct impl
    let ws_cap: Capability<CanWriteSensitive, GenericResource> =
        Capability::new_unchecked("agent:admin", "sensitive/data");
    let r_cap: Capability<CanRead, GenericResource> = ws_cap.coerce();
    assert_eq!(
        Capability::<CanRead, GenericResource>::permission_name(),
        "read"
    );
    assert_eq!(r_cap.subject(), "agent:admin");
}

#[test]
fn coerce_read_sensitive_to_read_internal() {
    let sensitive_cap: Capability<CanReadSensitive, GenericResource> =
        Capability::new_unchecked("agent:analyst", "internal/memo");
    let internal_cap: Capability<CanReadInternal, GenericResource> = sensitive_cap.coerce();
    assert_eq!(
        Capability::<CanReadInternal, GenericResource>::permission_name(),
        "read_internal"
    );
    assert_eq!(internal_cap.resource_id(), "internal/memo");
}

// ── LatticeEngine tests ────────────────────────────────────────────────────

#[test]
fn lattice_promotes_write_to_read() {
    // Engine grants "write" but not "read" directly.
    let inner: Arc<dyn PolicyEngine> = Arc::new(GrantOnly {
        subject: "agent:test",
        action: "write",
        resource: "reports/q1",
    });
    let engine = LatticeEngine::new(inner);

    // Direct read → denied by inner
    // Lattice: implied_by("read") includes "write" → inner.check("write") → Allow → promote
    let result = engine.check(
        &SubjectId::from("agent:test"),
        "read",
        &ResourceId::from("reports/q1"),
    );
    assert_eq!(
        result,
        PolicyResult::Allow,
        "lattice should promote write→read"
    );
}

#[test]
fn lattice_does_not_promote_upward() {
    // Engine only grants "read" — does NOT have write.
    let inner: Arc<dyn PolicyEngine> = Arc::new(GrantOnly {
        subject: "agent:test",
        action: "read",
        resource: "reports/q1",
    });
    let engine = LatticeEngine::new(inner);

    // Request "write" — no permission in the lattice implies write from read.
    let result = engine.check(
        &SubjectId::from("agent:test"),
        "write",
        &ResourceId::from("reports/q1"),
    );
    assert!(
        matches!(result, PolicyResult::Deny(_)),
        "should not be able to promote read→write"
    );
}

#[test]
fn lattice_passes_through_allow() {
    let inner: Arc<dyn PolicyEngine> = Arc::new(GrantOnly {
        subject: "agent:test",
        action: "read",
        resource: "data",
    });
    let engine = LatticeEngine::new(inner);
    let result = engine.check(
        &SubjectId::from("agent:test"),
        "read",
        &ResourceId::from("data"),
    );
    assert_eq!(result, PolicyResult::Allow);
}

#[test]
fn implication_table_matches_implied_by_lookup() {
    for (higher, lower) in implication_pairs() {
        assert!(
            implied_by(lower).any(|candidate| candidate == higher),
            "{higher} should appear in implied_by({lower})"
        );
    }
}

#[test]
fn implication_table_has_no_cycles() {
    let pairs: Vec<_> = implication_pairs().collect();
    for (higher, lower) in &pairs {
        assert_ne!(higher, lower, "permission cannot imply itself explicitly");
        assert!(
            !pairs.iter().any(
                |(candidate_higher, candidate_lower)| candidate_higher == lower
                    && candidate_lower == higher
            ),
            "cycle found between {higher} and {lower}"
        );
    }
}

#[test]
fn implication_table_contains_transitive_closure() {
    let pairs: Vec<_> = implication_pairs().collect();
    for (a, b) in &pairs {
        for (candidate_b, c) in &pairs {
            if b == candidate_b {
                assert!(
                    pairs
                        .iter()
                        .any(|(candidate_a, candidate_c)| candidate_a == a && candidate_c == c),
                    "missing transitive implication {a} => {c} via {b}"
                );
            }
        }
    }
}

proptest! {
    #[test]
    fn prop_explicit_implications_are_discoverable(index in 0usize..IMPLICATIONS.len()) {
        let pairs: Vec<_> = implication_pairs().collect();
        let (higher, lower) = pairs[index];

        prop_assert!(
            implied_by(lower).any(|candidate| candidate == higher),
            "{higher} should appear in implied_by({lower})"
        );
    }

    #[test]
    fn prop_implication_table_has_no_self_edges_or_cycles(index in 0usize..IMPLICATIONS.len()) {
        let pairs: Vec<_> = implication_pairs().collect();
        let (higher, lower) = pairs[index];

        // Same-permission use needs no coercion, so the explicit table stores
        // only strict privilege demotions.
        prop_assert_ne!(higher, lower, "permission cannot imply itself explicitly");
        prop_assert!(
            !pairs
                .iter()
                .any(|(candidate_higher, candidate_lower)| {
                    *candidate_higher == lower && *candidate_lower == higher
                }),
            "cycle found between {higher} and {lower}"
        );
    }

    #[test]
    fn prop_implication_table_contains_transitive_closure(
        left in 0usize..IMPLICATIONS.len(),
        right in 0usize..IMPLICATIONS.len(),
    ) {
        let pairs: Vec<_> = implication_pairs().collect();
        let (a, b) = pairs[left];
        let (candidate_b, c) = pairs[right];

        if b == candidate_b {
            prop_assert!(
                pairs
                    .iter()
                    .any(|(candidate_a, candidate_c)| *candidate_a == a && *candidate_c == c),
                "missing transitive implication {a} => {c} via {b}"
            );
        }
    }
}
