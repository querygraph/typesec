//! # Core capability example
//!
//! The load-bearing idea of Typesec with nothing but `typesec-core`: a custom
//! [`PolicyEngine`], the single gated mint path, and a function that *demands* a
//! capability. No agent, no YAML, no integrations — just the foundational loop.
//!
//! Run with:
//! ```sh
//! cargo run --example core_capability
//! ```
//!
//! ## What this shows
//!
//! 1. **The policy contract** — one `check` returning `Allow | Deny | Delegate`.
//! 2. **The only mint path** — `mint_capability` runs the engine and, *only* on
//!    `Allow`, returns an unforgeable [`Capability`]. There is no public
//!    constructor; a denial yields an error, not a capability.
//! 3. **Authority as a value** — `write_report` takes a `Capability` argument, so
//!    holding one in scope *is* the proof. It cannot be called otherwise.
//! 4. **The audit trail for free** — every decision flows through the installed
//!    [`AuditSink`], allow or deny.

use std::sync::Arc;

use typesec_core::{
    Capability, GenericResource, ResourceId, SubjectId,
    permissions::CanWrite,
    policy::{AuditEvent, AuditSink, PolicyEngine, PolicyResult, mint_capability, set_audit_sink},
};

/// A privileged action that can only be called with proof of write authority.
///
/// There is no permission check inside — the `Capability<CanWrite, _>` in the
/// signature *is* the proof. The compiler guarantees no caller reaches this
/// function without one, and the only way to obtain one is [`mint_capability`].
fn write_report(cap: &Capability<CanWrite, GenericResource>, contents: &str) {
    println!("    wrote to '{}': {contents}", cap.resource_id());
}

/// A tiny hand-written policy: `agent:writer` may `write` under `reports/`.
struct ReportPolicy;

impl PolicyEngine for ReportPolicy {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        if subject.as_str() == "agent:writer"
            && action == "write"
            && resource.as_str().starts_with("reports/")
        {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny(format!("{subject} may not {action} '{resource}'"))
        }
    }
}

/// An audit sink that prints every decision, showing the trail the mint path
/// emits automatically. Production sinks write to a log, queue, or database.
struct PrintingAuditSink;

impl AuditSink for PrintingAuditSink {
    fn record(&self, event: &AuditEvent) {
        println!(
            "    [audit] subject={} action={} resource={} -> {}",
            event.subject, event.action, event.resource, event.result
        );
    }
}

fn main() {
    set_audit_sink(Arc::new(PrintingAuditSink));
    let engine = ReportPolicy;

    println!("=== typesec core capability demo ===\n");

    // ✓ Allowed: the engine approves, a capability is minted, the action runs.
    println!("agent:writer requests CanWrite on reports/q1");
    let report = GenericResource::new("reports/q1", "report");
    match mint_capability::<CanWrite, GenericResource>(&engine, "agent:writer", &report) {
        Ok(cap) => {
            println!("  ✓ minted: {cap}");
            write_report(&cap, "revenue up 12%");
        }
        Err(e) => println!("  ✗ unexpected denial: {e}"),
    }

    println!();

    // ✗ Denied: no capability is produced, so `write_report` is simply
    // unreachable for this resource. The denial is a typed error, not a panic.
    println!("agent:writer requests CanWrite on secrets/keys");
    let secrets = GenericResource::new("secrets/keys", "secret");
    match mint_capability::<CanWrite, GenericResource>(&engine, "agent:writer", &secrets) {
        Ok(cap) => write_report(&cap, "this should never happen"),
        Err(e) => println!("  ✓ denied (expected): {e}"),
    }

    println!("\n=== demo complete ===");

    // ── Compile-time safety note ──────────────────────────────────────────────
    //
    // `write_report` cannot be called without a `Capability<CanWrite, _>`, and a
    // `Capability` has no public constructor — `mint_capability` above is the
    // only way to obtain one. Uncommenting this will not compile:
    //
    // write_report(/* ??? no capability exists to pass */, "forbidden");
}
