//! `typesec run` — simulate agent execution under a policy.

use anyhow::Result;
use clap::Args;
use std::{path::PathBuf, sync::Arc};
use typesec_agent::SecureAgent;
use typesec_core::Credentials;

#[derive(Args)]
pub struct RunArgs {
    /// Path to the policy YAML file.
    #[arg(long)]
    pub policy: PathBuf,

    /// The agent identity (e.g., `agent:summarizer`).
    #[arg(long)]
    pub agent: String,

    /// The task to simulate: `summarize`, `write`, `infer`, `exfiltrate`.
    #[arg(long)]
    pub task: String,

    /// Path to the input data file (JSON).
    #[arg(long)]
    pub input: Option<PathBuf>,

    /// Purpose context for ODRL constraint evaluation.
    #[arg(long)]
    pub purpose: Option<String>,

    /// Format: `rbac` or `odrl` (auto-detected).
    #[arg(long)]
    pub format: Option<String>,
}

pub async fn run(args: RunArgs) -> Result<()> {
    let yaml = std::fs::read_to_string(&args.policy)?;
    let format = detect_format(&args.format, &yaml);

    let engine: Arc<dyn typesec_core::policy::PolicyEngine> = match format.as_deref() {
        Some("rbac") => {
            let e = typesec_rbac::RbacEngine::from_yaml(&yaml).map_err(|e| anyhow::anyhow!(e))?;
            Arc::new(e)
        }
        Some("odrl") => {
            let base =
                typesec_odrl::OdrlEngine::from_yaml(&yaml).map_err(|e| anyhow::anyhow!(e))?;
            let engine = if let Some(purpose) = &args.purpose {
                let ctx = typesec_odrl::constraint::ConstraintContext::default()
                    .with_purpose(purpose.clone());
                base.with_context(ctx)
            } else {
                base
            };
            Arc::new(engine)
        }
        _ => anyhow::bail!("Could not detect policy format"),
    };

    // Create and authenticate the agent.
    let agent = SecureAgent::new(engine);
    let credentials = Credentials::new(args.agent.clone(), "cli-token");
    let agent = agent
        .authenticate(credentials)
        .map_err(|e| anyhow::anyhow!("auth failed: {e}"))?;

    println!("Agent '{}' authenticated ✓", agent.subject());
    println!("Running task: {}", args.task);
    println!();

    // Simulate tasks — each requires a different capability.
    // The resource identifier for the simulation — use the agent name as a proxy.
    let resource_id = args
        .input
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| format!("simulation:{}", args.agent));

    match args.task.as_str() {
        "summarize" | "read" => {
            simulate_task(
                &agent,
                "read",
                &resource_id,
                "Task: summarize/read completed",
            )
            .await;
        }
        "write" => {
            simulate_task(&agent, "write", &resource_id, "Task: write completed").await;
        }
        "infer" => {
            simulate_task(
                &agent,
                "ai:infer",
                &resource_id,
                "Task: AI inference completed",
            )
            .await;
        }
        "exfiltrate" => {
            simulate_task(
                &agent,
                "ai:exfiltrate",
                &resource_id,
                "Task: exfiltrate (DANGEROUS!)",
            )
            .await;
        }
        other => {
            anyhow::bail!("Unknown task: '{other}'. Try: summarize, write, infer, exfiltrate");
        }
    }

    Ok(())
}

/// Simulate a task by requesting a capability and printing the result.
///
/// Uses the policy engine's `check()` directly because we're mapping runtime
/// action strings to policy decisions — we can't select compile-time type
/// parameters (`CanRead`, `CanWrite`, etc.) from a CLI string.
/// In real application code you'd use `agent.request_capability::<CanRead, _>(&res)`.
async fn simulate_task(
    agent: &SecureAgent<typesec_core::typestate::Authenticated>,
    action: &str,
    resource_id: &str,
    success_message: &str,
) {
    use typesec_core::policy::PolicyResult;

    println!("Requesting: action='{action}' on '{resource_id}'");

    let engine = agent.engine();
    let result = engine.check(agent.subject(), action, resource_id);

    match result {
        PolicyResult::Allow => {
            println!("  ✓ ALLOWED — capability granted");
            println!("  → {success_message}");
        }
        PolicyResult::Deny(reason) => {
            println!("  ✗ DENIED — {reason}");
        }
        PolicyResult::Delegate(to) => {
            println!("  → DELEGATED to {to} (no definitive answer)");
        }
    }
}

fn detect_format(explicit: &Option<String>, yaml: &str) -> Option<String> {
    if let Some(f) = explicit {
        return Some(f.clone());
    }
    if yaml.contains("roles:") {
        Some("rbac".into())
    } else if yaml.contains("policies:") {
        Some("odrl".into())
    } else {
        None
    }
}
