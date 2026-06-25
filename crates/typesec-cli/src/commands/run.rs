//! `typesec run` — simulate agent execution under a policy.

use anyhow::Result;
use clap::Args;
use serde::Deserialize;
use std::path::PathBuf;
use typesec_agent::SecureAgent;
use typesec_core::{Credentials, RequestContext, ResourceId, SubjectId, policy::PolicyResult};

use super::engine::{detect_format, exit_for_result, load_engine, request_context};

#[derive(Args)]
pub struct RunArgs {
    /// Path to a multi-agent scenario YAML file.
    #[arg(long)]
    pub scenario: Option<PathBuf>,

    /// Path to the policy YAML file.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// The agent identity (e.g., `agent:summarizer`).
    #[arg(long)]
    pub agent: Option<String>,

    /// The task to simulate: `summarize`, `write`, `infer`, `exfiltrate`.
    #[arg(long)]
    pub task: Option<String>,

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

#[derive(Debug, Deserialize)]
struct ScenarioDocument {
    scenario: Scenario,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: Option<String>,
    policy: PathBuf,
    format: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
    steps: Vec<ScenarioStep>,
}

#[derive(Debug, Deserialize)]
struct ScenarioStep {
    agent: String,
    action: String,
    resource: String,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    expect: Option<String>,
}

pub async fn run(args: RunArgs) -> Result<()> {
    if let Some(scenario) = &args.scenario {
        return run_scenario(scenario).await;
    }

    let policy = args
        .policy
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--policy is required unless --scenario is used"))?;
    let agent_id = args
        .agent
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--agent is required unless --scenario is used"))?;
    let task = args
        .task
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--task is required unless --scenario is used"))?;

    let yaml = std::fs::read_to_string(policy)?;
    let context = request_context(args.purpose.as_deref());
    let format = detect_format(&args.format, &yaml);
    let engine = load_engine(format.as_deref(), &yaml)?;

    // Create and authenticate the agent.
    let agent = SecureAgent::new(engine);
    let credentials = Credentials::new(agent_id.clone(), "cli-token");
    let agent = agent
        .authenticate_unverified(credentials)
        .map_err(|e| anyhow::anyhow!("auth failed: {e}"))?;

    println!("Agent '{}' authenticated ✓", agent.subject());
    println!("Running task: {task}");
    println!();

    // Simulate tasks — each requires a different capability.
    // The resource identifier for the simulation — use the agent name as a proxy.
    let resource_id = args
        .input
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| format!("simulation:{agent_id}"));

    // Map the CLI task name to its policy action and success message.
    let (action, success_message) = match task.as_str() {
        "summarize" | "read" => ("read", "Task: summarize/read completed"),
        "write" => ("write", "Task: write completed"),
        "infer" => ("ai:infer", "Task: AI inference completed"),
        "exfiltrate" => ("ai:exfiltrate", "Task: exfiltrate (DANGEROUS!)"),
        other => {
            anyhow::bail!("Unknown task: '{other}'. Try: summarize, write, infer, exfiltrate");
        }
    };

    let result = simulate_task(&agent, action, &resource_id, &context, success_message).await;

    // Reflect the decision in the exit code (0 allow / 1 deny / 2 delegate),
    // like `typesec check`, so `run` is safe to gate CI on.
    exit_for_result(&result);
}

async fn run_scenario(path: &PathBuf) -> Result<()> {
    let yaml = std::fs::read_to_string(path)?;
    let doc: ScenarioDocument = serde_yaml::from_str(&yaml)?;
    let policy_path = if doc.scenario.policy.is_relative() {
        path.parent()
            .map(|parent| parent.join(&doc.scenario.policy))
            .unwrap_or_else(|| doc.scenario.policy.clone())
    } else {
        doc.scenario.policy.clone()
    };
    let policy_yaml = std::fs::read_to_string(&policy_path)?;
    let format = detect_format(&doc.scenario.format, &policy_yaml);
    let engine = load_engine(format.as_deref(), &policy_yaml)?;

    println!(
        "Scenario: {}",
        doc.scenario.name.as_deref().unwrap_or("unnamed")
    );
    println!("Policy: {}", policy_path.display());
    println!("Steps: {}", doc.scenario.steps.len());
    println!();

    let mut mismatches = 0usize;
    for (idx, step) in doc.scenario.steps.iter().enumerate() {
        let context = request_context(step.purpose.as_deref().or(doc.scenario.purpose.as_deref()));
        let agent = SecureAgent::new(engine.clone())
            .authenticate_unverified(Credentials::new(step.agent.clone(), "scenario-token"))
            .map_err(|e| anyhow::anyhow!("scenario step {} auth failed: {e}", idx + 1))?;

        println!(
            "[{}] agent='{}' action='{}' resource='{}'",
            idx + 1,
            agent.subject(),
            step.action,
            step.resource
        );
        let result = simulate_task(
            &agent,
            &step.action,
            &step.resource,
            &context,
            "Step completed",
        )
        .await;

        if let Some(expected) = &step.expect {
            let expected = expected.to_ascii_lowercase();
            let actual = result_label(&result);
            if actual == expected {
                println!("  ✓ EXPECTED {expected}");
            } else {
                println!("  ✗ EXPECTED {expected}, got {actual}");
                mismatches += 1;
            }
        }
        println!();
    }

    if mismatches > 0 {
        anyhow::bail!("{mismatches} scenario expectation(s) failed");
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
    context: &RequestContext,
    success_message: &str,
) -> PolicyResult {
    println!("Requesting: action='{action}' on '{resource_id}'");

    let engine = agent.engine();
    let subject = SubjectId::from(agent.subject());
    let resource = ResourceId::from(resource_id);
    let result = engine.check_with_context(&subject, action, &resource, context);

    match &result {
        PolicyResult::Allow => {
            println!("  ✓ ALLOWED — capability granted");
            println!("  → {success_message}");
        }
        PolicyResult::Deny(reason) => {
            println!("  ✗ DENIED — {reason}");
        }
        PolicyResult::Delegate(reason) => {
            println!(
                "  → DELEGATED to {}: {} (no definitive answer)",
                reason.engine, reason.reason
            );
        }
        _ => {
            println!("  ✗ UNKNOWN POLICY RESULT — treating as denied");
        }
    }
    result
}

fn result_label(result: &PolicyResult) -> &'static str {
    match result {
        PolicyResult::Allow => "allow",
        PolicyResult::Deny(_) => "deny",
        PolicyResult::Delegate(_) => "delegate",
        _ => "unknown",
    }
}
