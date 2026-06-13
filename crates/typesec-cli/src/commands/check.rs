//! `typesec check` — evaluate a single policy query.

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use std::path::PathBuf;
use typesec_core::policy::{PolicyEngine, PolicyResult, RequestContext};

#[derive(Args)]
pub struct CheckArgs {
    /// Path to the policy YAML file.
    #[arg(long)]
    pub policy: PathBuf,

    /// The subject (e.g., `agent:data-pipeline`).
    #[arg(long)]
    pub subject: String,

    /// The action / permission name (e.g., `write`, `read_sensitive`).
    #[arg(long)]
    pub action: String,

    /// The resource identifier (e.g., `reports/q1`).
    #[arg(long)]
    pub resource: String,

    /// Policy format: `rbac`, `odrl`, or `graph`.
    #[arg(long)]
    pub format: Option<String>,

    /// Purpose context for ODRL constraint evaluation.
    #[arg(long)]
    pub purpose: Option<String>,

    /// Print a machine-readable JSON decision.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: CheckArgs) -> Result<()> {
    let yaml = std::fs::read_to_string(&args.policy)?;
    let format = detect_format(&args.format, &yaml);
    let context = args
        .purpose
        .as_ref()
        .map_or_else(RequestContext::default, |purpose| {
            RequestContext::default().with_purpose(purpose.clone())
        });

    let result = match format.as_deref() {
        Some("rbac") => {
            let engine =
                typesec_rbac::RbacEngine::from_yaml(&yaml).map_err(|e| anyhow::anyhow!(e))?;
            PolicyEngine::check_with_context(
                &engine,
                &args.subject,
                &args.action,
                &args.resource,
                &context,
            )
        }
        Some("odrl") => {
            let engine =
                typesec_odrl::OdrlEngine::from_yaml(&yaml).map_err(|e| anyhow::anyhow!(e))?;
            PolicyEngine::check_with_context(
                &engine,
                &args.subject,
                &args.action,
                &args.resource,
                &context,
            )
        }
        Some("graph") => {
            let engine = typesec_rbac::GraphPolicyEngine::from_yaml(&yaml)
                .map_err(|e| anyhow::anyhow!(e))?;
            engine.check_with_context(&args.subject, &args.action, &args.resource, &context)
        }
        _ => anyhow::bail!(
            "Could not detect policy format. Use --format rbac, --format odrl, or --format graph"
        ),
    };

    if args.json {
        print_json_result(&args, format.as_deref(), &result)?;
    } else {
        print_human_result(&args, &result);
    }

    exit_for_result(&result);
}

fn print_human_result(args: &CheckArgs, result: &PolicyResult) {
    match &result {
        PolicyResult::Allow => {
            println!("✓ ALLOW");
            println!("  Subject:  {}", args.subject);
            println!("  Action:   {}", args.action);
            println!("  Resource: {}", args.resource);
        }
        PolicyResult::Deny(reason) => {
            println!("✗ DENY");
            println!("  Subject:  {}", args.subject);
            println!("  Action:   {}", args.action);
            println!("  Resource: {}", args.resource);
            println!("  Reason:   {reason}");
        }
        PolicyResult::Delegate(to) => {
            println!("→ DELEGATE to: {to}");
            println!("  (no definitive answer from this engine)");
        }
    }
}

fn print_json_result(args: &CheckArgs, format: Option<&str>, result: &PolicyResult) -> Result<()> {
    let response = CheckJsonResponse::new(args, format, result);
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn exit_for_result(result: &PolicyResult) -> ! {
    match result {
        PolicyResult::Allow => std::process::exit(0),
        PolicyResult::Deny(_) => std::process::exit(1),
        PolicyResult::Delegate(_) => std::process::exit(2),
    }
}

#[derive(Serialize)]
struct CheckJsonResponse<'a> {
    decision: &'static str,
    allowed: bool,
    subject: &'a str,
    action: &'a str,
    resource: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegate_to: Option<&'a str>,
}

impl<'a> CheckJsonResponse<'a> {
    fn new(args: &'a CheckArgs, format: Option<&'a str>, result: &'a PolicyResult) -> Self {
        let (decision, allowed, reason, delegate_to) = match result {
            PolicyResult::Allow => ("allow", true, None, None),
            PolicyResult::Deny(reason) => ("deny", false, Some(reason.as_str()), None),
            PolicyResult::Delegate(to) => ("delegate", false, None, Some(to.as_str())),
        };

        Self {
            decision,
            allowed,
            subject: &args.subject,
            action: &args.action,
            resource: &args.resource,
            format,
            purpose: args.purpose.as_deref(),
            reason,
            delegate_to,
        }
    }
}

fn detect_format(explicit: &Option<String>, yaml: &str) -> Option<String> {
    if let Some(f) = explicit {
        return Some(f.clone());
    }
    if yaml.contains("graph_policy:") || yaml.contains("\"graph_policy\"") {
        Some("graph".into())
    } else if yaml.contains("roles:") {
        Some("rbac".into())
    } else if yaml.contains("policies:") {
        Some("odrl".into())
    } else {
        None
    }
}
