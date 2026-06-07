//! `typesec check` — evaluate a single policy query.

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
use typesec_core::policy::{PolicyEngine, PolicyResult};

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

    /// Policy format: `rbac` or `odrl`.
    #[arg(long)]
    pub format: Option<String>,

    /// Purpose context for ODRL constraint evaluation.
    #[arg(long)]
    pub purpose: Option<String>,
}

pub fn run(args: CheckArgs) -> Result<()> {
    let yaml = std::fs::read_to_string(&args.policy)?;
    let format = detect_format(&args.format, &yaml);

    let result = match format.as_deref() {
        Some("rbac") => {
            let engine =
                typesec_rbac::RbacEngine::from_yaml(&yaml).map_err(|e| anyhow::anyhow!(e))?;
            engine.check(&args.subject, &args.action, &args.resource)
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
            engine.check(&args.subject, &args.action, &args.resource)
        }
        _ => anyhow::bail!("Could not detect policy format. Use --format rbac or --format odrl"),
    };

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
            std::process::exit(1);
        }
        PolicyResult::Delegate(to) => {
            println!("→ DELEGATE to: {to}");
            println!("  (no definitive answer from this engine)");
            std::process::exit(2);
        }
    }

    Ok(())
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
