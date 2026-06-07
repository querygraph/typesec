//! `typesec validate` — parse and validate a policy YAML file.

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct ValidateArgs {
    /// Path to the policy YAML file.
    #[arg(long)]
    pub policy: PathBuf,

    /// Policy format: `rbac` or `odrl` (auto-detected from content if omitted).
    #[arg(long)]
    pub format: Option<String>,
}

pub fn run(args: ValidateArgs) -> Result<()> {
    let yaml = std::fs::read_to_string(&args.policy)?;
    let format = detect_format(&args.format, &yaml);

    match format.as_deref() {
        Some("rbac") => {
            let policy = typesec_rbac::RbacPolicy::from_yaml(&yaml)?;
            policy.validate().map_err(|e| anyhow::anyhow!(e))?;
            let role_count = policy.roles.len();
            let assignment_count = policy.assignments.len();
            println!("✓ RBAC policy is valid");
            println!("  Roles: {role_count}");
            println!("  Assignments: {assignment_count}");
            for role in &policy.roles {
                println!(
                    "  • {} — permissions: [{}], resources: [{}]",
                    role.name,
                    role.permissions.join(", "),
                    role.resources.join(", "),
                );
            }
        }
        Some("odrl") => {
            let doc = typesec_odrl::model::OdrlDocument::from_yaml(&yaml)?;
            let policy_count = doc.policies.len();
            println!("✓ ODRL document is valid");
            println!("  Policies: {policy_count}");
            for p in &doc.policies {
                println!(
                    "  • {} ({}) — {} rules",
                    p.uid,
                    p.policy_type,
                    p.rules.len()
                );
            }
        }
        _ => {
            anyhow::bail!("Could not detect policy format. Use --format rbac or --format odrl");
        }
    }

    Ok(())
}

fn detect_format(explicit: &Option<String>, yaml: &str) -> Option<String> {
    if let Some(f) = explicit {
        return Some(f.clone());
    }
    if yaml.contains("roles:") && yaml.contains("assignments:") {
        Some("rbac".into())
    } else if yaml.contains("policies:") && yaml.contains("rules:") {
        Some("odrl".into())
    } else {
        None
    }
}
