//! `typesec generate` — emit typed Rust code from an RBAC policy.

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct GenerateArgs {
    /// Path to the RBAC policy YAML file.
    #[arg(long)]
    pub policy: PathBuf,

    /// Output file path for the generated Rust source.
    #[arg(long)]
    pub out: PathBuf,
}

pub fn run(args: GenerateArgs) -> Result<()> {
    let yaml = std::fs::read_to_string(&args.policy)?;
    let policy = typesec_rbac::RbacPolicy::from_yaml(&yaml)?;
    policy.validate().map_err(|e| anyhow::anyhow!(e))?;

    let code = typesec_rbac::codegen::generate_rust(&policy);

    std::fs::write(&args.out, &code)?;
    println!(
        "✓ Generated {} role structs → {}",
        policy.roles.len(),
        args.out.display()
    );

    Ok(())
}
