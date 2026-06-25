//! `typesec check` — evaluate a single policy query.

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use std::path::PathBuf;
use typesec_core::{
    ResourceId, SubjectId,
    policy::PolicyResult,
};

use super::engine::{detect_format, exit_for_result, load_engine, request_context};

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
    let context = request_context(args.purpose.as_deref());
    let subject = SubjectId::from(args.subject.as_str());
    let resource = ResourceId::from(args.resource.as_str());

    let engine = load_engine(format.as_deref(), &yaml)?;
    let result = engine.check_with_context(&subject, &args.action, &resource, &context);

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
        PolicyResult::Delegate(reason) => {
            println!("→ DELEGATE to: {}", reason.engine);
            println!("  Reason:   {}", reason.reason);
            if let Some(context) = &reason.context {
                println!("  Context:  {context}");
            }
            println!("  (no definitive answer from this engine)");
        }
        _ => {
            println!("✗ UNKNOWN POLICY RESULT");
            println!("  Treating as denied");
        }
    }
}

fn print_json_result(args: &CheckArgs, format: Option<&str>, result: &PolicyResult) -> Result<()> {
    let response = CheckJsonResponse::new(args, format, result);
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
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
    #[serde(skip_serializing_if = "Option::is_none")]
    delegate_engine: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegate_context: Option<&'a str>,
}

impl<'a> CheckJsonResponse<'a> {
    fn new(args: &'a CheckArgs, format: Option<&'a str>, result: &'a PolicyResult) -> Self {
        let (decision, allowed, reason, delegate_to, delegate_engine, delegate_context) =
            match result {
                PolicyResult::Allow => ("allow", true, None, None, None, None),
                PolicyResult::Deny(reason) => {
                    ("deny", false, Some(reason.as_str()), None, None, None)
                }
                PolicyResult::Delegate(reason) => (
                    "delegate",
                    false,
                    None,
                    Some(reason.engine),
                    Some(reason.engine),
                    reason.context.as_deref(),
                ),
                _ => ("unknown", false, None, None, None, None),
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
            delegate_engine,
            delegate_context,
        }
    }
}
