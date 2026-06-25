use quote::quote;

use crate::policy_dsl::policy_impl;
use crate::shared::pascal_to_snake;

#[test]
fn converts_pascal_case_role_names_to_snake_case() {
    assert_eq!(pascal_to_snake("AnalystReadOnly"), "analyst_read_only");
    assert_eq!(pascal_to_snake("AITrainer"), "ai_trainer");
    assert_eq!(pascal_to_snake("HTTPAuditLog"), "http_audit_log");
    assert_eq!(pascal_to_snake("Reader"), "reader");
}

#[test]
fn policy_macro_rejects_unknown_parent_role() {
    let err = policy_impl(quote! {
        role Writer extends Reader {
            can [write] on ["docs/*"];
        }
    })
    .expect_err("unknown parent should fail");

    assert!(err.to_string().contains("unknown role `Reader`"));
}

#[test]
fn policy_macro_rejects_cyclic_inheritance() {
    let err = policy_impl(quote! {
        role Reader extends Writer {
            can [read] on ["docs/*"];
        }
        role Writer extends Reader {
            can [write] on ["docs/*"];
        }
    })
    .expect_err("inheritance cycle should fail");

    assert!(err.to_string().contains("circular role inheritance"));
}
