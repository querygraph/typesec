//! Integration coverage for `#[derive(TypesecRole)]` — its generated `Role`
//! impl and, crucially, that it derives the *same* `name()` as the `policy!`
//! macro (both use `pascal_to_snake`, not `to_lowercase`).

use typesec_core::Role;
use typesec_macro::TypesecRole;

#[derive(TypesecRole)]
#[role(
    permissions = "read, read_sensitive",
    resources = "reports/*, metrics/*"
)]
struct AnalystReadOnly;

#[derive(TypesecRole)]
#[role(permissions = "read", resources = "docs/*")]
struct Reader;

#[test]
fn derive_uses_pascal_to_snake_naming() {
    // `AnalystReadOnly` → `analyst_read_only` (not `analystreadonly`), matching
    // how `policy!` names roles so the two can be compared to policy strings.
    assert_eq!(AnalystReadOnly::name(), "analyst_read_only");
    assert_eq!(Reader::name(), "reader");
}

#[test]
fn derive_exposes_permissions_and_resources() {
    assert_eq!(
        AnalystReadOnly::permission_names(),
        &["read", "read_sensitive"]
    );
    assert_eq!(
        AnalystReadOnly::resource_patterns(),
        &["reports/*", "metrics/*"]
    );
    assert_eq!(Reader::permission_names(), &["read"]);
    assert_eq!(Reader::resource_patterns(), &["docs/*"]);
}
