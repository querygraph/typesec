use typesec_core::Role;
use typesec_macro::policy;

policy! {
    role Reader {
        can [read] on ["docs/*"];
    }
    role Writer extends Reader {
        can [write] on ["docs/drafts/*"];
    }
    role Editor extends Writer {
        can [delete] on ["docs/archive/*"];
    }
}

#[test]
fn policy_macro_flattens_role_inheritance() {
    assert_eq!(Reader::name(), "reader");
    assert_eq!(Writer::name(), "writer");
    assert_eq!(Editor::name(), "editor");

    assert_eq!(Reader::permission_names(), &["read"]);
    assert_eq!(Writer::permission_names(), &["read", "write"]);
    assert_eq!(Editor::permission_names(), &["read", "write", "delete"]);

    assert_eq!(Reader::resource_patterns(), &["docs/*"]);
    assert_eq!(Writer::resource_patterns(), &["docs/*", "docs/drafts/*"]);
    assert_eq!(
        Editor::resource_patterns(),
        &["docs/*", "docs/drafts/*", "docs/archive/*"]
    );
}
