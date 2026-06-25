//! Helpers shared by both macros: permission validation and name casing.

use proc_macro2::Span;

/// Permission names defined in `typesec-core` (`Permission::name()` values).
///
/// Both macros validate against this list so a typo like `raed` fails at
/// compile time instead of becoming a permission string that never matches.
pub(crate) const KNOWN_PERMISSIONS: &[&str] = &[
    "read",
    "write",
    "delete",
    "execute",
    "delegate",
    "read_internal",
    "read_sensitive",
    "write_sensitive",
    "declassify",
    "ai:infer",
    "ai:train",
    "ai:exfiltrate",
];

/// Validate a permission name against [`KNOWN_PERMISSIONS`], erroring at `span`.
pub(crate) fn check_permission(name: &str, span: Span) -> Result<(), syn::Error> {
    if KNOWN_PERMISSIONS.contains(&name) {
        Ok(())
    } else {
        Err(syn::Error::new(
            span,
            format!(
                "unknown permission '{name}' (expected one of: {})",
                KNOWN_PERMISSIONS.join(", ")
            ),
        ))
    }
}

/// Convert a PascalCase role identifier to a `snake_case` name string.
pub(crate) fn pascal_to_snake(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();

    for (i, ch) in chars.iter().enumerate() {
        if ch.is_ascii_uppercase() {
            let prev = i.checked_sub(1).and_then(|idx| chars.get(idx));
            let next = chars.get(i + 1);
            let starts_new_word = prev.is_some_and(|prev| {
                prev.is_ascii_lowercase()
                    || prev.is_ascii_digit()
                    || (prev.is_ascii_uppercase()
                        && next.is_some_and(|next| next.is_ascii_lowercase()))
            });

            if starts_new_word && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else if *ch == '-' {
            if !out.ends_with('_') {
                out.push('_');
            }
        } else {
            out.push(*ch);
        }
    }

    out
}
