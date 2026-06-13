//! # typesec-macro
//!
//! Procedural macros for the typesec ecosystem.
//!
//! ## `#[derive(TypesecRole)]`
//!
//! Derive the [`Role`][typesec_core::role::Role] trait for a struct, pulling
//! permissions and resource patterns from the `#[role(...)]` attribute:
//!
//! ```rust,ignore
//! use typesec_macro::TypesecRole;
//!
//! #[derive(TypesecRole)]
//! #[role(permissions = "read,write", resources = "code/*,infra/*")]
//! pub struct Engineer;
//! ```
//!
//! Expands to:
//!
//! ```rust,ignore
//! impl typesec_core::role::Role for Engineer {
//!     fn name() -> &'static str { "Engineer" }
//!     fn permission_names() -> &'static [&'static str] { &["read", "write"] }
//!     fn resource_patterns() -> &'static [&'static str] { &["code/*", "infra/*"] }
//! }
//! ```
//!
//! ## `policy!` macro
//!
//! Inline role definitions without a YAML file:
//!
//! ```rust,ignore
//! use typesec_macro::policy;
//!
//! policy! {
//!     role Analyst {
//!         can [read, read_sensitive] on ["reports/*", "metrics/*"];
//!     }
//!     role LeadAnalyst extends Analyst {
//!         can [write] on ["reports/drafts/*"];
//!     }
//! }
//! ```

use std::collections::HashMap;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{DeriveInput, LitStr, parse_macro_input};

/// Permission names defined in `typesec-core` (`Permission::name()` values).
///
/// Both macros validate against this list so a typo like `raed` fails at
/// compile time instead of becoming a permission string that never matches.
const KNOWN_PERMISSIONS: &[&str] = &[
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

fn check_permission(name: &str, span: Span) -> Result<(), syn::Error> {
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

fn pascal_to_snake(name: &str) -> String {
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

/// Derive the `typesec_core::role::Role` trait.
///
/// Requires a `#[role(permissions = "...", resources = "...")]` attribute.
#[proc_macro_derive(TypesecRole, attributes(role))]
pub fn derive_typesec_role(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_typesec_role_impl(input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn derive_typesec_role_impl(input: DeriveInput) -> Result<proc_macro2::TokenStream, syn::Error> {
    let struct_name = &input.ident;
    let struct_name_str = struct_name.to_string().to_lowercase();

    // Find the #[role(...)] attribute.
    let role_attr = input
        .attrs
        .iter()
        .find(|a| a.path().is_ident("role"))
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "TypesecRole requires a #[role(permissions = \"...\", resources = \"...\")] attribute",
            )
        })?;

    // Parse the key=value pairs inside the attribute.
    let mut permissions: Vec<String> = Vec::new();
    let mut resources: Vec<String> = Vec::new();

    role_attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("permissions") {
            let value: LitStr = meta.value()?.parse()?;
            permissions = value
                .value()
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect();
            for permission in &permissions {
                check_permission(permission, value.span())?;
            }
            Ok(())
        } else if meta.path.is_ident("resources") {
            let value: LitStr = meta.value()?.parse()?;
            resources = value
                .value()
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect();
            Ok(())
        } else {
            Err(meta.error("unknown role attribute key (expected 'permissions' or 'resources')"))
        }
    })?;

    let perm_lits: Vec<LitStr> = permissions
        .iter()
        .map(|p| LitStr::new(p, Span::call_site()))
        .collect();

    let resource_lits: Vec<LitStr> = resources
        .iter()
        .map(|r| LitStr::new(r, Span::call_site()))
        .collect();

    let name_lit = LitStr::new(&struct_name_str, Span::call_site());

    Ok(quote! {
        impl typesec_core::role::Role for #struct_name {
            fn name() -> &'static str {
                #name_lit
            }
            fn permission_names() -> &'static [&'static str] {
                &[#(#perm_lits),*]
            }
            fn resource_patterns() -> &'static [&'static str] {
                &[#(#resource_lits),*]
            }
        }
    })
}

/// Inline policy macro.
///
/// ```rust,ignore
/// policy! {
///     role Analyst {
///         can [read, read_sensitive] on ["reports/*"];
///     }
///     role Engineer extends Analyst {
///         can [write, execute] on ["code/*"];
///     }
/// }
/// ```
///
/// Expands each `role X { ... }` block to a struct + `Role` impl.
#[proc_macro]
pub fn policy(input: TokenStream) -> TokenStream {
    match policy_impl(input.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn policy_impl(input: proc_macro2::TokenStream) -> Result<proc_macro2::TokenStream, syn::Error> {
    use syn::{
        Ident, Token, braced,
        parse::{Parse, ParseStream},
        punctuated::Punctuated,
    };

    // Mini-DSL parser for `role Name [extends Parent] { can [perms] on ["resources"]; }` blocks.
    struct RoleDef {
        name: Ident,
        parent: Option<Ident>,
        perms: Vec<Ident>,
        resources: Vec<LitStr>,
    }

    struct PolicyParser(Vec<RoleDef>);

    impl Parse for PolicyParser {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            let mut roles = Vec::new();

            while !input.is_empty() {
                // `role` — parse as a plain Ident (it's not a Rust keyword).
                let kw: Ident = input.parse()?;
                if kw != "role" {
                    return Err(syn::Error::new(kw.span(), "expected `role`"));
                }

                // Role name
                let name: Ident = input.parse()?;

                let parent = if input.peek(Ident) {
                    let maybe_extends: Ident = input.parse()?;
                    if maybe_extends != "extends" {
                        return Err(syn::Error::new(
                            maybe_extends.span(),
                            "expected `extends` or `{`",
                        ));
                    }
                    Some(input.parse()?)
                } else {
                    None
                };

                // `{ can [perms] on ["resources"]; }`
                let content;
                braced!(content in input);

                // `can`
                let can_kw: Ident = content.parse()?;
                if can_kw != "can" {
                    return Err(syn::Error::new(can_kw.span(), "expected `can`"));
                }

                // `[perm1, perm2, ...]`
                let perm_content;
                syn::bracketed!(perm_content in content);
                let perms: Punctuated<Ident, Token![,]> =
                    perm_content.parse_terminated(Ident::parse, Token![,])?;

                // `on`
                let on_kw: Ident = content.parse()?;
                if on_kw != "on" {
                    return Err(syn::Error::new(on_kw.span(), "expected `on`"));
                }

                // `["resource1", ...]`
                let res_content;
                syn::bracketed!(res_content in content);
                let resources: Punctuated<LitStr, Token![,]> =
                    res_content.parse_terminated(Parse::parse, Token![,])?;

                // Optional semicolon
                let _ = content.parse::<Token![;]>();

                roles.push(RoleDef {
                    name,
                    parent,
                    perms: perms.into_iter().collect(),
                    resources: resources.into_iter().collect(),
                });
            }

            Ok(PolicyParser(roles))
        }
    }

    let parsed: PolicyParser = syn::parse2(input)?;
    let role_index: HashMap<String, usize> = parsed
        .0
        .iter()
        .enumerate()
        .map(|(idx, role)| (role.name.to_string(), idx))
        .collect();
    let mut output = proc_macro2::TokenStream::new();

    fn flatten_role(
        idx: usize,
        roles: &[RoleDef],
        role_index: &HashMap<String, usize>,
        visiting: &mut Vec<String>,
    ) -> Result<(Vec<String>, Vec<LitStr>), syn::Error> {
        let role = &roles[idx];
        let role_name = role.name.to_string();
        if visiting.contains(&role_name) {
            return Err(syn::Error::new(
                role.name.span(),
                format!("circular role inheritance detected for `{role_name}`"),
            ));
        }

        visiting.push(role_name);

        let mut permissions = Vec::new();
        let mut resources = Vec::new();

        if let Some(parent) = &role.parent {
            let parent_name = parent.to_string();
            let parent_idx = role_index.get(&parent_name).ok_or_else(|| {
                syn::Error::new(
                    parent.span(),
                    format!("role `{}` extends unknown role `{parent_name}`", role.name),
                )
            })?;
            let (parent_permissions, parent_resources) =
                flatten_role(*parent_idx, roles, role_index, visiting)?;
            permissions.extend(parent_permissions);
            resources.extend(parent_resources);
        }

        for perm in &role.perms {
            let perm_name = perm.to_string();
            check_permission(&perm_name, perm.span())?;
            if !permissions.contains(&perm_name) {
                permissions.push(perm_name);
            }
        }

        for resource in &role.resources {
            if !resources
                .iter()
                .any(|existing: &LitStr| existing.value() == resource.value())
            {
                resources.push(resource.clone());
            }
        }

        visiting.pop();
        Ok((permissions, resources))
    }

    for (idx, role) in parsed.0.iter().enumerate() {
        let name = &role.name;
        let name_str = pascal_to_snake(&name.to_string());
        let (permissions, resources) = flatten_role(idx, &parsed.0, &role_index, &mut Vec::new())?;
        let perm_lits: Vec<LitStr> = permissions
            .iter()
            .map(|s| LitStr::new(s, Span::call_site()))
            .collect();

        let name_lit = LitStr::new(&name_str, Span::call_site());

        output.extend(quote! {
            #[derive(Debug, Clone, Copy)]
            pub struct #name;

            impl typesec_core::role::Role for #name {
                fn name() -> &'static str { #name_lit }
                fn permission_names() -> &'static [&'static str] { &[#(#perm_lits),*] }
                fn resource_patterns() -> &'static [&'static str] { &[#(#resources),*] }
            }
        });
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use quote::quote;

    use super::{pascal_to_snake, policy_impl};

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
}
