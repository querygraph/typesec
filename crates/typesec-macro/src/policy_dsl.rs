//! The `policy! { ... }` inline-role DSL.

use std::collections::HashMap;

use proc_macro2::Span;
use quote::quote;
use syn::LitStr;

use crate::shared::{check_permission, pascal_to_snake};

/// Mini-DSL parser for a `role Name [extends Parent] { can [perms] on [resources]; }` block.
struct RoleDef {
    name: syn::Ident,
    parent: Option<syn::Ident>,
    perms: Vec<syn::Ident>,
    resources: Vec<LitStr>,
}

struct PolicyParser(Vec<RoleDef>);

impl syn::parse::Parse for PolicyParser {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        use syn::{Ident, Token, braced, punctuated::Punctuated};

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
                res_content.parse_terminated(syn::parse::Parse::parse, Token![,])?;

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

/// Flatten a role's permissions and resources, inheriting from its parent.
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

pub(crate) fn policy_impl(
    input: proc_macro2::TokenStream,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    let parsed: PolicyParser = syn::parse2(input)?;
    let role_index: HashMap<String, usize> = parsed
        .0
        .iter()
        .enumerate()
        .map(|(idx, role)| (role.name.to_string(), idx))
        .collect();
    let mut output = proc_macro2::TokenStream::new();

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
