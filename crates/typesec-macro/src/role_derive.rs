//! `#[derive(TypesecRole)]` expansion.

use proc_macro2::Span;
use quote::quote;
use syn::{DeriveInput, LitStr};

use crate::shared::check_permission;

pub(crate) fn derive_typesec_role_impl(
    input: DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
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
