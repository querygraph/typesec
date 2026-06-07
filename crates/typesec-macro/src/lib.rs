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
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{DeriveInput, LitStr, parse_macro_input};

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
///     role Engineer {
///         can [read, write, execute] on ["code/*"];
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

    // Mini-DSL parser for `role Name { can [perms] on ["resources"]; }` blocks.
    struct PolicyParser(Vec<(Ident, Vec<Ident>, Vec<LitStr>)>);

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

                roles.push((
                    name,
                    perms.into_iter().collect(),
                    resources.into_iter().collect(),
                ));
            }

            Ok(PolicyParser(roles))
        }
    }

    let parsed: PolicyParser = syn::parse2(input)?;
    let mut output = proc_macro2::TokenStream::new();

    for (name, perms, resources) in parsed.0 {
        let name_str = name.to_string().to_lowercase();
        let perm_strs: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
        let perm_lits: Vec<LitStr> = perm_strs
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
