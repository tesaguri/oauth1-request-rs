#![warn(rust_2018_idioms)]

//! This crate provides `#[derive(Authorize)]` macro that implements
//! `oauth1_request` crate's `Authorize` trait for a struct with named fields.
//!
//! `oauth1_request` crate re-exports the derive macro if the `derive` feature of that crate
//! is enabled (which is on by default).
//! You should use the re-export instead of depend on this crate directly.
//!
//! See [`oauth1_request::Authorize`][Authorize] for more information.
//!
//! [Authorize]: https://docs.rs/oauth1-request/0.3/oauth1_request/authorize/trait.Authorize.html

#![doc(html_root_url = "https://docs.rs/oauth1-request-derive/0.3.3")]

#[allow(unused_extern_crates)]
extern crate proc_macro;

mod ctxt;
mod field;
mod method_body;
mod util;

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Data, DataStruct, DeriveInput, Fields, GenericParam, Generics,
    Ident,
};

use ctxt::Ctxt;
use field::Field;
use method_body::MethodBody;
use util::error;

/// See [`oauth1_request::Authorize`][Authorize].
///
/// [Authorize]: https://docs.rs/oauth1-request/^0.3/oauth1_request/authorize/trait.Authorize.html
#[proc_macro_derive(Authorize, attributes(oauth1))]
pub fn derive_oauth1_authorize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_derive_oauth1_authorize(input).into()
}

fn expand_derive_oauth1_authorize(input: DeriveInput) -> TokenStream {
    let fields = match input.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => fields,
        _ => return error("expected a struct with named fields", input.span()),
    };

    let mut cx = Ctxt::new();

    let DeriveInput {
        ident: name,
        mut generics,
        ..
    } = input;

    let mut fields: Vec<_> = fields
        .named
        .into_iter()
        .map(|f| Field::new(f, &mut cx))
        .collect();

    fields.sort_by(|f, g| f.with_renamed(|a| g.with_renamed(|b| a.cmp(&b))));
    for w in fields.windows(2) {
        let (f, g) = (&w[0], &w[1]);
        f.with_renamed(|a| {
            g.with_renamed(|b| {
                if *a == *b {
                    cx.error(&format!("duplicate parameter \"{}\"", *b), b.span());
                }
            });
        });
    }

    if let Some(tokens) = cx.emit_errors() {
        return tokens;
    }

    // We assume that `dummy` does not conflict with any of call-side identifiers
    // and (ab)use it to avoid potential name collisions.
    let dummy = format!("_impl_ToOAuth1Request_for_{}", name);
    let dummy = Ident::new(&dummy, Span::call_site());

    let krate = proc_macro_crate::crate_name("oauth1-request").unwrap();
    let krate = Ident::new(&krate, Span::call_site());

    add_trait_bounds(&mut generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut fn_generics = generics.clone();
    fn_generics.params.push(parse_quote! {
        #dummy: _oauth1_request::signature_method::SignatureMethod
    });
    let (fn_generics, _, _) = fn_generics.split_for_impl();

    let body = MethodBody::new(&fields, &dummy);

    quote! {
        #[allow(non_camel_case_types)]
        enum #dummy {}

        impl #dummy {
            fn _dummy(self) {
                extern crate #krate as _oauth1_request;

                #[allow(nonstandard_style)]
                fn #dummy #fn_generics(
                    mut #dummy: (
                        &#name #ty_generics,
                        _oauth1_request::signer::Signer<#dummy>,
                        &str,
                        ::std::option::Option<&_oauth1_request::Options>,
                    ),
                ) -> _oauth1_request::Request
                #where_clause
                {
                    #body
                }

                impl #impl_generics _oauth1_request::Authorize for #name #ty_generics
                    #where_clause
                {
                    fn authorize_with<SM>(
                        &self,
                        signer: _oauth1_request::signer::Signer<SM>,
                        ck: &str,
                        opts: ::std::option::Option<&_oauth1_request::Options>,
                    ) -> _oauth1_request::Request
                    where
                        SM: _oauth1_request::signature_method::SignatureMethod,
                    {
                        #dummy((self, signer, ck, opts))
                    }
                }
            }
        }
    }
}

fn add_trait_bounds(generics: &mut Generics) {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param.bounds.push(parse_quote!(::std::fmt::Display));
        }
    }
}
