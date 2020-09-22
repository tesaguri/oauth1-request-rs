#![warn(rust_2018_idioms)]

//! This crate provides `#[derive(Request)]` macro that implements
//! `oauth1_request` crate's `Request` trait for a struct with named fields.
//!
//! `oauth1_request` crate re-exports the derive macro if the `derive` feature of that crate
//! is enabled (which is on by default).
//! You should use the re-export instead of depend on this crate directly.
//!
//! See [`oauth1_request::Request`][Request] for more information.
//!
//! [Request]: https://docs.rs/oauth1-request/0.3/oauth1_request/request/trait.Request.html

#![doc(html_root_url = "https://docs.rs/oauth1-request-derive/0.3.3")]

#[allow(unused_extern_crates)]
extern crate proc_macro;

mod field;
mod method_body;
mod util;

use proc_macro2::{Span, TokenStream};
use proc_macro_error::{abort, abort_if_dirty, emit_error, proc_macro_error};
use quote::quote;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Data, DataStruct, DeriveInput, Fields, GenericParam, Generics,
    Ident,
};

use field::Field;
use method_body::MethodBody;

/// See [`oauth1_request::Request`][Request].
///
/// [Request]: https://docs.rs/oauth1-request/^0.3/oauth1_request/request/trait.Request.html
#[proc_macro_error]
#[proc_macro_derive(Request, attributes(oauth1))]
pub fn derive_oauth1_authorize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_derive_oauth1_authorize(input).into()
}

fn expand_derive_oauth1_authorize(mut input: DeriveInput) -> TokenStream {
    let name = &input.ident;

    // We assume that `dummy` does not conflict with any of call-side identifiers
    // and (ab)use it to avoid potential name collisions.
    let dummy = format!("_impl_ToOAuth1Request_for_{}", name);
    let dummy = Ident::new(&dummy, Span::call_site());

    let krate = proc_macro_crate::crate_name("oauth1-request").unwrap();
    let krate = Ident::new(&krate, Span::call_site());

    add_trait_bounds(&mut input.generics);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    proc_macro_error::set_dummy(quote! {
        const _: () = {
            extern crate #krate as _oauth1_request;
            impl #impl_generics _oauth1_request::Request for #name #ty_generics
                #where_clause
            {
                fn serialize<S>(&self, serializer: S) -> S::Output
                where
                    S: _oauth1_request::Serializer,
                {
                    unimplemented!();
                }
            }
        };
    });

    let fields = match input.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => fields,
        _ => abort!(input.span(), "expected a struct with named fields"),
    };

    let mut fields: Vec<_> = fields.named.into_iter().map(Field::new).collect();

    fields.sort_by(|f, g| f.with_renamed(|a| g.with_renamed(|b| a.value().cmp(&b.value()))));
    for w in fields.windows(2) {
        let (f, g) = (&w[0], &w[1]);
        f.with_renamed(|a| {
            g.with_renamed(|b| {
                if a.value() == b.value() {
                    emit_error!(b.span(), "duplicate parameter \"{}\"", b.value());
                }
            });
        });
    }

    abort_if_dirty();

    let mut fn_generics = input.generics.clone();
    fn_generics.params.push(parse_quote! {
        #dummy: _oauth1_request::Serializer
    });
    let (fn_generics, _, _) = fn_generics.split_for_impl();

    let body = MethodBody::new(&fields, &dummy);

    quote! {
        const _: () = {
            extern crate #krate as _oauth1_request;

            #[allow(nonstandard_style)]
            fn #dummy #fn_generics(mut #dummy: (&#name #ty_generics, #dummy)) -> #dummy::Output
            #where_clause
            {
                #body
            }

            impl #impl_generics _oauth1_request::Request for #name #ty_generics
                #where_clause
            {
                // We do not want to mess with the signature which appears in the docs
                // and do not want to expose the `serializer` and `S` to the macro caller,
                // so we are separating the implementation to another function.
                fn serialize<S>(&self, serializer: S) -> S::Output
                where
                    S: _oauth1_request::Serializer,
                {
                    #dummy((self, serializer))
                }
            }
        };
    }
}

fn add_trait_bounds(generics: &mut Generics) {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param.bounds.push(parse_quote!(::std::fmt::Display));
        }
    }
}
