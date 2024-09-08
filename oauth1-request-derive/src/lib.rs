#![warn(rust_2018_idioms)]

//! This crate provides a derive macro for [`oauth1_request::Request`][Request]:
//!
//! [Request]: https://docs.rs/oauth1-request/0.6/oauth1_request/trait.Request.html
//!
//! ```
//! # extern crate oauth1_request as oauth;
//! #[derive(oauth::Request)]
//! # struct Foo {}
//! ```
//!
//! `oauth1_request` crate re-exports the derive macro if the `derive` feature of the crate
//! is enabled (which is on by default).
//! You should use the re-export instead of depending on this crate directly.

#![doc(html_root_url = "https://docs.rs/oauth1-request-derive/0.5.1")]

#[macro_use]
mod meta;

mod container;
mod ctxt;
mod field;
mod method_body;
mod util;

use proc_macro2::{Span, TokenStream};
use proc_macro_crate::FoundCrate;
use quote::{quote, quote_spanned};
use syn::{
    parse_macro_input, parse_quote, Data, DataStruct, DeriveInput, Fields, GenericParam, Generics,
    Ident,
};

use self::container::ContainerMeta;
use self::ctxt::Ctxt;
use self::field::Field;
use self::method_body::MethodBody;

/// A derive macro for [`oauth1_request::Request`][Request] trait.
///
/// [Request]: https://docs.rs/oauth1-request/0.6/oauth1_request/trait.Request.html
///
/// See the [documentation] on the `oauth1_request` crate.
///
/// [documentation]: https://docs.rs/oauth1-request/0.6/oauth1_request/derive.Request.html
#[proc_macro_derive(Request, attributes(oauth1))]
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
        _ => {
            return syn::Error::new_spanned(input, "expected a struct with named fields")
                .into_compile_error()
        }
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

    fields.sort_by_cached_key(|f| f.name().string_value());
    fields.iter().fold(String::new(), |prev_name, f| {
        let name = f.name();
        let (name, span) = (name.string_value(), name.span());
        if name == prev_name {
            cx.add_error_message(span, format!("duplicate parameter \"{}\"", name));
        }
        name
    });

    let meta = ContainerMeta::new(input.attrs, &mut cx);

    let use_oauth1_request = if let Some(krate) = meta.krate {
        quote! {
            use #krate as _oauth1_request;
        }
    } else {
        let krate;
        let krate = match proc_macro_crate::crate_name("oauth1-request") {
            Ok(FoundCrate::Name(k)) => {
                krate = k;
                &*krate
            }
            // This is used in `oauth1_request`'s doctests.
            Ok(FoundCrate::Itself) => {
                krate = std::env::var("CARGO_CRATE_NAME").unwrap();
                &*krate
            }
            Err(proc_macro_crate::Error::CargoManifestDirNotSet) => "oauth1_request",
            Err(e) => {
                cx.add_error_message(Span::call_site(), e);
                "oauth1_request"
            }
        };
        let krate = Ident::new(krate, Span::call_site());
        quote! {
            extern crate #krate as _oauth1_request;
        }
    };

    add_trait_bounds(&mut generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    if let Some(e) = cx.take_error() {
        let mut tokens = e.into_compile_error();
        tokens.extend(quote! {
            const _: () = {
                #use_oauth1_request

                impl #impl_generics _oauth1_request::Request for #name #ty_generics
                    #where_clause
                {
                    fn serialize<S>(&self, serializer: S) -> S::Output
                    where
                        S: _oauth1_request::serializer::Serializer,
                    {
                        unimplemented!();
                    }
                }
            };
        });
        return tokens;
    }

    let body = MethodBody::new(&fields);

    quote_spanned! {Span::mixed_site()=>
        const _: () = {
            #use_oauth1_request

            #[automatically_derived]
            impl #impl_generics _oauth1_request::Request for #name #ty_generics
                #where_clause
            {
                // `_S`'s span resolves at call site so prefix it with underscore to avoid conflict.
                // TODO: Use def-site hygiene once it stabilizes.
                fn serialize<_S>(&self, mut serializer: _S) -> _S::Output
                where
                    _S: _oauth1_request::serializer::Serializer,
                {
                    #body
                }
            }
        };
    }
}

fn add_trait_bounds(generics: &mut Generics) {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param.bounds.push(parse_quote!(::core::fmt::Display));
        }
    }
}
