mod helper;

use proc_macro2::{Span, TokenStream, TokenTree};
use quote::{quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;
use syn::{Ident, PathArguments, Type};

use crate::field::Field;
use crate::util::OAuthParameter;

use self::helper::{FmtHelper, SkipIfHelper};

pub struct MethodBody<'a> {
    fields: &'a [Field],
}

impl<'a> MethodBody<'a> {
    pub fn new(fields: &'a [Field]) -> Self {
        MethodBody { fields }
    }
}

impl<'a> ToTokens for MethodBody<'a> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let this = Ident::new("self", Span::mixed_site());
        let ser = Ident::new("serializer", Span::mixed_site());
        let helper = Ident::new("helper", Span::mixed_site());
        // Name of destructured value inside an `Option` field value.
        let bind = Ident::new("value", Span::mixed_site());

        let has_fmt = self.fields.iter().any(|f| f.meta.fmt.is_some());
        let has_skip_if = self.fields.iter().any(|f| f.meta.skip_if.is_some());
        if has_fmt || has_skip_if {
            // TODO: Use `bool::then` when the minimum tested Rust version hits 1.50.
            let fmt = if has_fmt { Some(FmtHelper) } else { None };
            let skip_if = if has_skip_if {
                Some(SkipIfHelper)
            } else {
                None
            };
            // The items resolve at call site, so define them in the ephemeral block to avoid
            // name conflict, and "export" them through the unit struct `DeriveRequestAssertion`.
            // TODO: Use def-site hygiene once it stabilizes.
            tokens.extend(quote! {
                let #helper = {
                    struct DeriveRequestAssertion;
                    #fmt
                    #skip_if
                    DeriveRequestAssertion
                };
            });
        }

        let mut next_param = OAuthParameter::default();
        for f in self.fields {
            if f.meta.skip {
                continue;
            }

            let ident = &f.ident;
            let name = f.name();
            let name_string = name.string_value();
            // Name of temporary binds used to associate certain values to `f.ty`'s span.
            let tmp = Ident::new("tmp", f.ty.span());

            while next_param < *name_string {
                tokens.extend(quote! {
                    #ser.#next_param();
                });
                next_param = next_param.next();
            }

            let ty_is_option = f
                .meta
                .option
                .as_ref()
                .map(|v| v.value)
                .unwrap_or_else(|| is_option(&f.ty));

            let unwrapped = if ty_is_option {
                TokenStream::from(TokenTree::Ident(bind.clone()))
            } else {
                quote! { &#this.#ident }
            };

            // Set the value's span to `f.ty` so that a type error will appear at
            // the field's position.
            //
            // ```
            // #[derive(Request)] // <- Not here
            // struct Foo {
            //     field: (),
            //     //     ^^ `()` doesn't implement `std::fmt::Display`
            // }
            // ```
            let mut stmts = quote! { let #tmp = #unwrapped; };

            let display = if let Some(ref fmt) = f.meta.fmt {
                // Convert the function to an `impl Fn` so that type errors for it occurs only once.
                let fmt = quote_spanned! {fmt.span()=>
                    #helper.fmt_impls_fn(#fmt)
                };
                // Evaluate `#fmt` in advance so that the expression won't see the `#tmp` binding,
                // which resolves at call site.
                stmts = quote_spanned! {Span::mixed_site()=>
                    let fmt = #fmt;
                    #stmts
                };
                quote_spanned! {Span::mixed_site()=>
                    #helper.fmt(fmt, #tmp)
                }
            } else {
                TokenStream::from(TokenTree::Ident(tmp.clone()))
            };

            let serialize_method = if f.meta.encoded {
                // Set the method name's span to `f.ty` so that a trait bound error will point
                // at the field's position.
                //
                // ```
                // #[derive(Request)] // <- Not here
                // struct Foo {
                //     field: (),
                //     //~^ ERROR: `()` doesn't implement `std::fmt::Display`
                // }
                // ```
                Ident::new("serialize_parameter_encoded", f.ty.span())
            } else {
                Ident::new("serialize_parameter", f.ty.span())
            };
            stmts.extend(quote! { #ser.#serialize_method(#name, #display); });

            if let Some(ref skip_if) = f.meta.skip_if {
                let skip_if = quote_spanned! {skip_if.span()=>
                    #helper.skip_if_impls_fn(#skip_if)
                };
                let cond = quote_spanned! {f.ty.span()=>
                    !#skip_if({
                        // The purpose of this binding is the same as the `#tmp` binding above,
                        // but this is done in the ephemeral block to avoid name conflict.
                        let #tmp = #unwrapped;
                        #tmp
                    })
                };
                stmts = quote! {
                    if #cond {
                        #stmts
                    }
                };
            }

            if ty_is_option {
                stmts = quote! {
                    if let ::core::option::Option::Some(#bind) = {
                        let #tmp = &#this.#ident;
                        ::core::option::Option::as_ref(#tmp)
                    } {
                        #stmts
                    }
                };
            }

            // Enclose the statements with a block if not any yet, to keep the `#tmp` binding local.
            if f.meta.skip_if.is_none() && !ty_is_option {
                stmts = quote! {{ #stmts }};
            }

            tokens.extend(stmts);
        }

        while next_param != OAuthParameter::None {
            tokens.extend(quote! {
                #ser.#next_param();
            });
            next_param = next_param.next();
        }
        tokens.extend(quote! {
            #ser.end()
        });
    }
}

fn is_option(mut ty: &Type) -> bool {
    // Types that are interpolated through `macro_rules!` may be enclosed in a `Group`.
    // <https://github.com/rust-lang/rust/pull/72388>
    while let Type::Group(ref g) = *ty {
        ty = &g.elem;
    }

    if let Type::Path(ref ty_path) = *ty {
        let path = &ty_path.path;
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments[0].ident == "Option"
            && match path.segments[0].arguments {
                PathArguments::AngleBracketed(ref args) => args.args.len() == 1,
                PathArguments::None | PathArguments::Parenthesized(_) => false,
            }
    } else {
        false
    }
}
