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
            // name conflict, and "export" them through the unit struct `Helper`.
            // TODO: Use def-site hygiene once it stabilizes.
            tokens.extend(quote! {
                let #helper = {
                    struct Helper;
                    #fmt
                    #skip_if
                    Helper
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

            let display = if let Some(ref fmt) = f.meta.fmt {
                // Convert the function to an `impl Fn` so that type errors for it occurs only once.
                let fmt = quote_spanned! {fmt.span()=>
                    #helper.fmt_as_impl_fn(#fmt)
                };
                quote! { #helper.fmt(#fmt, #unwrapped) }
            } else {
                unwrapped.clone()
            };

            let mut stmts = if f.meta.encoded {
                // Set the expression's span to `f.ty` so that a trait bound error will appear
                // at the field's position.
                //
                // ```
                // #[derive(Request)] // <- Not here
                // struct Foo {
                //     field: (),
                //     //~^ ERROR: `()` doesn't implement `std::fmt::Display`
                // }
                // ```
                quote_spanned! {f.ty.span()=>
                    #ser.serialize_parameter_encoded(#name, #display);
                }
            } else {
                quote_spanned! {f.ty.span()=>
                    #ser.serialize_parameter(#name, #display);
                }
            };
            if let Some(ref skip_if) = f.meta.skip_if {
                let skip_if = quote_spanned! {skip_if.span()=>
                    #helper.skip_if_as_impl_fn(#skip_if)
                };
                stmts = quote! {
                    if !#skip_if(#unwrapped) {
                        #stmts
                    }
                };
            }
            if ty_is_option {
                let tmp = Ident::new("tmp", f.ty.span());
                stmts = quote! {
                    if let ::std::option::Option::Some(#bind) = {
                        // Set the argument's span to `f.ty` so that a type error will appear
                        // at the field's position. The span resolves at call site, so we are
                        // binding `#tmp` to the ephemeral block to avoid name conflict.
                        //
                        // ```
                        // #[derive(Request)] // <- Not here
                        // struct Foo {
                        //     #[oauth1(option = true)]
                        //     field: (),
                        //     //~^ expected enum `Option`, found `()`
                        // }
                        // ```
                        let #tmp = &#this.#ident;
                        ::std::option::Option::as_ref(#tmp)
                    } {
                        #stmts
                    }
                };
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
