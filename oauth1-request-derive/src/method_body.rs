use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::Ident;

use field::Field;

pub struct MethodBody<'a> {
    fields: &'a [Field],
    dummy: &'a Ident,
}

impl<'a> MethodBody<'a> {
    pub fn new(fields: &'a [Field], dummy: &'a Ident) -> Self {
        MethodBody { fields, dummy }
    }
}

impl<'a> ToTokens for MethodBody<'a> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let dummy = &self.dummy;
        let (this, signer, ck, opts) = (
            quote! { #dummy.0 },
            quote! { #dummy.1 },
            quote! { #dummy.2 },
            quote! { #dummy.3 },
        );

        let mut ready = false;
        for f in self.fields {
            let ident = &f.ident;

            f.with_renamed(|name| {
                if f.meta.skip {
                    return;
                }

                if **name > *"oauth_" && !ready {
                    quote!(
                        let mut #dummy = (
                            #this,
                            #signer.oauth_parameters(#ck, #opts),
                        );
                    ).to_tokens(tokens);
                    ready = true;
                }

                let value = if f.meta.option {
                    quote_spanned! {f.ty.span()=> {
                        let ref value = #this.#ident;
                        ::std::option::Option::as_ref(value).unwrap()
                    }}
                } else {
                    quote! { &#this.#ident }
                };

                let display = if let Some(fmt) = f.meta.fmt.get() {
                    quote! {
                        {
                            use std::fmt::{Display, Formatter, Result};

                            // We can't just use `f.ty` instead of `T` because doing so would lead
                            // to E0412/E0261 if `f.ty` contains lifetime/type parameters.
                            struct Adapter<'a, T: 'a + ?Sized, F>(&'a T, F);
                            impl<'a, T: 'a + ?Sized, F> Display for Adapter<'a, T, F>
                            where
                                F: Fn(&T, &mut Formatter<'_>) -> Result,
                            {
                                fn fmt(&self, f: &mut Formatter<'_>) -> Result {
                                    self.1(self.0, f)
                                }
                            }

                            // A helper to make deref coertion from `&#f.ty` to `&T` work properly.
                            struct MakeAdapter<F>(F);
                            impl<F> MakeAdapter<F> {
                                fn make_adapter<T: ?Sized>(self, t: &T) -> Adapter<'_, T, F>
                                where
                                    for<'a> Adapter<'a, T, F>: Display,
                                {
                                    Adapter(t, self.0)
                                }
                            }

                            MakeAdapter
                        }({
                            let fmt: fn(&_, &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result =
                                #fmt;
                            fmt
                        })
                        .make_adapter(#value)
                    }
                } else {
                    value.clone()
                };

                let mut stmt = if f.meta.encoded {
                    quote_spanned! {f.ty.span()=>
                        #signer.parameter_encoded(#name, #display);
                    }
                } else {
                    quote_spanned! {f.ty.span()=>
                        #signer.parameter(#name, #display);
                    }
                };
                if let Some(skip_if) = f.meta.skip_if.get() {
                    stmt = quote! {
                        if !{
                            let skip_if: fn(&_) -> bool = #skip_if;
                            skip_if
                        }(#value)
                        {
                            #stmt
                        }
                    };
                }
                if f.meta.option {
                    stmt = quote_spanned! {f.ty.span()=>
                        if {
                            let ref value = #this.#ident;
                            ::std::option::Option::is_some(value)
                        } {
                            #stmt
                        }
                    };
                }
                stmt.to_tokens(tokens);
            });
        }
        if ready {
            quote! {
                #signer.finish()
            }
        } else {
            quote! {
                #signer.finish(#ck, #opts)
            }
        }.to_tokens(tokens);
    }
}
