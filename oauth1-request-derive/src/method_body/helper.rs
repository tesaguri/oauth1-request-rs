use proc_macro2::TokenStream;
use quote::{quote, ToTokens};

#[cfg(test)]
macro_rules! def_tokens {
    ($name:ident; $($tt:tt)*) => {
        def_tokens_inner! {$name; $($tt)* }
        // Expand the tokens into this module as well to make the code testable
        // and get nice compile errors.
        $($tt)*
    };
}

#[cfg(not(test))]
macro_rules! def_tokens {
    ($name:ident; $($tt:tt)*) => {
        def_tokens_inner! {$name; $($tt)* }
    };
}

macro_rules! def_tokens_inner {
    ($name:ident; $($tt:tt)*) => {
        pub struct $name;

        impl ToTokens for $name {
            fn to_tokens(&self, tokens: &mut TokenStream) {
                tokens.extend(quote! { $($tt)* });
            }
        }
    };
}

#[cfg(test)]
struct DeriveRequestAssertion;

def_tokens! {FmtHelper;
    use ::core::fmt::{Display, Formatter, Result};

    struct Fmt<T, F>(T, F);

    impl<T: Copy, F> Display for Fmt<T, F>
    where
        F: Fn(T, &mut Formatter<'_>) -> Result,
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            self.1(self.0, f)
        }
    }

    impl DeriveRequestAssertion {
        // The order of arguments is imoprtant here.
        // If you reverse the order, deref coercions won't work for `t` (see the test below).
        fn fmt<'a, F, T: ?Sized>(&self, f: F, t: &'a T) -> Fmt<&'a T, F>
        where
            F: Fn(&T, &mut Formatter<'_>) -> Result,
        {
            Fmt(t, f)
        }

        fn fmt_impls_fn<F, T: ?Sized>(&self, f: F) -> impl Fn(&T, &mut Formatter<'_>) -> Result
        where
            F: Fn(&T, &mut Formatter<'_>) -> Result,
        {
            f
        }
    }
}

def_tokens! {SkipIfHelper;
    impl DeriveRequestAssertion {
        fn skip_if_impls_fn<F, T: ?Sized>(&self, f: F) -> impl Fn(&T) -> bool
        where
            F: Fn(&T) -> bool,
        {
            f
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(unused)]
    fn it_compiles() {
        fn fmt_str(_: &str, _: &mut Formatter<'_>) -> Result {
            unimplemented!();
        }

        let helper = DeriveRequestAssertion;

        let fmt = helper.fmt_impls_fn(fmt_str);
        // The `&String` should coerce to `&str`.
        let _ = helper.fmt(fmt_str, "");

        let _ = helper.skip_if_impls_fn(|&()| true);
    }
}
