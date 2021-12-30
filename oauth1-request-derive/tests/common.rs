#![allow(dead_code, unused_macros)]

use core::fmt::{self, Display, Formatter};

macro_rules! assert_expand {
    (
        $(#[$attr:meta])* struct $Name:ident
            [$($lt:tt),*]
            [$($ty_param:ident $(: ($($bound:tt)*))* $(= $ty:ty)*),*]
            $(where $($where_ty:ident: ($($where_bound:tt)*),)*)*
        {
            $($(#[$f_attr:meta])* $field:ident: $f_ty:ty $(= $value:expr)*,)*
        }
        $expand_to:expr
    ) => {
        #[allow(non_snake_case)]
        #[test]
        fn $Name() {
            extern crate alloc;

            use core::num::NonZeroU64;

            use oauth::serializer::auth::{self, Authorizer};
            use oauth::signature_method::Identity;
            use oauth::Credentials;

            mod inner {
                // Shadow items imported via the prelude:
                #[allow(dead_code)]
                #[derive(Default)]
                pub struct Option<T>(T);
                #[allow(dead_code)]
                struct Some;
                #[allow(dead_code)]
                struct None;
                #[allow(dead_code)]
                struct Result;
                #[allow(dead_code)]
                struct Ok;
                #[allow(dead_code)]
                struct Err;

                $(#[$attr])*
                pub struct $Name<$($lt,)* $($ty_param $(: $($bound)*)*),*>
                    $(where $($where_ty: $($where_bound)*,)*)*
                {
                    $($(#[$f_attr])* pub $field: $f_ty,)*
                }
            }

            impl<$($lt,)* $($ty_param$(: $($bound)*)*),*> inner::$Name<$($lt,)* $($ty_param),*>
            where
                $($ty_param: std::fmt::Display,)*
                $($($where_ty: $($where_bound)*,)*)*
            {
                fn expected(&self, auth: Authorizer<'_, Identity>) -> alloc::string::String {
                    let expand_to: fn(&Self, Authorizer<'_, Identity>) -> _ = $expand_to;
                    expand_to(self, auth)
                }
            }

            #[allow(unused_macros)]
            macro_rules! this_or_default {
                ($this:expr) => ($this);
                () => (Default::default());
            }
            let x = inner::$Name $(::<$($ty),*>)* {
                $($field: this_or_default!($($value)*),)*
            };

            let client = Credentials::new("", "");
            let mut opts = auth::Options::new();
            opts.nonce("nonce").timestamp(NonZeroU64::new(9999999999));
            let auth = Authorizer::new(
                "GET",
                "https://example.com/get",
                client,
                None,
                &opts,
                Identity::new(),
            );
            let authorization = oauth::Request::serialize(&x, auth.clone());
            let expected = x.expected(auth);

            assert_eq!(authorization, expected);
        }
    };
}

pub fn always<T>(_: &T) -> bool {
    true
}

#[allow(clippy::unnecessary_wraps)]
pub fn fmt_ignore<T>(_: &T, _: &mut Formatter<'_>) -> fmt::Result {
    Ok(())
}

pub fn fmt_str(s: &str, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(s, f)
}
