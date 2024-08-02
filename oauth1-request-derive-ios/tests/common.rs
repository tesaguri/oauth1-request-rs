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

            use oauth::serializer::recorder::{Record, Recorder};

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
                $($ty_param: core::fmt::Display,)*
                $($($where_ty: $($where_bound)*,)*)*
            {
                fn expected(&self) -> alloc::vec::Vec<Record> {
                    let expand_to: fn(&Self, Recorder) -> _ = $expand_to;
                    expand_to(self, Recorder::new())
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

            let records = oauth::Request::serialize(&x, Recorder::new());
            let expected = x.expected();

            assert_eq!(records, expected);
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
