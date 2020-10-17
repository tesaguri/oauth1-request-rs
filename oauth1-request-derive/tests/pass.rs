#![deny(warnings)]

extern crate oauth;

use std::fmt::{self, Display, Formatter};

use oauth::serializer::{Serializer, SerializerExt};

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
            use std::num::NonZeroU64;

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
                fn expected(&self, auth: Authorizer<Identity>) -> String {
                    let expand_to: fn(&Self, Authorizer<Identity>) -> _ = $expand_to;
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
            let auth = Authorizer::<Identity>::new("GET", "https://example.com/get", client, None, &opts);
            let authorization = oauth::Request::serialize(&x, auth.clone());
            let expected = x.expected(auth);

            assert_eq!(authorization, expected);
        }
    };
}

assert_expand! {
    #[derive(oauth::Request)]
    struct OneBeforeOAuth[][] {
        foo: u64,
    }
    |this, mut ser| {
        ser.serialize_parameter("foo", this.foo);
        ser.serialize_oauth_parameters();
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct MultipleBeforeOAuth[][] {
        foo: u64,
        bar: bool,
    }
    |this, mut ser| {
        ser.serialize_parameter("bar", this.bar);
        ser.serialize_parameter("foo", this.foo);
        ser.serialize_oauth_parameters();
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct OneBeforeAndAfterOAuth[][] {
        baz: char,
        qux: f64,
    }
    |this, mut ser| {
        ser.serialize_parameter("baz", this.baz);
        ser.serialize_oauth_parameters();
        ser.serialize_parameter("qux", this.qux);
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct OneBeforeAndAfterOAuthRev[][] {
        qux: f64,
        baz: char,
    }
    |this, mut ser| {
        ser.serialize_parameter("baz", this.baz);
        ser.serialize_oauth_parameters();
        ser.serialize_parameter("qux", this.qux);
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct OAuthPrefix[][] {
        oauth_prefix: u64,
    }
    |this, mut ser| {
        ser.serialize_oauth_callback();
        ser.serialize_oauth_consumer_key();
        ser.serialize_oauth_nonce();
        ser.serialize_parameter("oauth_prefix", this.oauth_prefix);
        ser.serialize_oauth_signature_method();
        ser.serialize_oauth_timestamp();
        ser.serialize_oauth_token();
        ser.serialize_oauth_verifier();
        ser.serialize_oauth_version();
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct OneAfterOAuth[][] {
        qux: f64,
    }
    |this, mut ser| {
        ser.serialize_oauth_parameters();
        ser.serialize_parameter("qux", this.qux);
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct MultipleAfterOAuth[][] {
        qux: f64,
        quux: String = "quux".to_owned(),
    }
    |this, mut ser| {
        ser.serialize_oauth_parameters();
        ser.serialize_parameter("quux", &this.quux);
        ser.serialize_parameter("qux", this.qux);
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct Empty[][] {}
    |_this, mut ser| {
        ser.serialize_oauth_parameters();
        ser.end()
    }
}

// Just checking that this compiles.
#[derive(oauth::Request)]
struct Unsized {
    a: u64,
    c: u64,
    b: str,
}

assert_expand! {
    #[derive(oauth::Request)]
    struct TyParam[][T = u64] {
        t: T,
    }
    |this, mut ser| {
        ser.serialize_oauth_parameters();
        ser.serialize_parameter("t", &this.t);
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct Bound[][T: (AsRef<str>)] {
        t: T = "bound",
    }
    |this, mut ser| {
        ser.serialize_oauth_parameters();
        ser.serialize_parameter("t", this.t.as_ref());
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct Where[][T]
    where
        T: (AsRef<str>),
    {
        t: T = "where",
    }
    |this, mut ser| {
        ser.serialize_oauth_parameters();
        ser.serialize_parameter("t", this.t.as_ref());
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct Lifetime['a][] {
        a: &'a str,
    }
    |this, mut ser| {
        ser.serialize_parameter("a", &this.a);
        ser.serialize_oauth_parameters();
        ser.end()
    }
}

assert_expand! {
    #[derive(oauth::Request)]
    struct Attrs['a][T: ('static + std::fmt::Debug)] {
        #[oauth1(encoded)]
        percent_encoded: T = "%20",

        #[oauth1(rename = "FLAG")]
        flag: bool,

        #[oauth1()] // OK
        #[oauth1(skip)]
        _marker: [*const (); 0],

        #[oauth1(skip_if = std::option::Option::is_none, fmt = super::fmt_option_str)]
        some: std::option::Option<&'static str> = Some("option"),

        #[oauth1(option = true)]
        some_2: std::option::Option<&'static str> = Some("option"),

        #[oauth1(option = true)]
        none: std::option::Option<T> = None,

        #[oauth1(option = true, fmt = super::fmt_ignore)]
        option_fmt: std::option::Option<&'static str> = Some("option_fmt"),

        #[oauth1(option = false, fmt = super::fmt_ignore)]
        option_false: Option<()>,

        #[oauth1(skip_if = std::any::Any::is::<&'static str>)]
        #[oauth1(fmt = std::fmt::Debug::fmt)]
        trait_item: T,

        #[oauth1(skip_if = <[u8]>::is_empty)]
        #[oauth1(fmt = std::fmt::Debug::fmt)]
        qualified_path: &'static [u8],

        #[oauth1(skip_if = super::tautology, fmt = super::fmt_ignore)]
        ty_param: T,

        #[oauth1(skip_if = str::is_empty)]
        #[oauth1(fmt = super::fmt_str)]
        deref_arg: &'a Box<String> = &Box::new(String::new()),
    }
    |this, mut ser| {
        ser.serialize_parameter("FLAG", this.flag);
        ser.serialize_oauth_parameters();
        ser.serialize_parameter("option_false", "");
        ser.serialize_parameter("option_fmt", "");
        ser.serialize_parameter_encoded("percent_encoded", &this.percent_encoded);
        ser.serialize_parameter("some", "option");
        ser.serialize_parameter("some_2", "option");
        ser.end()
    }
}

// Just checking that this produces no warnings.
#[derive(oauth::Request)]
#[allow(nonstandard_style)]
struct non_camel_case {
    #[oauth1(skip_if = str::is_empty, fmt = std::fmt::Debug::fmt)]
    SHOUTING_SNAKE_CASE: Option<&'static str>,
}

#[derive(oauth::Request)]
struct WeirdAttrs {
    #[rustfmt::skip]
    #[oauth1(skip,)]
    _trailing_comma: (),
}

fn fmt_option_str(s: &Option<&str>, f: &mut Formatter<'_>) -> fmt::Result {
    if let Some(s) = s {
        Display::fmt(s, f)
    } else {
        Ok(())
    }
}

fn tautology<T>(_: &T) -> bool {
    true
}

fn fmt_ignore<T>(_: &T, _: &mut Formatter<'_>) -> fmt::Result {
    Ok(())
}

fn fmt_str(s: &str, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(s, f)
}
