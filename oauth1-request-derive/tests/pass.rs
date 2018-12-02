#![deny(warnings)]

extern crate oauth1_request as oauth;
#[macro_use]
extern crate oauth1_request_derive;

use std::fmt::{self, Display, Formatter};

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
            use oauth::signature_method::Identity;
            use oauth::{Options, Request, Signer, OAuth1Authorize};

            mod inner {
                // Shadow items imported via the prelude:
                #[allow(dead_code)]
                struct Option;
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
                $($ty_param: ::std::fmt::Display,)*
                $($($where_ty: $($where_bound)*,)*)*
            {
                fn expected(&self, signer: Signer<Identity>, ck: &str, opts: Option<&Options>)
                    -> Request
                {
                    let expand_to: fn(&Self, Signer<Identity>, _, _) -> _ = $expand_to;
                    expand_to(self, signer, ck, opts)
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

            let signer = Signer::<Identity>::new("GET", "https://example.com/get", "", None);
            let mut opts = Options::new();
            opts.nonce("nonce").timestamp(9999999999);
            let req = OAuth1Authorize::authorize_with(&x, signer.clone(), "", Some(&opts));
            let expected = x.expected(signer, "", Some(&opts));

            assert_eq!(req, expected);
        }
    };
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct OneBeforeOAuth[][] {
        foo: u64,
    }
    |this, mut signer, ck, opts| {
        signer.parameter("foo", this.foo);
        signer.finish(ck, opts)
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct MultipleBeforeOAuth[][] {
        foo: u64,
        bar: bool,
    }
    |this, mut signer, ck, opts| {
        signer.parameter("bar", this.bar);
        signer.parameter("foo", this.foo);
        signer.finish(ck, opts)
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct OneBeforeAndAfterOAuth[][] {
        baz: char,
        qux: f64,
    }
    |this, mut signer, ck, opts| {
        signer.parameter("baz", this.baz);
        let mut signer = signer.oauth_parameters(ck, opts);
        signer.parameter("qux", this.qux);
        signer.finish()
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct OneBeforeAndAfterOAuthRev[][] {
        qux: f64,
        baz: char,
    }
    |this, mut signer, ck, opts| {
        signer.parameter("baz", this.baz);
        let mut signer = signer.oauth_parameters(ck, opts);
        signer.parameter("qux", this.qux);
        signer.finish()
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct OneAfterOAuth[][] {
        qux: f64,
    }
    |this, signer, ck, opts| {
        let mut signer = signer.oauth_parameters(ck, opts);
        signer.parameter("qux", this.qux);
        signer.finish()
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct MultipleAfterOAuth[][] {
        qux: f64,
        quux: String = "quux".to_owned(),
    }
    |this, signer, ck, opts| {
        let mut signer = signer.oauth_parameters(ck, opts);
        signer.parameter("quux", &this.quux);
        signer.parameter("qux", this.qux);
        signer.finish()
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct Empty[][] {}
    |_this, signer, ck, opts| signer.finish(ck, opts)
}

// Just checking that this compiles.
#[derive(OAuth1Authorize)]
struct Unsized {
    a: u64,
    c: u64,
    b: str,
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct TyParam[][T = u64] {
        t: T,
    }
    |this, signer, ck, opts| {
        let mut signer = signer.oauth_parameters(ck, opts);
        signer.parameter("t", &this.t);
        signer.finish()
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct Bound[][T: (AsRef<str>)] {
        t: T = "bound",
    }
    |this, signer, ck, opts| {
        let mut signer = signer.oauth_parameters(ck, opts);
        signer.parameter("t", this.t.as_ref());
        signer.finish()
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct Where[][T]
    where
        T: (AsRef<str>),
    {
        t: T = "where",
    }
    |this, signer, ck, opts| {
        let mut signer = signer.oauth_parameters(ck, opts);
        signer.parameter("t", this.t.as_ref());
        signer.finish()
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct Lifetime['a][] {
        a: &'a str,
    }
    |this, mut signer, ck, opts| {
        signer.parameter("a", &this.a);
        signer.finish(ck, opts)
    }
}

assert_expand! {
    #[derive(OAuth1Authorize)]
    struct Attrs['a][T: ('static + ::std::fmt::Debug)] {
        #[oauth1(encoded)]
        percent_encoded: T = "%20",

        #[oauth1(rename = "FLAG")]
        flag: bool,

        #[oauth1()] // OK
        #[oauth1(skip)]
        _marker: [*const (); 0],

        #[oauth1(skip_if = "::std::option::Option::is_none", fmt = "super::fmt_option_str")]
        some: ::std::option::Option<&'static str> = Some("option"),

        #[oauth1(option)]
        some_2: ::std::option::Option<&'static str> = Some("option"),

        #[oauth1(option)]
        none: ::std::option::Option<T> = None,

        #[oauth1(option, fmt = "super::fmt_ignore")]
        option_fmt: ::std::option::Option<&'static str> = Some("option_fmt"),

        #[oauth1(skip_if = "::std::any::Any::is::<&'static str>")]
        #[oauth1(fmt = "::std::fmt::Debug::fmt")]
        trait_item: T,

        #[oauth1(skip_if = "super::tautology", fmt = "super::fmt_ignore")]
        ty_param: T,

        #[oauth1(skip_if = "str::is_empty")]
        #[oauth1(fmt = "super::fmt_str")]
        deref_arg: &'a Box<String> = &Box::new(String::new()),
    }
    |this, mut signer, ck, opts| {
        signer.parameter("FLAG", this.flag);
        let mut signer = signer.oauth_parameters(ck, opts);
        signer.parameter("option_fmt", "");
        signer.parameter_encoded("percent_encoded", &this.percent_encoded);
        signer.parameter("some", "option");
        signer.parameter("some_2", "option");
        signer.finish()
    }
}

// Just checking that this produces no warnings.
#[derive(OAuth1Authorize)]
#[allow(nonstandard_style)]
struct non_camel_case {
    #[oauth1(skip_if = "Option::is_none", fmt = "::std::fmt::Debug::fmt")]
    SHOUTING_SNAKE_CASE: Option<&'static str>,
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
