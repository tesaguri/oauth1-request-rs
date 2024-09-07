#![deny(warnings)]

extern crate oauth1_request as oauth;

#[macro_use]
mod common;

use std::fmt::{self, Display, Formatter};

use oauth::serializer::{Serializer, SerializerExt};

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
#[allow(dead_code)]
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
        ser.serialize_parameter("a", this.a);
        ser.serialize_oauth_parameters();
        ser.end()
    }
}

// Just checking that this compiles.
#[allow(dead_code)]
#[derive(oauth::Request)]
#[oauth1(crate = oauth)]
struct Crate {}

assert_expand! {
    #[derive(oauth::Request)]
    struct FieldAttrs['a][T: ('static + std::fmt::Debug)] {
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

        #[oauth1(option = true, fmt = crate::common::fmt_ignore)]
        option_fmt: std::option::Option<&'static str> = Some("option_fmt"),

        #[oauth1(option = false, fmt = crate::common::fmt_ignore)]
        option_false: Option<()>,

        #[oauth1(skip_if = <dyn std::any::Any>::is::<&'static str>)]
        #[oauth1(fmt = std::fmt::Debug::fmt)]
        trait_item: T,

        #[oauth1(skip_if = <[u8]>::is_empty)]
        #[oauth1(fmt = std::fmt::Debug::fmt)]
        qualified_path: &'static [u8],

        #[oauth1(skip_if = crate::common::always, fmt = crate::common::fmt_ignore)]
        ty_param: T,

        #[oauth1(skip_if = str::is_empty)]
        #[oauth1(fmt = crate::common::fmt_str)]
        #[allow(clippy::borrowed_box)]
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

// Just checking that these compile. They are tests for the code generation around the internal
// `DeriveRequestAssertion` struct which `fmt` and `skip_if` attributes share, checking that
// the attributes don't interfere with or depend on each other.
#[allow(dead_code)]
#[derive(oauth::Request)]
struct HasFmtAndSkipIf {
    #[oauth1(fmt = common::fmt_ignore)]
    fmt: (),
    #[oauth1(skip_if = common::always)]
    skip_if: u8,
}
#[allow(dead_code)]
#[derive(oauth::Request)]
struct HasFmtOnly {
    #[oauth1(fmt = common::fmt_ignore)]
    fmt: (),
}
#[allow(dead_code)]
#[derive(oauth::Request)]
struct HasSkipIfOnly {
    #[oauth1(skip_if = common::always)]
    skip_if: u8,
}

// Just checking that this compiles.
#[allow(dead_code)]
#[derive(oauth::Request)]
struct Hygiene {
    // The expanded code defines a binding named `helper`. This attribute should not refer to that.
    #[oauth1(fmt = helper)]
    should_not_conflict_with_helper_binding: (),
    // The expanded code defines a binding named `tmp` for each field. In order for the test to
    // make the fullest sense, the field's name should be after another field in alphabetical order.
    #[oauth1(fmt = tmp)]
    should_not_conflict_with_tmp_binding: (),
    // The expanded code defines `serializer` argument.
    #[oauth1(fmt = serializer)]
    should_not_conflict_with_serializer_arg: (),
}
#[allow(dead_code)]
fn helper(_: &(), _: &mut Formatter<'_>) -> fmt::Result {
    unimplemented!();
}
#[allow(dead_code)]
fn tmp(_: &(), _: &mut Formatter<'_>) -> fmt::Result {
    unimplemented!();
}
#[allow(dead_code)]
fn serializer(_: &(), _: &mut Formatter<'_>) -> fmt::Result {
    unimplemented!();
}

// Just checking that this produces no warnings.
#[allow(dead_code)]
#[derive(oauth::Request)]
#[allow(nonstandard_style)]
struct non_camel_case {
    #[oauth1(skip_if = str::is_empty, fmt = std::fmt::Debug::fmt)]
    SHOUTING_SNAKE_CASE: Option<&'static str>,
}

#[allow(dead_code)]
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
