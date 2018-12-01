#[macro_use]
extern crate oauth1_request_derive;

use std::fmt::{self, Formatter};

#[derive(OAuth1Authorize)]
//~^ ERROR: mismatched types
//~| expected u8, found ()
//~^^^ ERROR: mismatched types
//~| expected (), found u8
// FIXME: move these errors to (1) and (2) respectively
struct Test {
    not_display: (),
    //~^ ERROR: `()` doesn't implement `std::fmt::Display`

    #[oauth1(fmt = "fmt_missing_arg")]
    //~^ ERROR: mismatched types
    //~| incorrect number of function parameters
    fmt_missing_arg: (),

    #[oauth1(fmt = "fmt_arg_not_ref")]
    //~^ ERROR: mismatched types
    //~| expected reference, found ()
    fmt_arg_not_ref: (),

    #[oauth1(fmt = "fmt_arg_mismatch")]
    //^ (1)
    fmt_arg_mismatch: (),

    #[oauth1(fmt = "fmt_trait_bound_unsatisfied")]
    //~^ ERROR: the trait bound `(): std::convert::AsRef<str>` is not satisfied
    fmt_trait_bound_unsatisfied: (),

    #[oauth1(fmt = "fmt_ret_mismatch")]
    //~^ ERROR: mismatched types
    //~| expected struct `std::fmt::Error`, found ()
    fmt_ret_mismatch: (),

    #[oauth1(fmt = "NOT_FN")]
    //~^ ERROR: mismatched types
    //~| expected fn pointer, found ()
    fmt_not_fn: (),

    #[oauth1(option)]
    option_not_option: u8,
    //~^ ERROR: mismatched types
    //~| expected enum `std::option::Option`, found u8

    #[oauth1(skip_if = "skip_if_too_many_args")]
    //~^ ERROR: mismatched types
    //~| incorrect number of function parameters
    skip_if_too_many_args: u8,

    #[oauth1(skip_if = "skip_if_arg_not_ref")]
    //~^ ERROR: mismatched types
    //~| expected reference, found u8
    skip_if_arg_not_ref: u8,

    #[oauth1(skip_if = "skip_if_arg_mismatch")]
    //^ (2)
    skip_if_arg_mismatch: u8,

    #[oauth1(skip_if = "skip_if_trait_bound_unsatisfied")]
    //~^ ERROR: the trait bound `u8: std::convert::AsRef<str>` is not satisfied
    skip_if_trait_bound_unsatisfied: u8,

    #[oauth1(skip_if = "skip_if_ret_mismatch")]
    //~^ ERROR: mismatched types
    //~| expected bool, found enum `std::option::Option`
    skip_if_ret_mismatch: u8,

    #[oauth1(skip_if = "NOT_FN")]
    //~^ ERROR: mismatched types
    //~| expected fn pointer, found ()
    skip_if_not_fn: u8,
}

const NOT_FN: () = ();

fn fmt_missing_arg(_: &()) -> fmt::Result {
    Ok(())
}

fn fmt_arg_not_ref(_: (), _: &mut Formatter<'_>) -> fmt::Result {
    Ok(())
}

fn fmt_arg_mismatch(_: &u8, _: &mut Formatter<'_>) -> fmt::Result {
    Ok(())
}

fn fmt_trait_bound_unsatisfied<T: AsRef<str>>(_: &T, _: &mut Formatter<'_>) -> fmt::Result {
    Ok(())
}

fn fmt_ret_mismatch(_: &(), _: &mut Formatter<'_>) -> Result<(), ()> {
    Ok(())
}

fn skip_if_too_many_args(_: &u8, _: ()) -> bool {
    false
}

fn skip_if_arg_not_ref(_: u8) -> bool {
    false
}

fn skip_if_arg_mismatch(_: &()) -> bool {
    false
}

fn skip_if_trait_bound_unsatisfied<T: AsRef<str>>(_: &T) -> bool {
    false
}

fn skip_if_ret_mismatch(_: &u8) -> Option<()> {
    None
}

fn main() {}
