use std::fmt::{self, Formatter};

#[derive(oauth1_request_ios::Request)]
struct Test {
    not_display: (),

    #[oauth1(fmt = fmt_missing_arg)]
    fmt_missing_arg: (),

    #[oauth1(fmt = fmt_arg_not_ref)]
    fmt_arg_not_ref: (),

    #[oauth1(fmt = fmt_arg_mismatch)]
    fmt_arg_mismatch: (),

    #[oauth1(fmt = fmt_trait_bound_unsatisfied)]
    //~^ ERROR: the trait bound `(): AsRef<str>` is not satisfied
    //^ XXX: The error also appears at the call site.
    fmt_trait_bound_unsatisfied: (),

    #[oauth1(fmt = fmt_ret_mismatch)]
    fmt_ret_mismatch: (),

    #[oauth1(fmt = NOT_FN)]
    fmt_not_fn: (),

    #[oauth1(option = true)]
    option_not_option: u8,

    #[oauth1(skip_if = skip_if_too_many_args)]
    skip_if_too_many_args: u8,

    #[oauth1(skip_if = skip_if_arg_not_ref)]
    skip_if_arg_not_ref: u8,

    #[oauth1(skip_if = skip_if_arg_mismatch)]
    skip_if_arg_mismatch: u8,

    #[oauth1(skip_if = skip_if_trait_bound_unsatisfied)]
    // XXX: Same here.
    skip_if_trait_bound_unsatisfied: u8,

    #[oauth1(skip_if = skip_if_ret_mismatch)]
    skip_if_ret_mismatch: u8,

    #[oauth1(skip_if = NOT_FN)]
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
