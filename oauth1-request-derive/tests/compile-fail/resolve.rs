#[macro_use]
extern crate oauth1_request_derive;

#[derive(OAuth1Authorize)]
struct Test {
    #[oauth1(fmt = "missing_fmt")]
    //~^ ERROR: cannot find value `missing_fmt` in this scope
    missing_fmt: (),
    #[oauth1(skip_if = "missing_skip_if")]
    //~^ ERROR: cannot find value `missing_skip_if` in this scope
    missing_skip_if: u8,
}
