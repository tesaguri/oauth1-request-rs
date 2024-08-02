#[derive(oauth1_request_ios::Request)]
struct Test {
    #[oauth1(fmt = missing_fmt)]
    missing_fmt: (),

    #[oauth1(skip_if = missing_skip_if)]
    missing_skip_if: u8,
}

fn main() {}
