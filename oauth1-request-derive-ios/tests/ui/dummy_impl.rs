#[derive(oauth1_request_ios::Request)]
struct Dummy {
    #[oauth1(unknown)]
    _field: (),
}

impl Dummy where Dummy: oauth1_request_ios::Request {} // OK

fn main() {}
