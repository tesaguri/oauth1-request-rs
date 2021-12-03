#[derive(oauth1_request::Request)]
struct Dummy {
    #[oauth1(unknown)]
    _field: (),
}

impl Dummy where Dummy: oauth1_request::Request {} // OK

fn main() {}
