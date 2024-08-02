// https://github.com/tesaguri/oauth1-request-rs/pull/3

macro_rules! def_foo {
    ($t:ty) => {
        #[derive(oauth1_request_ios::Request)]
        pub struct Foo {
            field: $t,
        }
    };
}

def_foo!(Option<u64>);
