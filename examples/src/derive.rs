#![feature(async_await, await_macro, futures_api)]

extern crate bytes;
extern crate hyper;
extern crate oauth1_request as oauth;
extern crate oauth1_request_derive;
extern crate string;
extern crate tokio;

use bytes::Bytes;
use hyper::client::{Client, ResponseFuture};
use oauth1_request_derive::OAuth1Authorize;
use tokio::await;
use tokio::prelude::*;

macro_rules! def_requests {
    ($(
        $method:ident $uri:expr;
        pub struct $Name:ident[$($param:tt)*] {
            $($(#[$r_attr:meta])* $required:ident: $r_ty:ty),*;
            $($(#[$o_attr:meta])* $optional:ident: $o_ty:ty $(= $default:expr)*),* $(,)*
        }
    )*) => {$(
        #[derive(OAuth1Authorize)]
        pub struct $Name<$($param)*> {
            $($(#[$r_attr])* $required: $r_ty,)*
            $($(#[$o_attr])* $optional: $o_ty,)*
        }

        impl<$($param)*> $Name<$($param)*> {
            pub fn new($($required: $r_ty)*) -> Self {
                macro_rules! this_or_default {
                    ($value:expr) => ($value);
                    () => (Default::default());
                }
                $Name {
                    $($required,)*
                    $($optional: this_or_default!($($default)*),)*
                }
            }

            def_setters! {
                $($required: $r_ty,)*
                $($optional: $o_ty,)*
            }

            pub fn send<C, B>(
                &self,
                consumer_key: &str,
                consumer_secret: &str,
                token: &str,
                token_secret: &str,
                client: &::hyper::Client<C, B>,
            ) -> ::hyper::client::ResponseFuture
            where
                C: ::hyper::client::connect::Connect + Sync + 'static,
                C::Transport: 'static,
                C::Future: 'static,
                B: ::hyper::body::Payload + Default + From<Vec<u8>> + Send + 'static,
                B::Data: Send,
            {
                use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
                use hyper::{Method, Request, Uri};
                use oauth;

                let is_post = stringify!($method) == "POST";

                let oauth::Request {
                    authorization,
                    data,
                } = if is_post {
                    oauth::OAuth1Authorize::authorize_form
                } else {
                    oauth::OAuth1Authorize::authorize
                }(
                    self,
                    stringify!($method),
                    $uri,
                    consumer_key,
                    consumer_secret,
                    token_secret,
                    oauth::HmacSha1,
                    &*oauth::Options::new().token(token),
                );

                let mut req = Request::builder();
                req.method(Method::$method)
                    .header(AUTHORIZATION, authorization);

                let req = if is_post {
                    req.uri(Uri::from_static($uri))
                        .header(
                            CONTENT_TYPE,
                            HeaderValue::from_static("application/x-www-form-urlencoded"),
                        )
                        .body(data.into_bytes().into())
                        .unwrap()
                } else {
                    req.uri(data).body(Default::default()).unwrap()
                };

                client.request(req)
            }
        }
    )*};
}

macro_rules! def_setters {
    ($($name:ident: $ty:ty,)*) => {$(
        pub fn $name(&mut self, $name: $ty) -> &mut Self {
            self.$name = $name;
            self
        }
    )*};
}

def_requests! {
    GET "http://oauthbin.com/v1/echo";
    pub struct GetEcho['a] {
        text: &'a str;
        #[oauth1(skip_if = "str::is_empty")]
        note: &'a str,
    }

    POST "http://oauthbin.com/v1/echo";
    pub struct PostEcho['a] {
        text: &'a str;
        #[oauth1(skip_if = "str::is_empty")]
        note: &'a str,
    }
}

fn main() {
    tokio::run_async(
        async {
            let client = Client::new();
            let res1 =
                GetEcho::new("hello").send("key", "secret", "accesskey", "accesssecret", &client);
            let res2 = PostEcho::new("hello").note("world").send(
                "key",
                "secret",
                "accesskey",
                "accesssecret",
                &client,
            );
            println!("{}", await!(to_string(res1)));
            println!("{}", await!(to_string(res2)));
        },
    );
}

async fn to_string(res: ResponseFuture) -> string::String<Bytes> {
    let body = await!(await!(res).unwrap().into_body().concat2()).unwrap();
    string::TryFrom::try_from(Bytes::from(body)).unwrap()
}
