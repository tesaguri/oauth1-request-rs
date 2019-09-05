use bytes::Bytes;
use futures::prelude::*;
use hyper::client::{Client, ResponseFuture};
use oauth1_request_derive::OAuth1Authorize;

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

            pub fn send<T, C, B>(
                &self,
                client: &oauth::Credentials<T>,
                token: &oauth::Credentials<T>,
                http: &hyper::Client<C, B>,
            ) -> hyper::client::ResponseFuture
            where
                T: std::borrow::Borrow<str>,
                C: hyper::client::connect::Connect + Sync + 'static,
                C::Transport: 'static,
                C::Future: 'static,
                B: hyper::body::Payload + Default + From<Vec<u8>> + std::marker::Unpin + Send + 'static,
                B::Data: std::marker::Unpin + Send,
            {
                use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
                use hyper::{Method, Request, Uri};
                use oauth;

                let is_post = stringify!($method) == "POST";

                let mut builder = oauth::Builder::new(client.as_ref(), oauth::HmacSha1);
                builder.token(token.as_ref());

                let oauth::Request {
                    authorization,
                    data,
                } = if is_post {
                    builder.build_form(stringify!($method), $uri, self)
                } else {
                    builder.build(stringify!($method), $uri, self)
                };

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

                http.request(req)
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
    GET "http://term.ie/oauth/example/echo_api.php";
    pub struct GetEcho['a] {
        text: &'a str;
        #[oauth1(skip_if = "str::is_empty")]
        note: &'a str,
    }

    POST "http://term.ie/oauth/example/echo_api.php";
    pub struct PostEcho['a] {
        text: &'a str;
        #[oauth1(skip_if = "str::is_empty")]
        note: &'a str,
    }
}

#[tokio::main]
async fn main() {
    let client = oauth::Credentials::new("key", "secret");
    let token = oauth::Credentials::new("accesskey", "accesssecret");

    let http = Client::new();

    let res1 = GetEcho::new("hello").send(&client, &token, &http);
    let res2 = PostEcho::new("hello")
        .note("world")
        .send(&client, &token, &http);

    let (res1, res2) = future::join(to_string(res1), to_string(res2)).await;
    println!("{}", res1);
    println!("{}", res2);
}

async fn to_string(res: ResponseFuture) -> string::String<Bytes> {
    let body = res.await.unwrap().into_body().try_concat().await.unwrap();
    string::TryFrom::try_from(Bytes::from(body)).unwrap()
}
