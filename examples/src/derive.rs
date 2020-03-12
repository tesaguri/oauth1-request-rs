use futures::prelude::*;
use hyper::client::{Client, ResponseFuture};

macro_rules! def_requests {
    ($(
        $method:ident $uri:expr;
        pub struct $Name:ident[$($param:tt)*] {
            $($(#[$r_attr:meta])* $required:ident: $r_ty:ty),*;
            $($(#[$o_attr:meta])* $optional:ident: $o_ty:ty $(= $default:expr)*),* $(,)*
        }
    )*) => {$(
        #[derive(oauth::Authorize)]
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

            pub fn send<T, S, B>(
                &self,
                client: &oauth::Credentials<T>,
                token: &oauth::Credentials<T>,
                http: S,
            ) -> S::Future
            where
                T: std::borrow::Borrow<str>,
                S: tower_service::Service<http::Request<B>>,
                B: Default + From<Vec<u8>>,
            {
                send_request(
                    http::Method::$method,
                    &http::Uri::from_static($uri),
                    self,
                    client.as_ref(),
                    token.as_ref(),
                    http,
                )
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

    let mut http = Client::new();

    let res1 = GetEcho::new("hello").send(&client, &token, &mut http);
    let res2 = PostEcho::new("hello")
        .note("world")
        .send(&client, &token, &mut http);

    let (res1, res2) = future::join(to_string(res1), to_string(res2)).await;
    println!("{}", res1);
    println!("{}", res2);
}

async fn to_string(res: ResponseFuture) -> String {
    let body = res
        .await
        .unwrap()
        .into_body()
        .try_fold(Vec::new(), |mut vec, chunk| {
            vec.extend(&*chunk);
            async { Ok(vec) }
        })
        .await
        .unwrap();
    String::from_utf8(body).unwrap()
}

fn send_request<A: oauth::Authorize, S, B>(
    method: http::Method,
    uri: &http::Uri,
    request: A,
    client: oauth::Credentials<&str>,
    token: oauth::Credentials<&str>,
    mut http: S,
) -> S::Future
where
    S: tower_service::Service<http::Request<B>>,
    B: Default + From<Vec<u8>>,
{
    use http::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};

    let is_post = method == http::Method::POST;

    let mut builder = oauth::Builder::new(client, oauth::HmacSha1);
    builder.token(token);

    let oauth::Request {
        authorization,
        data,
    } = if is_post {
        builder.build_form(method.as_str(), uri, request)
    } else {
        builder.build(method.as_str(), uri, request)
    };

    let req = http::Request::builder()
        .method(method)
        .header(AUTHORIZATION, authorization);

    let req = if is_post {
        req.uri(uri)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(data.into_bytes().into())
            .unwrap()
    } else {
        req.uri(data).body(Default::default()).unwrap()
    };

    http.call(req)
}
