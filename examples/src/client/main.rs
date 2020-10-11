mod auth;
#[macro_use]
mod request;
mod util;

use futures::prelude::*;
use hyper::client::{Client, ResponseFuture};
use oauth_credentials::{Credentials, Token};

request! {
    GET "http://127.0.0.1:8080/echo";
    #[derive(oauth::Request)]
    pub struct GetEcho['a] {
        foo: &'a str,
    }

    POST "http://127.0.0.1:8080/echo";
    #[derive(oauth::Request)]
    pub struct PostEcho['a] {
        bar: &'a str,
        baz: &'a str,
    }
}

const CLIENT: Credentials<&str> = Credentials {
    identifier: "client",
    secret: "client_secret",
};

#[tokio::main]
async fn main() {
    let http = Client::new();

    let temporary_credentials = auth::temporary_credentials(&CLIENT, "oob", &http).await;

    let verifier = "verifier";

    let token = auth::token_credentials(&CLIENT, &temporary_credentials, verifier, &http).await;
    let token = Token::new(CLIENT, token);

    let res1 = GetEcho { foo: "GET" }.send(&token, &http);
    let res2 = PostEcho {
        bar: "POST",
        baz: "ＰＯＳＴ",
    }
    .send(&token, &http);

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
