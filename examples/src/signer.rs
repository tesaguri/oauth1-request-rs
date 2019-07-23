use std::str;

use futures::prelude::*;
use hyper::header::AUTHORIZATION;
use hyper::{Client, Request, Uri};

#[tokio::main]
async fn main() {
    let uri = Uri::from_static("http://oauthbin.com/v1/echo");

    let mut signer =
        oauth::signer::PlaintextSigner::new_form("POST", &uri, "secret", "accesssecret");
    signer.parameter("foo", "風");
    let mut signer = signer.oauth_parameters("key", &*oauth::Options::new().token("accesskey"));
    signer.parameter_encoded("qux", true);
    let oauth::Request {
        authorization,
        data,
    } = signer.finish();

    let req = Request::post(uri)
        .header(AUTHORIZATION, authorization)
        .body(data.into())
        .unwrap();

    let client = Client::new();
    let body = client
        .request(req)
        .await
        .unwrap()
        .into_body()
        .try_concat()
        .await
        .unwrap();
    println!("{}", str::from_utf8(&body).unwrap());
}
