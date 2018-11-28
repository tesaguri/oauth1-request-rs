#![feature(async_await, await_macro, futures_api)]

extern crate hyper;
extern crate oauth1_request as oauth;
extern crate tokio;

use std::str;

use hyper::header::AUTHORIZATION;
use hyper::{Client, Request, Uri};
use tokio::await;
use tokio::prelude::*;

fn main() {
    let uri = Uri::from_static("http://oauthbin.com/v1/echo");

    let mut signer = oauth::PlaintextSigner::new_form("POST", &uri, "secret", "accesssecret");
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

    tokio::run_async(
        async {
            let client = Client::new();
            let body = await!(await!(client.request(req)).unwrap().into_body().concat2()).unwrap();
            println!("{}", str::from_utf8(&body).unwrap());
        },
    );
}
