extern crate hyper;
extern crate oauth1_request;

use std::str;

use hyper::header::AUTHORIZATION;
use hyper::rt::{self, Future, Stream};
use hyper::{Client, Request, Uri};
use oauth1_request as oauth;

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
    let fut = Client::new()
        .request(req)
        .and_then(|res| res.into_body().concat2())
        .map(|body| {
            println!("{}", str::from_utf8(&body).unwrap());
        }).map_err(|e| panic!("{:?}", e));

    rt::run(fut);
}
