use futures::prelude::*;
use hyper::header::AUTHORIZATION;
use hyper::{Client, Request, Uri};

#[tokio::main]
async fn main() {
    let uri = Uri::from_static("http://oauthbin.com/v1/echo");

    let client = Client::new();

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

    let body = client
        .request(req)
        .await
        .unwrap()
        .into_body()
        .try_fold(Vec::new(), |mut vec, chunk| {
            vec.extend(&*chunk);
            async { Ok(vec) }
        })
        .await
        .unwrap();
    let body = String::from_utf8(body).unwrap();

    println!("{}", body);
}
