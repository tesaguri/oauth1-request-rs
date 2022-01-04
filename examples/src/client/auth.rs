//! Functions to retrieve token credentials from the server.

use std::fmt::Debug;

use bytes::Bytes;
use http::header::AUTHORIZATION;
use oauth_credentials::Credentials;
use tower_service::Service;

pub async fn temporary_credentials<T, S, B>(
    client: &Credentials<T>,
    callback: &str,
    http: S,
) -> Credentials<Box<str>>
where
    T: AsRef<str>,
    S: Service<http::Request<B>, Response = http::Response<B>>,
    S::Error: Debug,
    B: http_body::Body<Error = S::Error> + Default + From<Vec<u8>>,
{
    let uri = http::Uri::from_static("http://127.0.0.1:8080/request_temp_credentials");
    let authorization = oauth::Builder::<_, _>::new(client.as_ref(), oauth::HmacSha1::new())
        .callback(callback)
        .post(&uri, &());
    let body = send_request(uri, authorization, http).await;

    serde_urlencoded::from_bytes(&body).unwrap()
}

pub async fn token_credentials<C, T, S, B>(
    client: &Credentials<C>,
    temporary: &Credentials<T>,
    verifier: &str,
    http: S,
) -> Credentials<Box<str>>
where
    C: AsRef<str>,
    T: AsRef<str>,
    S: Service<http::Request<B>, Response = http::Response<B>>,
    S::Error: Debug,
    B: http_body::Body<Error = S::Error> + Default + From<Vec<u8>>,
{
    let uri = http::Uri::from_static("http://127.0.0.1:8080/request_token");
    let authorization = oauth::Builder::new(client.as_ref(), oauth::HmacSha1::new())
        .token(temporary.as_ref())
        .verifier(verifier)
        .post(&uri, &());
    let body = send_request(uri, authorization, http).await;

    serde_urlencoded::from_bytes(&body).unwrap()
}

async fn send_request<S, B>(uri: http::Uri, authorization: String, mut http: S) -> Bytes
where
    S: Service<http::Request<B>, Response = http::Response<B>>,
    S::Error: Debug,
    B: http_body::Body<Error = S::Error> + Default,
{
    let req = http::Request::post(uri)
        .header(AUTHORIZATION, authorization)
        .body(B::default())
        .unwrap();
    hyper::body::to_bytes(http.call(req).await.unwrap())
        .await
        .unwrap()
}
