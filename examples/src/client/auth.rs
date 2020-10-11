//! Functions to retrieve token credentials from the server.

use std::borrow::Borrow;
use std::fmt::Debug;

use bytes::Buf;
use futures::TryStreamExt;
use http::header::AUTHORIZATION;
use oauth_credentials::Credentials;
use tower_service::Service;

use crate::util::BodyExt;

// https://tools.ietf.org/html/rfc5849#section-2.1
#[derive(serde::Deserialize)]
struct TempCredentials {
    oauth_token: Box<str>,
    oauth_token_secret: Box<str>,
}

pub async fn temporary_credentials<T, S, B>(
    client: &Credentials<T>,
    callback: &str,
    http: S,
) -> Credentials<Box<str>>
where
    T: Borrow<str>,
    S: Service<http::Request<B>, Response = http::Response<B>>,
    S::Error: Debug,
    B: http_body::Body<Error = S::Error> + Default + From<Vec<u8>>,
{
    let uri = http::Uri::from_static("http://127.0.0.1:8080/request_temp_credentials");

    let authorization = oauth::Builder::<_, _>::new(client.as_ref(), oauth::HmacSha1)
        .callback(callback)
        .post(&uri, &());

    let body = send_request(uri, authorization, http).await;
    let res: TempCredentials = serde_urlencoded::from_bytes(&body).unwrap();

    Credentials {
        identifier: res.oauth_token,
        secret: res.oauth_token_secret,
    }
}

// https://tools.ietf.org/html/rfc5849#section-2.3
#[derive(serde::Deserialize)]
struct TokenCredentials {
    oauth_token: Box<str>,
    oauth_token_secret: Box<str>,
}

pub async fn token_credentials<C, T, S, B>(
    client: &Credentials<C>,
    temporary: &Credentials<T>,
    verifier: &str,
    http: S,
) -> Credentials<Box<str>>
where
    C: Borrow<str>,
    T: Borrow<str>,
    S: Service<http::Request<B>, Response = http::Response<B>>,
    S::Error: Debug,
    B: http_body::Body<Error = S::Error> + Default + From<Vec<u8>>,
{
    let uri = http::Uri::from_static("http://127.0.0.1:8080/request_token");

    let authorization = oauth::Builder::new(client.as_ref(), oauth::HmacSha1)
        .token(temporary.as_ref())
        .verifier(verifier)
        .post(&uri, &());

    let body = send_request(uri, authorization, http).await;
    let res: TokenCredentials = serde_urlencoded::from_bytes(&body).unwrap();

    Credentials {
        identifier: res.oauth_token,
        secret: res.oauth_token_secret,
    }
}

async fn send_request<S, B>(uri: http::Uri, authorization: String, mut http: S) -> Vec<u8>
where
    S: Service<http::Request<B>, Response = http::Response<B>>,
    S::Error: Debug,
    B: http_body::Body<Error = S::Error> + Default + From<Vec<u8>>,
{
    let req = http::Request::post(uri)
        .header(AUTHORIZATION, authorization)
        .body(B::default())
        .unwrap();

    let body = http.call(req).await.unwrap().into_body().into_stream();
    body.try_fold(Vec::new(), |mut acc, buf| {
        acc.extend(buf.bytes());
        async { Ok(acc) }
    })
    .await
    .unwrap()
}
