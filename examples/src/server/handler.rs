use std::borrow::Cow;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac, NewMac};
use http::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use http::uri::Authority;
use hyper::{Body, Request, Response, StatusCode};
use oauth_credentials::Credentials;
use percent_encoding::{percent_decode, percent_encode, AsciiSet};
use serde::Serialize;
use sha1::Sha1;

use crate::authorization;

const CLIENT: Credentials<&str> = Credentials {
    identifier: "client",
    secret: "client_secret",
};
const REQUEST: Credentials<&str> = Credentials {
    identifier: "request",
    secret: "request_secret",
};
const VERIFIER: &str = "verifier";
const TOKEN: Credentials<&str> = Credentials {
    identifier: "token",
    secret: "token_secret",
};

const SCHEME: &str = "http";
const AUTHORITY: &str = "127.0.0.1:8080";

/// Characters to be percent-encoded.
///
/// https://tools.ietf.org/html/rfc5849#section-3.6
const RESERVED: AsciiSet = percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

const APPLICATION_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

struct OAuthParams<'a> {
    consumer_key: &'a str,
    token: Option<&'a str>,
    signature_method: &'a str,
    timestamp: Option<u64>,
    nonce: Option<&'a str>,
    signature: &'a str,
    callback: Option<&'a str>,
    verifier: Option<&'a str>,
}

/// A tuple of key-value parameter.
type Parameter<'a> = (Cow<'a, str>, Cow<'a, str>);

pub async fn echo(req: Request<Body>) -> Response<Body> {
    verify_and_then(req, CLIENT, Some(TOKEN), None, |params, _| {
        let body = serde_urlencoded::to_string(params).unwrap();
        Response::builder()
            .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
            .body(Body::from(body))
            .unwrap()
    })
    .await
}

/// Returns a set of temporary credentials.
///
/// https://tools.ietf.org/html/rfc5849#section-2.1
pub async fn post_request_temp_credentials(req: Request<Body>) -> Response<Body> {
    #[derive(Serialize)]
    struct Token<'a> {
        #[serde(flatten)]
        credentials: Credentials<&'a str>,
        oauth_callback_confirmed: bool,
    }

    verify_and_then(req, CLIENT, None, None, |_, params| {
        match params.callback {
            // This example only accepts the "oob" callback.
            Some("oob") => {}
            Some(callback) => {
                info!("unexpected callback: {:?}", callback);
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::default())
                    .unwrap();
            }
            None => {
                info!("missing callback");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::default())
                    .unwrap();
            }
        }
        let body = serde_urlencoded::to_string(&Token {
            credentials: REQUEST,
            oauth_callback_confirmed: true,
        })
        .unwrap();
        Response::builder()
            .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
            .body(Body::from(body))
            .unwrap()
    })
    .await
}

/// Returns a set of token credentials.
///
/// https://tools.ietf.org/html/rfc5849#section-2.3
pub async fn post_request_token(req: Request<Body>) -> Response<Body> {
    verify_and_then(req, CLIENT, Some(REQUEST), Some(VERIFIER), |_, _| {
        let body = serde_urlencoded::to_string(&TOKEN).unwrap();
        Response::builder()
            .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
            .body(Body::from(body))
            .unwrap()
    })
    .await
}

/// Verifies the request against the provided credentials and calls `f` if successful.
async fn verify_and_then<F>(
    mut req: Request<Body>,
    client: Credentials<&str>,
    token: Option<Credentials<&str>>,
    verifier: Option<&str>,
    f: F,
) -> Response<Body>
where
    F: FnOnce(&[Parameter<'_>], OAuthParams<'_>) -> Response<Body>,
{
    let form = if req
        .headers()
        .get(CONTENT_TYPE)
        .map_or(false, |v| v == APPLICATION_WWW_FORM_URLENCODED)
    {
        hyper::body::to_bytes(&mut req).await.unwrap()
    } else {
        Default::default()
    };

    let params = if let Some(params) = collect_params(&req, &form) {
        params
    } else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::default())
            .unwrap();
    };

    let oauth_params = match collect_oauth_params(&params) {
        Ok(p) => p,
        Err(code) => {
            return Response::builder()
                .status(code)
                .body(Body::default())
                .unwrap();
        }
    };

    // Most of the verification process is separated to another function
    // to avoid monomorphization bloat.
    let ret = match inner(&req, &params, &oauth_params, client, token, verifier) {
        Ok(()) => f(&params, oauth_params),
        Err(code) => Response::builder()
            .status(code)
            .body(Body::default())
            .unwrap(),
    };

    return ret;

    fn inner(
        req: &Request<Body>,
        params: &[Parameter<'_>],
        oauth_params: &OAuthParams<'_>,
        client: Credentials<&str>,
        token: Option<Credentials<&str>>,
        verifier: Option<&str>,
    ) -> Result<(), StatusCode> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time went backwards")
            .as_secs();

        if let Some(t) = oauth_params.timestamp {
            if t + 30 < now {
                info!("timestamp is too old");
                return Err(StatusCode::UNAUTHORIZED);
            }
        }

        match (token, oauth_params.token) {
            // Do not check if the token matches the expected one before calculating the signature
            // in order to mitigate timing attacks.
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => {
                info!("missing `oauth_token`");
                return Err(StatusCode::UNAUTHORIZED);
            }
            (None, Some(t)) => {
                info!("unexpected token: {:?}", t);
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        match (verifier, oauth_params.verifier) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => {
                info!("missing `oauth_token`");
                return Err(StatusCode::UNAUTHORIZED);
            }
            (None, Some(v)) => {
                info!("unexpected verifier: {:?}", v);
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        match oauth_params.signature_method {
            "HMAC-SHA1" => {
                // Check that the nonce was provided, which is required by the spec,
                // but skip the verification of the nonce just for brevity of this example.
                if oauth_params.timestamp.is_none() || oauth_params.nonce.is_none() {
                    info!("missing `oauth_nonce`");
                    return Err(StatusCode::BAD_REQUEST);
                }

                const BUF_SIZE: usize = 21;
                const SIGN_LEN: usize = 20;

                let mut signature = [0; BUF_SIZE];
                if oauth_params.signature.len() > BUF_SIZE / 3 * 4 {
                    info!("signature too large: {:?}", oauth_params.signature);
                    return Err(StatusCode::BAD_REQUEST);
                }
                match base64::decode_config_slice(
                    oauth_params.signature,
                    base64::STANDARD,
                    &mut signature,
                ) {
                    Ok(SIGN_LEN) => {}
                    Ok(n) if n > SIGN_LEN => {
                        info!("signature too large: {:?}", oauth_params.signature);
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    Ok(n) if n < SIGN_LEN => {
                        info!("signature too short: {:?}", oauth_params.signature);
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    Ok(_) => unreachable!(),
                    Err(_) => {
                        info!("bad signature: {:?}", oauth_params.signature);
                        return Err(StatusCode::BAD_REQUEST);
                    }
                }
                let signature = &signature[..SIGN_LEN];

                let mut mac = {
                    let capacity = client.secret.len() + 1 + token.map_or(0, |t| t.secret.len());
                    let mut key = Vec::with_capacity(capacity);
                    key.extend(client.secret.as_bytes());
                    key.push(b'&');
                    if let Some(t) = token {
                        key.extend(t.secret.as_bytes());
                    }
                    Hmac::<Sha1>::new_varkey(&key).unwrap()
                };

                let base = create_base_string(&req, &params);
                trace!("signature base string: {:?}", base);

                mac.update(base.as_bytes());
                let code = mac.finalize().into_bytes();

                if *signature != *code {
                    info!(
                        "signature mismatch: expected {:?}, got {:?}",
                        code, signature
                    );
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
            "PLAINTEXT" => {
                use nom::bytes::complete::tag;
                use nom::combinator::eof;

                let parser = move |input| {
                    let (input, _) = tag::<_, _, ()>(client.secret)(input)?;
                    let (mut input, _) = tag("&")(input)?;
                    if let Some(token) = token {
                        input = tag(token.secret)(input)?.0;
                    }
                    eof(input)
                };

                if parser(oauth_params.signature).is_err() {
                    info!("signature mismatch: {:?}", oauth_params.signature);
                }
            }
            _ => {
                info!(
                    "unknown signature method: {:?}",
                    oauth_params.signature_method
                );
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        if client.identifier != oauth_params.consumer_key {
            info!("unknown client: {:?}", oauth_params.consumer_key);
            return Err(StatusCode::UNAUTHORIZED);
        }
        match (token, oauth_params.token) {
            (Some(token), Some(t)) if token.identifier != t => {
                info!("unknown token: {:?}", t);
                return Err(StatusCode::UNAUTHORIZED);
            }
            _ => {}
        }
        match (verifier, oauth_params.verifier) {
            (Some(verifier), Some(v)) if verifier != v => {
                info!("bad verifier: {:?}", v);
                return Err(StatusCode::UNAUTHORIZED);
            }
            _ => {}
        }

        Ok(())
    }
}

/// Collects form/query parameters into a vector.
fn collect_params<'a>(req: &'a Request<Body>, form: &'a [u8]) -> Option<Vec<Parameter<'a>>> {
    let query = req.uri().query().unwrap_or_default().as_bytes();

    let mut params = match collect_auth_params(&req.headers()) {
        Ok(params) => params,
        Err(v) => {
            info!("bad `Authorization` header: {:?}", v);
            return None;
        }
    };
    params.extend(form_urlencoded::parse(&form).chain(form_urlencoded::parse(&query)));
    params.sort_unstable();

    Some(params)
}

/// Collects `oauth_*` protocol parameters from an `Authorization` header.
fn collect_auth_params<'a>(headers: &'a HeaderMap) -> Result<Vec<Parameter<'a>>, &'a HeaderValue> {
    let mut ret = Vec::new();

    for v in headers.get_all(AUTHORIZATION) {
        if let Ok((auth_params, b"OAuth")) = authorization::auth_scheme(v.as_bytes()) {
            if auth_params.is_empty() {
                break;
            }
            if !auth_params.starts_with(b" ") {
                return Err(v);
            }

            let mut iter = authorization::hash(&auth_params[1..], authorization::auth_param);
            for (k, v) in &mut iter {
                let k = percent_decode(k).decode_utf8_lossy();
                let v = match v {
                    Cow::Borrowed(v) => percent_decode(v).decode_utf8_lossy(),
                    Cow::Owned(v) => match percent_decode(&v).decode_utf8_lossy() {
                        Cow::Borrowed(_) => String::from_utf8(v).unwrap().into(),
                        Cow::Owned(v) => v.into(),
                    },
                };
                ret.push((k, v));
            }

            match iter.finish() {
                Ok((b"", ())) => break,
                _ => return Err(v),
            }
        }
    }

    Ok(ret)
}

/// Collects the values of `oauth_*` parameters of form, query and `Authorization` header string.
///
/// This function assumes that `params` have been sorted in ascending order.
fn collect_oauth_params<'a>(params: &'a [Parameter<'a>]) -> Result<OAuthParams<'a>, StatusCode> {
    let i = params
        .binary_search_by_key(&"oauth_callback", |(k, _)| &**k)
        .unwrap_or_else(|i| i);

    let mut params = params[i..].iter().map(|&(ref k, ref v)| (&**k, &**v));

    /// Advances `params` past the `key` and gets the value of `key` if exists.
    fn get<'a, I>(params: &mut I, key: &str) -> Option<&'a str>
    where
        I: Iterator<Item = (&'a str, &'a str)> + Clone,
    {
        loop {
            match params.clone().next() {
                Some((k, v)) if k == key => {
                    params.next();
                    return Some(v);
                }
                Some((k, _)) if k > key => return None,
                Some(_) => {
                    params.next();
                }
                None => return None,
            }
        }
    }

    let callback = get(&mut params, "oauth_callback");
    let consumer_key = if let Some(v) = get(&mut params, "oauth_consumer_key") {
        v
    } else {
        info!("missing `oauth_consumer_key`");
        return Err(StatusCode::UNAUTHORIZED);
    };
    let nonce = get(&mut params, "oauth_nonce");
    let signature = if let Some(v) = get(&mut params, "oauth_signature") {
        v
    } else {
        info!("missing `oauth_signature");
        return Err(StatusCode::BAD_REQUEST);
    };
    let signature_method = if let Some(v) = get(&mut params, "oauth_signature_method") {
        v
    } else {
        info!("missing `oauth_signature_method`");
        return Err(StatusCode::BAD_REQUEST);
    };
    let timestamp = if let Some(v) = get(&mut params, "oauth_timestamp") {
        let v = if let Ok(v) = v.parse() {
            v
        } else {
            info!("invalid `oauth_timestamp`: {:?}", v);
            return Err(StatusCode::BAD_REQUEST);
        };
        Some(v)
    } else {
        None
    };
    let token = get(&mut params, "oauth_token");
    let verifier = get(&mut params, "oauth_verifier");

    Ok(OAuthParams {
        consumer_key,
        token,
        signature_method,
        timestamp,
        nonce,
        signature,
        callback,
        verifier,
    })
}

/// Creates a "signature base string", which is used as an input to the "HMAC-SHA1"
/// signature method.
///
/// https://tools.ietf.org/html/rfc5849#section-3.4.1
fn create_base_string(req: &Request<Body>, params: &[(Cow<'_, str>, Cow<'_, str>)]) -> String {
    let mut ret = String::new();

    let method = &*req.method().as_str().to_ascii_uppercase();
    write!(ret, "{}", percent_encode(method.as_bytes(), &RESERVED)).unwrap();
    ret.push('&');

    write!(ret, "{}", percent_encode(SCHEME.as_bytes(), &RESERVED)).unwrap();
    ret.push_str("%3A%2F%2F"); // "://"
    let authority = Authority::from_static(AUTHORITY);
    let authority = if let Some(port) = authority.port_u16() {
        let authority = authority.as_str();
        match (SCHEME, port) {
            ("http", 80) | ("https", 443) => authority.rfind(':').map(|i| &authority[..i]).unwrap(),
            _ => authority,
        }
    } else {
        authority.as_str()
    };
    write!(ret, "{}", percent_encode(authority.as_bytes(), &RESERVED)).unwrap();
    let path = req.uri().path().as_bytes();
    write!(ret, "{}", percent_encode(path, &RESERVED)).unwrap();
    ret.push('&');

    let mut first = true;
    for (k, v) in params {
        if k == "oauth_signature" {
            continue;
        }
        if first {
            first = false;
        } else {
            ret.push_str("%26"); // '&'
        }

        // `k` and `v` is required to be percent-encoded twice.
        let k: Cow<_> = percent_encode(k.as_bytes(), &RESERVED).into();
        write!(ret, "{}", percent_encode(k.as_bytes(), &RESERVED)).unwrap();
        ret.push_str("%3D"); // '='
        let v: Cow<_> = percent_encode(v.as_bytes(), &RESERVED).into();
        write!(ret, "{}", percent_encode(v.as_bytes(), &RESERVED)).unwrap();
    }

    ret
}
