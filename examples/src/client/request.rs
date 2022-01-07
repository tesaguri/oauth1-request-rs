use http::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use oauth_credentials::Token;
use tower_service::Service;

/// Defines a struct and associete it with a request method and URI of an API endpoint.
macro_rules! request {
    ($(
        $method:ident $uri:expr;
        $(#[$attr:meta])*
        pub struct $Name:ident $([$($param:tt)*])? {
            $($field:tt)*
        }
    )*) => {$(
        $(#[$attr])*
        pub struct $Name $(<$($param)*>)? {
            $($field)*
        }

        impl $(<$($param)*>)? $Name $(<$($param)*>)? {
            pub fn send<C, T, S, B>(
                &self,
                token: &oauth_credentials::Token<C, T>,
                http: S,
            ) -> S::Future
            where
                C: AsRef<str>,
                T: AsRef<str>,
                S: tower_service::Service<http::Request<B>>,
                B: Default + From<Vec<u8>>,
            {
                $crate::request::SendRequest::send(self, token, http)
            }
        }

        impl $(<$($param)*>)? $crate::request::SendRequest for $Name $(<$($param)*>)? {
            const METHOD: http::Method = http::Method::$method;
            const URI: &'static str = $uri;
        }
    )*};
}

/// Convenience trait to make an OAuth-authenticated request to an API endpoint.
/// Implemented by the `request!` macro.
pub trait SendRequest: oauth::Request {
    const METHOD: http::Method;
    const URI: &'static str;

    fn send<C, T, S, B>(&self, token: &Token<C, T>, http: S) -> S::Future
    where
        C: AsRef<str>,
        T: AsRef<str>,
        S: Service<http::Request<B>>,
        B: Default + From<Vec<u8>>,
    {
        send::<Self, _, _, _>(self, token.as_ref(), http)
    }
}

fn send<SR, R, S, B>(request: R, token: Token<&str, &str>, mut http: S) -> S::Future
where
    SR: SendRequest + ?Sized,
    R: oauth::Request,
    S: Service<http::Request<B>>,
    B: Default + From<Vec<u8>>,
{
    let uri = http::Uri::from_static(SR::URI);

    let mut builder = oauth::Builder::new(token.client, oauth::HmacSha1::new());
    builder.token(token.token);

    let authorization = builder.authorize(SR::METHOD.as_str(), SR::URI, &request);

    let is_post = SR::METHOD == http::Method::POST;
    let req = http::Request::builder()
        .method(SR::METHOD)
        .header(AUTHORIZATION, authorization);

    let req = if is_post {
        let x_www_form_urlencoded = HeaderValue::from_static("application/x-www-form-urlencoded");
        let data = oauth::to_form_urlencoded(&request).into_bytes();
        req.uri(uri)
            .header(CONTENT_TYPE, x_www_form_urlencoded)
            .body(data.into())
            .unwrap()
    } else {
        let uri = oauth::to_uri_query(SR::URI.to_owned(), &request);
        req.uri(uri).body(Default::default()).unwrap()
    };

    http.call(req)
}
