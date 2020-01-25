//! Yet yet yet another OAuth 1 client library.
//!
//! # Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! oauth = { version = "0.3", package = "oauth1-request" }
//! ```
//!
//! For brevity, we refer to the crate name as `oauth` throughout the documentation,
//! since the API is designed in favor of qualified paths like `oauth::get`.
//!
//! ## Create a request
//!
//! A typical authorization flow looks like this:
//!
//! ```
//! # extern crate oauth1_request as oauth;
//! #
//! // Define a type to represent your request.
//! #[derive(oauth::Request)]
//! struct CreateComment<'a> {
//!     article_id: u64,
//!     text: &'a str,
//! }
//!
//! let uri = "https://example.com/api/v1/comments/create.json";
//!
//! let request = CreateComment {
//!     article_id: 123456789,
//!     text: "A request signed with OAuth & Rust 🦀 🔏",
//! };
//!
//! // Prepare your credentials.
//! let client = oauth::Credentials::new("consumer_key", "consumer_secret");
//! let token = oauth::Credentials::new("token", "token_secret");
//!
//! // Create the `Authorization` header.
//! let authorization_header = oauth::post(oauth::HmacSha1, uri, &client, Some(&token), &request);
//! # // Override the above value to pin the nonce and timestamp value.
//! # let mut builder = oauth::Builder::new(client, oauth::HmacSha1);
//! # builder.token(token);
//! # builder.nonce("Dk-OGluFEQ4f").timestamp(std::num::NonZeroU64::new(1234567890));
//! # let authorization_header = builder.post(uri, &request);
//! // `oauth_nonce` and `oauth_timestamp` vary on each execution.
//! assert_eq!(
//!     authorization_header,
//!     "OAuth \
//!          oauth_consumer_key=\"consumer_key\",\
//!          oauth_nonce=\"Dk-OGluFEQ4f\",\
//!          oauth_signature_method=\"HMAC-SHA1\",\
//!          oauth_timestamp=\"1234567890\",\
//!          oauth_token=\"token\",\
//!          oauth_signature=\"n%2FrUgos4CFFZbZK8Z8wFR7drU4c%3D\"",
//! );
//!
//! // You can create an `x-www-form-urlencoded` string or a URI with query pairs from the request.
//!
//! let form = oauth::to_form_urlencoded(&request);
//! assert_eq!(
//!     form,
//!     "article_id=123456789&text=A%20request%20signed%20with%20OAuth%20%26%20Rust%20%F0%9F%A6%80%20%F0%9F%94%8F",
//! );
//!
//! let uri = oauth::to_uri_query(uri.to_owned(), &request);
//! assert_eq!(
//!     uri,
//!     "https://example.com/api/v1/comments/create.json?article_id=123456789&text=A%20request%20signed%20with%20OAuth%20%26%20Rust%20%F0%9F%A6%80%20%F0%9F%94%8F",
//! );
//! ```
//!
//! Use [`oauth::Builder`][Builder] if you need to specify a callback URI or verifier:
//!
//! ```rust
//! # extern crate oauth1_request as oauth;
//! #
//! let uri = "https://example.com/oauth/request_temp_credentials";
//! let callback = "https://client.example.net/oauth/callback";
//! #
//! # let client = oauth::Credentials::new("consumer_key", "consumer_secret");
//!
//! let authorization_header = oauth::Builder::<_, _>::new(client, oauth::HmacSha1)
//!     .callback(callback)
//!     .post(uri, &());
//! ```
//!
//! See [`Request`][oauth1_request_derive::Request] for more details on the derive macro.

#![doc(html_root_url = "https://docs.rs/oauth1-request/0.3.2")]
#![deny(broken_intra_doc_links)]
#![warn(missing_docs, rust_2018_idioms)]

#[macro_use]
mod util;

pub mod serializer;
pub mod signature_method;

mod request;

#[cfg(feature = "derive")]
#[doc(inline)]
pub use oauth1_request_derive::Request;
#[doc(no_inline)]
pub use oauth_credentials::Credentials;

pub use request::Request;
#[cfg(feature = "hmac-sha1")]
pub use signature_method::HmacSha1;
pub use signature_method::Plaintext;

use std::borrow::Borrow;
use std::fmt::{Debug, Display};
use std::num::NonZeroU64;
use std::str;

use serializer::auth::{self, Authorizer};
use serializer::Urlencoder;
use signature_method::SignatureMethod;

/// A builder for OAuth `Authorization` header string.
#[derive(Clone, Debug)]
pub struct Builder<'a, SM, C = String, T = C> {
    signature_method: SM,
    client: Credentials<C>,
    token: Option<Credentials<T>>,
    options: auth::Options<'a>,
}

impl<'a, SM: SignatureMethod, C: Borrow<str>, T: Borrow<str>> Builder<'a, SM, C, T> {
    /// Creates a `Builder` that signs requests using the specified client credentials
    /// and signature method.
    pub fn new(client: Credentials<C>, signature_method: SM) -> Self {
        Builder {
            signature_method,
            client,
            token: None,
            options: auth::Options::new(),
        }
    }

    /// Sets/unsets the token credentials pair to sign requests with.
    pub fn token(&mut self, token: impl Into<Option<Credentials<T>>>) -> &mut Self {
        self.token = token.into();
        self
    }

    /// Sets/unsets the `oauth_callback` URI.
    pub fn callback(&mut self, callback: impl Into<Option<&'a str>>) -> &mut Self {
        self.options.callback(callback);
        self
    }

    /// Sets/unsets the `oauth_verifier` value.
    pub fn verifier(&mut self, verifier: impl Into<Option<&'a str>>) -> &mut Self {
        self.options.verifier(verifier);
        self
    }

    /// Sets/unsets the `oauth_nonce` value.
    ///
    /// By default, `Builder` generates a random nonce for each request.
    /// This method overrides that behavior and forces the `Builder` to use the specified nonce.
    ///
    /// This method is for debugging/testing purpose only and should not be used in production.
    pub fn nonce(&mut self, nonce: impl Into<Option<&'a str>>) -> &mut Self {
        self.options.nonce(nonce);
        self
    }

    /// Sets/unsets the `oauth_timestamp` value.
    ///
    /// By default, `Builder` uses the timestamp of the time when `build`(-like) method is called.
    /// This method overrides that behavior and forces the `Builder` to use the specified timestamp.
    ///
    /// This method is for debugging/testing purpose only and should not be used in production.
    pub fn timestamp(&mut self, timestamp: impl Into<Option<NonZeroU64>>) -> &mut Self {
        self.options.timestamp(timestamp);
        self
    }

    /// Sets whether to include the `oauth_version` value in requests.
    pub fn version(&mut self, version: bool) -> &mut Self {
        self.options.version(version);
        self
    }

    /// Authorizes a `GET` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn get<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("GET", uri, request)
    }

    /// Authorizes a `PUT` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn put<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("PUT", uri, request)
    }

    /// Authorizes a `POST` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn post<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("POST", uri, request)
    }

    /// Authorizes a `DELETE` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn delete<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("DELETE", uri, request)
    }

    /// Authorizes an `OPTIONS` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn options<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("OPTIONS", uri, request)
    }

    /// Authorizes a `HEAD` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn head<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("HEAD", uri, request)
    }

    /// Authorizes a `CONNECT` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn connect<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("CONNECT", uri, request)
    }

    /// Authorizes a `PATCH` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn patch<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("PATCH", uri, request)
    }

    /// Authorizes a `TRACE` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn trace<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("TRACE", uri, request)
    }

    /// Authorizes a request to `uri` with a custom HTTP request method.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn build<U: Display, R: Request + ?Sized>(
        &self,
        method: &str,
        uri: U,
        request: &R,
    ) -> String
    where
        SM: Clone,
    {
        let serializer = Authorizer::with_signature_method(
            self.signature_method.clone(),
            method,
            uri,
            self.client.as_ref(),
            self.token.as_ref().map(Credentials::as_ref),
            &self.options,
        );

        request.serialize(serializer)
    }

    /// Authorizes a request and consumes `self`.
    ///
    /// This may be more efficient than `build` if the signature method holds a non-`Copy` data
    /// (e.g. RSA private key). However, the cost is the same as `build` for the signature methods
    /// bundled with this library (`HmacSha1` and `Plaintext`).
    pub fn consume<U: Display, R: Request + ?Sized>(
        self,
        method: &str,
        uri: U,
        request: &R,
    ) -> String {
        let serializer = Authorizer::with_signature_method(
            self.signature_method,
            method,
            uri,
            self.client.as_ref(),
            self.token.as_ref().map(Credentials::as_ref),
            &self.options,
        );

        request.serialize(serializer)
    }
}

macro_rules! def_shorthand {
    ($($(#[$attr:meta])* $name:ident($method:expr);)*) => {$(
        $(#[$attr])*
        pub fn $name<SM, U, C, T, R>(
            signature_method: SM,
            uri: U,
            client: &Credentials<C>,
            token: Option<&Credentials<T>>,
            request: &R,
        ) -> String
        where
            SM: SignatureMethod,
            U: Display,
            C: Borrow<str>,
            T: Borrow<str>,
            R: Request + ?Sized,
        {
            let mut builder = Builder::new(client.as_ref(), signature_method);
            builder.token(token.map(Credentials::as_ref));
            builder.consume($method, uri, request)
        }
    )*};
}

def_shorthand! {
    /// Authorizes a `GET` request to `uri` using the given credentials.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    get("GET");

    /// Authorizes a `PUT` request to `uri` using the given credentials.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    put("PUT");

    /// Authorizes a `POST` request to `uri` using the given credentials.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    post("POST");

    /// Authorizes a `DELETE` request to `uri` using the given credentials.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    delete("DELETE");

    /// Authorizes an `OPTIONS` request to `uri` using the given credentials.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    options("OPTIONS");

    /// Authorizes a `HEAD` request to `uri` using the given credentials.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    head("HEAD");

    /// Authorizes a `CONNECT` request to `uri` using the given credentials.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    connect("CONNECT");

    /// Authorizes a `PATCH` request to `uri` using the given credentials.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    patch("PATCH");

    /// Authorizes a `TRACE` request to `uri` using the given credentials.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    trace("TRACE");
}

/// Turns a `Request` into an `x-www-form-urlencoded` string.
pub fn to_form_urlencoded<R>(request: &R) -> String
where
    R: Request + ?Sized,
{
    request.serialize(Urlencoder::form())
}

/// Turns a `Request` to a query string and appends it to the given URI.
///
/// This function naively concatenates a query string to `uri` and if `uri` already has
/// a query part, it will have a duplicate query part like `?foo=bar?baz=qux`.
pub fn to_uri_query<R>(uri: String, request: &R) -> String
where
    R: Request + ?Sized,
{
    request.serialize(Urlencoder::query(uri))
}
