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
//! For brevity we refer to the crate name as `oauth` throughout the documentation.
//
//! ## Create a `GET` request
//!
//! ```rust
//! # extern crate oauth1_request as oauth;
//! #[derive(oauth::Authorize)]
//! struct SearchComments<'a> {
//!     article_id: u64,
//!     text: &'a str,
//! }
//!
//! # fn main() {
//! let client = oauth::Credentials::new("consumer_key", "consumer_secret");
//! let token = oauth::Credentials::new("token", "token_secret");
//!
//! let mut builder = oauth::Builder::new(client, oauth::HmacSha1);
//! builder
//!     .token(token)
//!     .nonce("nonce")
//!     .timestamp(9999999999);
//!
//! let req = SearchComments {
//!     article_id: 123456789,
//!     text: "Rust",
//! };
//!
//! let oauth::Request {
//!     authorization,
//!     data,
//! } = builder.get("https://example.com/api/v1/comments/search.json", &req);
//!
//! assert_eq!(
//!     authorization,
//!     "OAuth \
//!          oauth_consumer_key=\"consumer_key\",\
//!          oauth_nonce=\"nonce\",\
//!          oauth_signature_method=\"HMAC-SHA1\",\
//!          oauth_timestamp=\"9999999999\",\
//!          oauth_token=\"token\",\
//!          oauth_signature=\"kAkbCLL7obDyzdjz3uJoWSwiLqU%3D\"",
//! );
//! assert_eq!(
//!     data,
//!     "https://example.com/api/v1/comments/search.json?article_id=123456789&text=Rust",
//! );
//! # }
//! ```
//!
//! ## Create an `x-www-form-urlencoded` request
//!
//! ```rust
//! # extern crate oauth1_request as oauth;
//! #[derive(oauth::Authorize)]
//! struct CreateComment<'a> {
//!     article_id: u64,
//!     text: &'a str,
//! }
//!
//! # fn main() {
//! # let client = oauth::Credentials::new("consumer_key", "consumer_secret");
//! # let token = oauth::Credentials::new("token", "token_secret");
//! # let mut builder = oauth::Builder::new(client, oauth::HmacSha1);
//! # builder
//! #     .token(token)
//! #     .nonce("nonce")
//! #     .timestamp(9999999999);
//! let req = CreateComment {
//!     article_id: 123456789,
//!     text: "Rust lang is great 🦀",
//! };
//!
//! // Use `post_form` method to create an `x-www-form-urlencoded` request.
//! let oauth::Request {
//!     authorization,
//!     data,
//! } = builder.post_form("https://example.com/api/v1/comments/create.json", &req);
//!
//! assert_eq!(
//!     authorization,
//!     "OAuth \
//!          oauth_consumer_key=\"consumer_key\",\
//!          oauth_nonce=\"nonce\",\
//!          oauth_signature_method=\"HMAC-SHA1\",\
//!          oauth_timestamp=\"9999999999\",\
//!          oauth_token=\"token\",\
//!          oauth_signature=\"bbhEIrjfisdDBrZkKnEXKa4ykE4%3D\"",
//! );
//! assert_eq!(
//!     data,
//!     "article_id=123456789&text=Rust%20lang%20is%20great%20%F0%9F%A6%80",
//! );
//! # }
//! ```
//!
//! See [`Authorize`](authorize/trait.Authorize.html) for more details on the custom derive macro.

#![doc(html_root_url = "https://docs.rs/oauth1-request/0.3.2")]
#![deny(intra_doc_link_resolution_failure)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod authorize;
pub mod signature_method;
pub mod signer;

#[macro_use]
mod util;

#[cfg(feature = "derive")]
pub use oauth1_request_derive::Authorize;

pub use authorize::Authorize;
#[cfg(feature = "hmac-sha1")]
pub use signature_method::HmacSha1;
pub use signature_method::Plaintext;

use std::borrow::Borrow;
use std::fmt::{Debug, Display};
use std::num::NonZeroU64;
use std::str;

use signature_method::SignatureMethod;
use signer::Signer;

/// A pair of an OAuth header and its corresponding query/form string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    /// The `Authorization` header string for the request.
    pub authorization: String,
    /// The URI with query string or the x-www-form-urlencoded string for the request.
    pub data: String,
}

/// An OAuth `Request` builder.
#[derive(Clone, Debug)]
pub struct Builder<'a, SM, T = String> {
    signature_method: SM,
    client: Credentials<T>,
    token: Option<Credentials<T>>,
    options: Options<'a>,
}

/// The "credentials" pair defined in [RFC 5849 section 1.1][rfc].
///
/// [rfc]: https://tools.ietf.org/html/rfc5849#section-1.1
///
/// This type represents:
///
/// - Client credentials (consumer key and secrets)
/// - Temporary credentials (request token and secret)
/// - Token credentials (access token and secret)
pub type Credentials<T = String> = oauth_credentials::Credentials<T>;

options! {
    /// Optional OAuth parameters.
    #[derive(Clone, Debug, Default)]
    pub struct Options<'a> {
        /// Creates a blank `Options` with default values (`None`).
        new;
        /// Sets `oauth_callback` parameter.
        callback: Option<&'a str>,
        /// Sets `oauth_nonce` parameter.
        nonce: Option<&'a str>,
        /// Sets `oauth_timestamp` parameter.
        ///
        /// The OAuth standard ([RFC 5849 section 3.3.][rfc]) says that the timestamp value
        /// MUST be a positive integer, so this method treats `0` as `None`.
        ///
        /// [rfc]: https://tools.ietf.org/html/rfc5849#section-3.3
        timestamp: Option<NonZeroU64>,
        /// Sets `oauth_token` parameter.
        token: Option<&'a str>,
        /// Sets `oauth_verifier` parameter.
        verifier: Option<&'a str>,
        /// Sets whether to include `oauth_version="1.0"` parameter in the `Authorization` header.
        version: bool,
    }
}

impl<'a, SM: SignatureMethod, T: Borrow<str>> Builder<'a, SM, T> {
    /// Creates a `Builder` that signs requests using the specified client credentials
    /// and signature method.
    pub fn new(client: Credentials<T>, signature_method: SM) -> Self {
        Builder {
            signature_method,
            client,
            token: None,
            options: Options::new(),
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
    pub fn timestamp(&mut self, timestamp: impl Into<Option<u64>>) -> &mut Self {
        self.options.timestamp(timestamp);
        self
    }

    /// Sets/unsets the `oauth_verifier` value.
    pub fn verifier(&mut self, verifier: impl Into<Option<&'a str>>) -> &mut Self {
        self.options.verifier(verifier);
        self
    }

    /// Sets whether to include the `oauth_version` value in requests.
    pub fn version(&mut self, version: bool) -> &mut Self {
        self.options.version(version);
        self
    }

    /// Signs a `GET` request to `uri`.
    pub fn get<U: Display, A: Authorize>(&self, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        self.build("GET", uri, request)
    }

    /// Signs an `x-www-form-urlencoded` `PUT` request to `uri`.
    pub fn put_form<U: Display, A: Authorize>(&self, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        self.build_form("PUT", uri, request)
    }

    /// Signs an `x-www-form-urlencoded` `POST` request to `uri`.
    pub fn post_form<U: Display, A: Authorize>(&self, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        self.build_form("POST", uri, request)
    }

    /// Signs a `DELETE` request to `uri`.
    pub fn delete<U: Display, A: Authorize>(&self, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        self.build("DELETE", uri, request)
    }

    /// Signs an `OPTIONS` request to `uri`.
    pub fn options<U: Display, A: Authorize>(&self, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        self.build("OPTIONS", uri, request)
    }

    /// Signs a `HEAD` request to `uri`.
    pub fn head<U: Display, A: Authorize>(&self, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        self.build("HEAD", uri, request)
    }

    /// Signs a `CONNECT` request to `uri`.
    pub fn connect<U: Display, A: Authorize>(&self, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        self.build("CONNECT", uri, request)
    }

    /// Signs an `x-www-form-urlencoded` `PATCH` request to `uri`.
    pub fn patch_form<U: Display, A: Authorize>(&self, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        self.build_form("PATCH", uri, request)
    }

    /// Signs a `TRACE` request to `uri`.
    pub fn trace<U: Display, A: Authorize>(&self, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        self.build("TRACE", uri, request)
    }

    /// Signs a request to `uri` with a custom HTTP request method.
    pub fn build<U: Display, A: Authorize>(&self, method: &str, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        #[allow(deprecated)]
        self.build_(method, uri, request, true)
    }

    /// Signs an `x-www-form-urlencoded` request to `uri` with a custom HTTP request method.
    pub fn build_form<U: Display, A: Authorize>(&self, method: &str, uri: U, request: A) -> Request
    where
        SM: Copy,
    {
        #[allow(deprecated)]
        self.build_(method, uri, request, false)
    }

    #[deprecated(since = "0.3.1", note = "This method was made public by mistake")]
    #[doc(hidden)]
    pub fn build_<U, A>(&self, method: &str, uri: U, request: A, q: bool) -> Request
    where
        SM: Copy,
        U: Display,
        A: Authorize,
    {
        let mut options;
        let (options, token_secret) = if let Some(ref token) = self.token {
            // Clone `options` due to incompatible lifetimes.
            options = self.options.clone();
            options.token(token.identifier.borrow());
            (&options, Some(token.secret.borrow()))
        } else {
            (&self.options, None)
        };

        let signer = Signer::new_(
            method,
            uri,
            self.client.secret.borrow(),
            token_secret,
            self.signature_method,
            q,
        );

        request.authorize_with(signer, self.client.identifier.borrow(), Some(options))
    }
}
