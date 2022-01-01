//! Yet yet yet another OAuth 1.0 client library.
//!
//! # Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! oauth = { version = "0.5", package = "oauth1-request" }
//! ```
//!
//! For brevity, we refer to the crate name as `oauth` throughout the documentation,
//! since the API is designed in favor of qualified paths like `oauth::get`.
//!
//! ## Create a request
//!
//! A typical authorization flow looks like this:
//!
#![cfg_attr(all(feature = "derive", feature = "hmac-sha1"), doc = " ```")]
#![cfg_attr(
    not(all(feature = "derive", feature = "hmac-sha1")),
    doc = " ```ignore"
)]
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
//! let token =
//!     oauth::Token::from_parts("consumer_key", "consumer_secret", "token", "token_secret");
//!
//! // Create the `Authorization` header.
//! let authorization_header = oauth::post(uri, &request, &token, oauth::HmacSha1::new());
//! # // Override the above value to pin the nonce and timestamp value.
//! # let mut builder = oauth::Builder::new(token.client, oauth::HmacSha1::new());
//! # builder.token(token.token);
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
//! See [`Request`][oauth1_request_derive::Request] for more details on the derive macro.
//!
//! If you want to authorize a request with dynamic keys, use [`request::ParameterList`].
//!
//! ```
//! # extern crate oauth1_request as oauth;
//! #
//! use std::fmt::Display;
//!
//! use oauth::request::ParameterList;
//!
//! let request = ParameterList::new([
//!     ("article_id", &123456789 as &dyn Display),
//!     ("text", &"A request signed with OAuth & Rust 🦀 🔏"),
//! ]);
//!
//! let form = oauth::to_form_urlencoded(&request);
//! assert_eq!(
//!     form,
//!     "article_id=123456789&text=A%20request%20signed%20with%20OAuth%20%26%20Rust%20%F0%9F%A6%80%20%F0%9F%94%8F",
//! );
//! ```
//!
//! Use [`oauth::Builder`][Builder] if you need to specify a callback URI or verifier:
//!
#![cfg_attr(all(feature = "alloc", feature = "hmac-sha1"), doc = " ```")]
#![cfg_attr(not(all(feature = "alloc", feature = "hmac-sha1")), doc = " ```ignore")]
//! # extern crate oauth1_request as oauth;
//! #
//! let uri = "https://example.com/oauth/request_temp_credentials";
//! let callback = "https://client.example.net/oauth/callback";
//!
//! let client = oauth::Credentials::new("consumer_key", "consumer_secret");
//!
//! let authorization_header = oauth::Builder::<_, _>::new(client, oauth::HmacSha1::new())
//!     .callback(callback)
//!     .post(uri, &());
//! ```

#![cfg_attr(docsrs, feature(doc_cfg, doc_cfg_hide))]
#![doc(html_root_url = "https://docs.rs/oauth1-request/0.5.1")]
// Prevent `oauth-credentials/alloc` feature from showing up on re-exports.
#![cfg_attr(docsrs, doc(cfg_hide(feature = "alloc")))]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[macro_use]
mod util;

pub mod request;
pub mod serializer;
pub mod signature_method;

/// A derive macro for [`Request`] trait.
///
/// The derive macro uses the struct's field names and `Display` implementation of the values as
/// the keys and values of the parameter pairs of the `Request`.
///
/// ## Example
///
#[cfg_attr(feature = "alloc", doc = " ```")]
#[cfg_attr(not(feature = "alloc"), doc = " ```ignore")]
/// # extern crate oauth1_request as oauth;
/// #
/// #[derive(oauth::Request)]
/// struct CreateItem<'a> {
///     name: &'a str,
///     #[oauth1(rename = "type")]
///     kind: Option<u32>,
///     #[oauth1(skip_if = str::is_empty)]
///     note: &'a str,
/// }
///
/// let request = CreateItem {
///     name: "test",
///     kind: Some(42),
///     note: "",
/// };
///
/// assert_eq!(oauth::to_form_urlencoded(&request), "name=test&type=42");
/// ```
///
/// ## Field attributes
///
/// You can customize the behavior of the derive macro with the following field attributes:
///
/// - `#[oauth1(encoded)]`
///
/// Do not percent encode the value when serializing it.
///
/// - `#[oauth1(fmt = path)]`
///
/// Use the formatting function at `path` instead of `Display::fmt` when serializing the value.
/// The function must be callable as `fn(&T, &mut Formatter<'_>) -> fmt::Result`
/// (same as `Display::fmt`).
///
/// - `#[oauth1(option = true)]` (or `#[oauth1(option = false)]`)
///
/// If set to `true`, skip the field when the value is `None` or use the unwrapped value otherwise.
/// The value's type must be `Option<T>` in this case.
///
/// When the field's type name is `Option<_>`, the attribute is implicitly set to `true`.
/// Use `#[oauth1(option = false)]` if you need to opt out of that behavior.
///
/// - `#[oauth1(rename = "name")]`
///
/// Use the given string as the parameter's key. The given string must be URI-safe.
///
/// - `#[oauth1(skip)]`
///
/// Do not serialize the field.
///
/// - `#[oauth1(skip_if = path)]`
///
/// Call the function at `path` and do not serialize the field if the function returns `true`.
/// The function must be callable as `fn(&T) -> bool`.
#[cfg(feature = "derive")]
#[doc(inline)]
pub use oauth1_request_derive::Request;
#[doc(no_inline)]
pub use oauth_credentials::{Credentials, Token};

pub use self::request::Request;
#[cfg(feature = "hmac-sha1")]
pub use self::signature_method::HmacSha1;
pub use self::signature_method::Plaintext;

#[cfg(feature = "alloc")]
use alloc::string::String;
use core::fmt::Debug;
use core::fmt::{Display, Write};
use core::num::NonZeroU64;
use core::str;

use self::serializer::auth;
use self::signature_method::SignatureMethod;

/// A builder for OAuth `Authorization` header string.
#[derive(Clone, Debug)]
pub struct Builder<
    'a,
    SM,
    #[cfg(feature = "alloc")] C = String,
    #[cfg(not(feature = "alloc"))] C,
    T = C,
> {
    signature_method: SM,
    client: Credentials<C>,
    token: Option<Credentials<T>>,
    options: auth::Options<'a>,
}

impl<'a, SM: SignatureMethod, C: AsRef<str>, T: AsRef<str>> Builder<'a, SM, C, T> {
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

    /// Creates a `Builder` that uses the token credentials from `token`.
    pub fn with_token(token: Token<C, T>, signature_method: SM) -> Self {
        let mut ret = Builder::new(token.client, signature_method);
        ret.token(token.token);
        ret
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
    #[cfg(feature = "alloc")]
    pub fn get<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("GET", uri, request)
    }

    /// Authorizes a `PUT` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    #[cfg(feature = "alloc")]
    pub fn put<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("PUT", uri, request)
    }

    /// Authorizes a `POST` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    #[cfg(feature = "alloc")]
    pub fn post<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("POST", uri, request)
    }

    /// Authorizes a `DELETE` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    #[cfg(feature = "alloc")]
    pub fn delete<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("DELETE", uri, request)
    }

    /// Authorizes an `OPTIONS` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    #[cfg(feature = "alloc")]
    pub fn options<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("OPTIONS", uri, request)
    }

    /// Authorizes a `HEAD` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    #[cfg(feature = "alloc")]
    pub fn head<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("HEAD", uri, request)
    }

    /// Authorizes a `CONNECT` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    #[cfg(feature = "alloc")]
    pub fn connect<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("CONNECT", uri, request)
    }

    /// Authorizes a `PATCH` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    #[cfg(feature = "alloc")]
    pub fn patch<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("PATCH", uri, request)
    }

    /// Authorizes a `TRACE` request to `uri`.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    #[cfg(feature = "alloc")]
    pub fn trace<U: Display, R: Request + ?Sized>(&self, uri: U, request: &R) -> String
    where
        SM: Clone,
    {
        self.build("TRACE", uri, request)
    }

    /// Authorizes a request to `uri` with a custom HTTP request method.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    #[cfg(feature = "alloc")]
    pub fn build<U: Display, R: Request + ?Sized>(
        &self,
        method: &str,
        uri: U,
        request: &R,
    ) -> String
    where
        SM: Clone,
    {
        let serializer = serializer::auth::Authorizer::new(
            method,
            uri,
            self.client.as_ref(),
            self.token.as_ref().map(Credentials::as_ref),
            &self.options,
            self.signature_method.clone(),
        );

        request.serialize(serializer)
    }

    /// Same as `build` except that this writes the resulting `Authorization` header value
    /// into `buf`.
    pub fn build_with_buf<W: Write, U: Display, R: Request + ?Sized>(
        &self,
        buf: W,
        method: &str,
        uri: U,
        request: &R,
    ) -> W
    where
        SM: Clone,
    {
        let serializer = serializer::auth::Authorizer::with_buf(
            buf,
            method,
            uri,
            self.client.as_ref(),
            self.token.as_ref().map(Credentials::as_ref),
            &self.options,
            self.signature_method.clone(),
        );

        request.serialize(serializer)
    }

    /// Authorizes a request and consumes `self`.
    ///
    /// Unlike `build`, this does not clone the signature method and may be more efficient for
    /// non-`Copy` signature methods like `RsaSha1`.
    ///
    /// For `HmacSha1`, `&RsaSha1` and `Plaintext`, cloning is no-op or very cheap so you should
    /// use `build` instead.
    #[cfg(feature = "alloc")]
    pub fn consume<U: Display, R: Request + ?Sized>(
        self,
        method: &str,
        uri: U,
        request: &R,
    ) -> String {
        let serializer = serializer::auth::Authorizer::new(
            method,
            uri,
            self.client.as_ref(),
            self.token.as_ref().map(Credentials::as_ref),
            &self.options,
            self.signature_method,
        );

        request.serialize(serializer)
    }

    /// Same as `consume` except that this writes the resulting `Authorization` header value
    /// into `buf`.
    pub fn consume_with_buf<W: Write, U: Display, R: Request + ?Sized>(
        self,
        buf: W,
        method: &str,
        uri: U,
        request: &R,
    ) -> W
    where
        SM: Clone,
    {
        let serializer = serializer::auth::Authorizer::with_buf(
            buf,
            method,
            uri,
            self.client.as_ref(),
            self.token.as_ref().map(Credentials::as_ref),
            &self.options,
            self.signature_method,
        );

        request.serialize(serializer)
    }
}

macro_rules! def_shorthand {
    ($($(#[$attr:meta])* $name:ident($method:expr);)*) => {$(
        $(#[$attr])*
        #[cfg(feature = "alloc")]
        pub fn $name<U, R, C, T, SM>(
            uri: U,
            request: &R,
            token: &Token<C, T>,
            signature_method: SM,
        ) -> String
        where
            U: Display,
            R: Request + ?Sized,
            C: AsRef<str>,
            T: AsRef<str>,
            SM: SignatureMethod,
        {
            authorize($method, uri, request, token, signature_method)
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

/// Authorizes a request to `uri` using the given credentials.
///
/// `uri` must not contain a query part, which would result in a wrong signature.
#[cfg(feature = "alloc")]
pub fn authorize<U, R, C, T, SM>(
    method: &str,
    uri: U,
    request: &R,
    token: &Token<C, T>,
    signature_method: SM,
) -> String
where
    U: Display,
    R: Request + ?Sized,
    C: AsRef<str>,
    T: AsRef<str>,
    SM: SignatureMethod,
{
    fn inner<U, R, SM>(
        method: &str,
        uri: U,
        request: &R,
        token: Token<&str, &str>,
        signature_method: SM,
    ) -> String
    where
        U: Display,
        R: Request + ?Sized,
        SM: SignatureMethod,
    {
        Builder::with_token(token, signature_method).consume(method, uri, request)
    }
    inner(method, uri, request, token.as_ref(), signature_method)
}

/// Turns a `Request` into an `x-www-form-urlencoded` string.
#[cfg(feature = "alloc")]
pub fn to_form_urlencoded<R>(request: &R) -> String
where
    R: Request + ?Sized,
{
    request.serialize(serializer::Urlencoder::form())
}

/// Turns a `Request` to a query string and appends it to the given URI.
///
/// This function naively concatenates a query string to `uri` and if `uri` already has
/// a query part, it will have a duplicate query part like `?foo=bar?baz=qux`.
#[cfg(feature = "alloc")]
pub fn to_uri_query<R>(uri: String, request: &R) -> String
where
    R: Request + ?Sized,
{
    request.serialize(serializer::Urlencoder::query(uri))
}
