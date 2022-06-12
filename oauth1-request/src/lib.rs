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
//! let authorization_header = oauth::post(uri, &request, &token, oauth::HMAC_SHA1);
//! # // Override the above value to pin the nonce and timestamp value.
//! # let mut builder = oauth::Builder::new(token.client, oauth::HMAC_SHA1);
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
//! let form = oauth::to_form(&request);
//! assert_eq!(
//!     form,
//!     "article_id=123456789&text=A%20request%20signed%20with%20OAuth%20%26%20Rust%20%F0%9F%A6%80%20%F0%9F%94%8F",
//! );
//!
//! let uri = oauth::to_query(uri.to_owned(), &request);
//! assert_eq!(
//!     uri,
//!     "https://example.com/api/v1/comments/create.json?article_id=123456789&text=A%20request%20signed%20with%20OAuth%20%26%20Rust%20%F0%9F%A6%80%20%F0%9F%94%8F",
//! );
//! ```
//!
//! See [`Request`][oauth1_request_derive::Request] for more details on the derive macro.
//!
//! If you want to authorize a request with dynamic keys, use
//! [`oauth::ParameterList`][ParameterList].
//!
#![cfg_attr(feature = "alloc", doc = " ```")]
#![cfg_attr(not(feature = "alloc"), doc = " ```ignore")]
//! # extern crate oauth1_request as oauth;
//! #
//! use std::fmt::Display;
//!
//! let request = oauth::ParameterList::new([
//!     ("article_id", &123456789 as &dyn Display),
//!     ("text", &"A request signed with OAuth & Rust 🦀 🔏"),
//! ]);
//!
//! let form = oauth::to_form(&request);
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

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/oauth1-request/0.5.1")]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[macro_use]
mod util;

pub mod request;
pub mod serializer;
pub mod signature_method;

doc_auto_cfg! {
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
    /// assert_eq!(oauth::to_form(&request), "name=test&type=42");
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
    ///
    /// ## Container attributes
    ///
    /// - `#[oauth1(crate = "name")]`
    ///
    /// Specify the path of `oauth1_request` crate. The path is automatically determined by the
    /// derive macro by default, even if the crate is renamed with the [`[package]`][package] key of
    /// `Cargo.toml`, so you usually don't need this attribute. It may be useful if you are using an
    /// exotic build tool where the crate name cannot be determined reliably.
    ///
    /// [package]: <https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#renaming-dependencies-in-cargotoml>
    #[cfg(feature = "derive")]
    #[doc(inline)]
    pub use oauth1_request_derive::Request;
}
#[doc(no_inline)]
pub use oauth_credentials::{Credentials, Token};

doc_auto_cfg! {
    pub use self::request::ParameterList;
    pub use self::request::Request;
    #[cfg(feature = "hmac-sha1")]
    pub use self::signature_method::HmacSha1;
    pub use self::signature_method::Plaintext;
    #[cfg(feature = "rsa-sha1-06")]
    pub use self::signature_method::RsaSha1;
    #[cfg(feature = "hmac-sha1")]
    pub use self::signature_method::HMAC_SHA1;
    #[cfg(feature = "alloc")]
    pub use self::signature_method::PLAINTEXT;
}

#[cfg(feature = "alloc")]
use alloc::string::String;
use core::fmt::Debug;
use core::fmt::{Display, Write};
use core::num::NonZeroU64;
use core::str;

use self::serializer::auth;
use self::signature_method::SignatureMethod;

cfg_type_param_hack! {
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
}

macro_rules! builder_authorize_shorthand {
    ($($name:ident($method:expr);)*) => {doc_auto_cfg! {$(
        #[doc = concat!("Authorizes a `", $method, "` request to `uri`,")]
        /// returning an HTTP `Authorization` header value.
        ///
        /// `uri` must not contain a query part, which would result in a wrong signature.
        #[cfg(feature = "alloc")]
        pub fn $name<U, R>(&self, uri: U, request: &R) -> String
        where
            U: Display,
            R: Request + ?Sized,
            SM: Clone,
        {
            self.authorize($method, uri, request)
        }
    )*}};
}

macro_rules! builder_to_form_shorthand {
    ($($name:ident($method:expr);)*) => {doc_auto_cfg! {$(
        #[doc = concat!("Authorizes a `", $method, "` request to `uri`,")]
        /// writing the OAuth protocol parameters to an `x-www-form-urlencoded` string
        /// along with the other request parameters.
        ///
        /// `uri` must not contain a query part, which would result in a wrong signature.
        #[cfg(feature = "alloc")]
        pub fn $name<U, R>(&self, uri: U, request: &R) -> String
        where
            U: Display,
            R: Request + ?Sized,
            SM: Clone,
        {
            self.to_form($method, uri, request)
        }
    )*}};
}

macro_rules! builder_to_query_shorthand {
    ($($name:ident($method:expr);)*) => {$(
        doc_coerce_expr! {
            #[doc = concat!("Authorizes a `", $method, "` request to `uri`, appending")]
            /// the OAuth protocol parameters to `uri` along with the other request parameters.
            ///
            /// `uri` must not contain a query part, which would result in a wrong signature.
            pub fn $name<W, R>(&self, uri: W, request: &R) -> W
            where
                W: Display + Write,
                R: Request + ?Sized,
                SM: Clone,
            {
                self.to_query($method, uri, request)
            }
        }
    )*};
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
    /// By default, `Builder` uses the timestamp of the time when `authorize`-like method is called.
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

    builder_authorize_shorthand! {
        get("GET");
        put("PUT");
        post("POST");
        delete("DELETE");
        options("OPTIONS");
        head("HEAD");
        connect("CONNECT");
        patch("PATCH");
        trace("TRACE");
    }

    builder_to_form_shorthand! {
        put_form("PUT");
        post_form("POST");
        options_form("OPTIONS");
        patch_form("PATCH");
    }

    builder_to_query_shorthand! {
        get_query("GET");
        put_query("PUT");
        post_query("POST");
        delete_query("DELETE");
        options_query("OPTIONS");
        head_query("HEAD");
        connect_query("CONNECT");
        patch_query("PATCH");
        trace_query("TRACE");
    }

    doc_auto_cfg! {
        /// Authorizes a request to `uri` with a custom HTTP request method,
        /// returning an HTTP `Authorization` header value.
        ///
        /// `uri` must not contain a query part, which would result in a wrong signature.
        #[cfg(feature = "alloc")]
        pub fn authorize<U, R>(&self, method: &str, uri: U, request: &R) -> String
        where
            U: Display,
            R: Request + ?Sized,
            SM: Clone,
        {
            let serializer = serializer::auth::Authorizer::authorization(
                method,
                uri,
                self.client.as_ref(),
                self.token.as_ref().map(Credentials::as_ref),
                &self.options,
                self.signature_method.clone(),
            );

            request.serialize(serializer)
        }

        /// Authorizes a request to `uri` with a custom HTTP request method, writing the OAuth protocol
        /// parameters to an `x-www-form-urlencoded` string along with the other request parameters.
        ///
        /// `uri` must not contain a query part, which would result in a wrong signature.
        #[cfg(feature = "alloc")]
        pub fn to_form<U, R>(&self, method: &str, uri: U, request: &R) -> String
        where
            U: Display,
            R: Request + ?Sized,
            SM: Clone,
        {
            let serializer = serializer::auth::Authorizer::form(
                method,
                uri,
                self.client.as_ref(),
                self.token.as_ref().map(Credentials::as_ref),
                &self.options,
                self.signature_method.clone(),
            );

            request.serialize(serializer)
        }
    }

    /// Authorizes a request to `uri` with a custom HTTP request method, appending the OAuth
    /// protocol parameters to `uri` along with the other request parameters.
    ///
    /// `uri` must not contain a query part, which would result in a wrong signature.
    pub fn to_query<W, R>(&self, method: &str, uri: W, request: &R) -> W
    where
        W: Display + Write,
        R: Request + ?Sized,
        SM: Clone,
    {
        let serializer = serializer::auth::Authorizer::query(
            method,
            uri,
            self.client.as_ref(),
            self.token.as_ref().map(Credentials::as_ref),
            &self.options,
            self.signature_method.clone(),
        );

        request.serialize(serializer)
    }

    /// Same as `authorize` except that this writes the resulting `Authorization` header value
    /// into `buf`.
    pub fn authorize_with_buf<W, U, R>(&self, buf: W, method: &str, uri: U, request: &R) -> W
    where
        W: Write,
        U: Display,
        R: Request + ?Sized,
        SM: Clone,
    {
        let serializer = serializer::auth::Authorizer::authorization_with_buf(
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

    doc_auto_cfg! {
        /// Same as `to_form` except that this writes the resulting `x-www-form-urlencoded` string
        /// into `buf`.
        #[cfg(feature = "alloc")]
        pub fn to_form_with_buf<W, U, R>(&self, buf: W, method: &str, uri: U, request: &R) -> W
        where
            W: Write,
            U: Display,
            R: Request + ?Sized,
            SM: Clone,
        {
            let serializer = serializer::auth::Authorizer::form_with_buf(
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

        /// Authorizes a request and consumes `self`, returning an HTTP `Authorization` header value.
        ///
        /// Unlike `authorize`, this does not clone the signature method and may be more efficient for
        /// non-`Copy` signature methods like `RsaSha1`.
        ///
        /// For `HmacSha1`, `&RsaSha1` and `Plaintext`, cloning is no-op or very cheap so you should
        /// use `authorize` instead.
        #[cfg(feature = "alloc")]
        pub fn into_authorization<U, R>(self, method: &str, uri: U, request: &R) -> String
        where
            U: Display,
            R: Request + ?Sized,
        {
            let serializer = serializer::auth::Authorizer::authorization(
                method,
                uri,
                self.client.as_ref(),
                self.token.as_ref().map(Credentials::as_ref),
                &self.options,
                self.signature_method,
            );

            request.serialize(serializer)
        }

        /// Authorizes a request and consumes `self`, writing the OAuth protocol parameters to
        /// an `x-www-form-urlencoded` string along with the other request parameters.
        ///
        /// Unlike `to_form`, this does not clone the signature method and may be more efficient for
        /// non-`Copy` signature methods like `RsaSha1`.
        ///
        /// For `HmacSha1`, `&RsaSha1` and `Plaintext`, cloning is no-op or very cheap so you should
        /// use `to_form` instead.
        #[cfg(feature = "alloc")]
        pub fn into_form<U, R>(self, method: &str, uri: U, request: &R) -> String
        where
            U: Display,
            R: Request + ?Sized,
        {
            let serializer = serializer::auth::Authorizer::form(
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

    /// Authorizes a request and consumes `self`, appending the OAuth protocol parameters to
    /// `uri` along with the other request parameters.
    ///
    /// Unlike `to_query`, this does not clone the signature method and may be more efficient for
    /// non-`Copy` signature methods like `RsaSha1`.
    ///
    /// For `HmacSha1`, `&RsaSha1` and `Plaintext`, cloning is no-op or very cheap so you should
    /// use `to_query` instead.
    pub fn into_query<W, R>(self, method: &str, uri: W, request: &R) -> W
    where
        W: Display + Write,
        R: Request + ?Sized,
    {
        let serializer = serializer::auth::Authorizer::query(
            method,
            uri,
            self.client.as_ref(),
            self.token.as_ref().map(Credentials::as_ref),
            &self.options,
            self.signature_method,
        );

        request.serialize(serializer)
    }

    /// Same as `into_authorization` except that this writes the resulting `Authorization` header
    /// value into `buf`.
    pub fn into_authorization_with_buf<W, U, R>(
        self,
        buf: W,
        method: &str,
        uri: U,
        request: &R,
    ) -> W
    where
        W: Write,
        U: Display,
        R: Request + ?Sized,
        SM: Clone,
    {
        let serializer = serializer::auth::Authorizer::authorization_with_buf(
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

    /// Same as `into_form` except that this writes the resulting `x-www-form-urlencoded` string
    /// into `buf`.
    pub fn into_form_with_buf<W, U, R>(self, buf: W, method: &str, uri: U, request: &R) -> W
    where
        W: Write,
        U: Display,
        R: Request + ?Sized,
    {
        let serializer = serializer::auth::Authorizer::form_with_buf(
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

macro_rules! authorize_shorthand {
    ($($name:ident($method:expr);)*) => {doc_auto_cfg! {$(
        #[doc = concat!("Authorizes a `", $method, "` request to `uri` with the given credentials.")]
        ///
        /// This returns an HTTP `Authorization` header value.
        ///
        /// `uri` must not contain a query part, which would result in a wrong signature.
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
    )*}};
}

authorize_shorthand! {
    get("GET");
    put("PUT");
    post("POST");
    delete("DELETE");
    options("OPTIONS");
    head("HEAD");
    connect("CONNECT");
    patch("PATCH");
    trace("TRACE");
}

doc_auto_cfg! {
    /// Authorizes a request to `uri` with the given credentials.
    ///
    /// This returns an HTTP `Authorization` header value.
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
            Builder::with_token(token, signature_method).into_authorization(method, uri, request)
        }
        inner(method, uri, request, token.as_ref(), signature_method)
    }

    /// Serializes a `Request` to an `x-www-form-urlencoded` string.
    #[cfg(feature = "alloc")]
    pub fn to_form<R>(request: &R) -> String
    where
        R: Request + ?Sized,
    {
        request.serialize(serializer::Urlencoder::form())
    }

    /// Serializes a `Request` to a query string and appends it to the given URI.
    ///
    /// This function naively concatenates a query string to `uri` and if `uri` already has
    /// a query part, it will have a duplicate query part like `?foo=bar?baz=qux`.
    #[cfg(feature = "alloc")]
    pub fn to_query<R>(uri: String, request: &R) -> String
    where
        R: Request + ?Sized,
    {
        request.serialize(serializer::Urlencoder::query(uri))
    }
}
