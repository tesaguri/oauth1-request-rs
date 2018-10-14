//! Yet yet yet another OAuth 1 client library.
//!
//! # Usage
//!
//! Creating a `GET` request:
//!
//! ```rust
//! extern crate oauth1_request as oauth;
//!
//! let mut sign = oauth::Signer::new(
//!     "GET",
//!     "https://example.com/api/v1/get.json",
//!     "consumer_secret",
//!     "token_secret", // or `None`
//! );
//!
//! // The parameters must be appended in the ascending ordering.
//! sign.append("abc", "value")
//!     .append("lmn", "something");
//!
//! // Append `oauth_*` parameters.
//! let mut sign = sign.append_oauth_params(
//!     "consumer_key",
//!     &*oauth::Options::new()
//!         .token("token")
//!         .nonce("nonce")
//!         .timestamp(9999999999),
//! );
//!
//! sign.append("qrs", "stuff")
//!     .append("xyz", "blah-blah");
//!
//! let oauth::Request { authorization, data } = sign.finish();
//!
//! assert_eq!(
//!     authorization,
//!     "OAuth \
//!      oauth_consumer_key=\"consumer_key\",\
//!      oauth_nonce=\"nonce\",\
//!      oauth_signature_method=\"HMAC-SHA1\",\
//!      oauth_timestamp=\"9999999999\",\
//!      oauth_token=\"token\",\
//!      oauth_version=\"1.0\",\
//!      oauth_signature=\"JeDlFImHxfukYP0e6P2fy63G6V4%3D\"",
//! );
//! assert_eq!(
//!     data,
//!     "https://example.com/api/v1/get.json?abc=value&lmn=something&qrs=stuff&xyz=blah-blah",
//! );
//! ```
//!
//! Creating an `x-www-form-urlencoded` request:
//!
//! ```rust
//! # extern crate oauth1_request as oauth;
//! // Use `new_form` method to create an `x-www-form-urlencoded` string.
//! let mut sign = oauth::Signer::new_form(
//!     "POST",
//!     "https://example.com/api/v1/post.json",
//!     "consumer_secret",
//!     "token_secret", // or `None`
//! );
//!
//! // ...
//! // (same as the above example...)
//! # sign.append("abc", "value").append("lmn", "something");
//! # let mut sign = sign.append_oauth_params(
//! #     "consumer_key",
//! #     &*oauth::Options::new().token("token").nonce("nonce").timestamp(9999999999),
//! # );
//! # sign.append("qrs", "stuff").append("xyz", "blah-blah");
//!
//! let oauth::Request { authorization, data } = sign.finish();
//!
//! assert_eq!(
//!     authorization,
//!     "OAuth \
//!      oauth_consumer_key=\"consumer_key\",\
//!      oauth_nonce=\"nonce\",\
//!      oauth_signature_method=\"HMAC-SHA1\",\
//!      oauth_timestamp=\"9999999999\",\
//!      oauth_token=\"token\",\
//!      oauth_version=\"1.0\",\
//!      oauth_signature=\"3S3N5Dod9azPWhXZKh4h44bTp4Y%3D\"",
//! );
//! assert_eq!(
//!     data,
//!     "abc=value&lmn=something&qrs=stuff&xyz=blah-blah",
//! );
//! ```
//!
//! Using the convenience wrapper method:
//!
//! ```rust
//! # extern crate oauth1_request as oauth;
//! let oauth::Request { authorization, data } = oauth::Request::new(
//!     "GET",
//!     "https://example.com/api/v1/get.json",
//!     "consumer_key",
//!     "consumer_secret",
//!     "token_secret",
//!     &*oauth::Options::new()
//!         .token("token")
//!         .nonce("nonce")
//!         .timestamp(9999999999),
//!     Some(&[
//!         // Ordering doesn't matter here:
//!         ("xyz", "blah-blah"),
//!         ("qrs", "stuff"),
//!         ("abc", "value"),
//!         ("lmn", "something"),
//!     ].iter().cloned().collect()),
//! );
//!
//! assert_eq!(
//!     authorization,
//!     "OAuth \
//!      oauth_consumer_key=\"consumer_key\",\
//!      oauth_nonce=\"nonce\",\
//!      oauth_signature_method=\"HMAC-SHA1\",\
//!      oauth_timestamp=\"9999999999\",\
//!      oauth_token=\"token\",\
//!      oauth_version=\"1.0\",\
//!      oauth_signature=\"JeDlFImHxfukYP0e6P2fy63G6V4%3D\"",
//! );
//! assert_eq!(
//!     data,
//!     "https://example.com/api/v1/get.json?abc=value&lmn=something&qrs=stuff&xyz=blah-blah",
//! );
//! ```

extern crate base64;
#[macro_use]
extern crate bitflags;
extern crate hmac;
extern crate percent_encoding;
extern crate rand;
extern crate sha1;

#[macro_use]
mod util;

use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::fmt::{Display, Write};
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::display::Base64Display;
use hmac::{Hmac, Mac};
use rand::distributions::Distribution;
use rand::thread_rng;
use sha1::Sha1;

use util::*;

/// A type that creates a signed `Request`.
#[derive(Debug)]
pub struct Signer<S = NotReady> {
    inner: Inner,
    state: PhantomData<fn() -> S>,
}

/// A pair of an OAuth header and its corresponding query/form string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    /// The `Authorization` header string for the request.
    pub authorization: String,
    /// The URI with query string or the x-www-form-urlencoded string for the request.
    pub data: String,
}

options! {
    /// Optional OAuth parameters.
    #[derive(Clone, Debug, Default)]
    pub struct Options<'a> {
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
    }
}

/// Represents the state of a `Signer` before `append_oauth_params` method is called
/// and unready to `finish`.
pub enum NotReady {}

/// Represents the state of a `Signer` after `append_oauth_params` method is called
/// and ready to `finish`.
pub enum Ready {}

#[derive(Debug)]
struct Inner {
    authorization: String,
    data: String,
    signature: MacWrite<Hmac<Sha1>>,
    next_append: Append,
    #[cfg(debug_assertions)]
    prev_key: String,
}

bitflags! {
    struct Append: u8 {
        const QUESTION  = 0b001;
        const AMPERSAND = 0b010;
        const COMMA     = 0b100;
    }
}

impl Signer<NotReady> {
    /// Returns a `Signer` that appends query string to `uri` and returns it as `Request.data`.
    ///
    /// `?` character and any characters following it (i.e. query part) in `uri` will be ignored.
    pub fn new<'a>(
        method: &str,
        uri: impl Display,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
    ) -> Self {
        Self::new_(method, uri, consumer_secret, token_secret.into(), true)
    }

    /// Returns a `Signer` that creates an x-www-form-urlencoded string and returns it as
    /// `Request.data`.
    ///
    /// `?` character and any characters following it (i.e. query part) in `uri` will be ignored.
    pub fn new_form<'a>(
        method: &str,
        uri: impl Display,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
    ) -> Self {
        Self::new_(method, uri, consumer_secret, token_secret.into(), false)
    }

    fn new_(method: &str, uri: impl Display, cs: &str, ts: Option<&str>, q: bool) -> Self {
        let standard_header_len = str::len(
            "OAuth \
             oauth_consumer_key=\"XXXXXXXXXXXXXXXXXXXXXXXXX\",\
             oauth_nonce=\"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\",\
             oauth_signature_method=\"HMAC-SHA1\",\
             oauth_timestamp=\"NNNNNNNNNN\",\
             oauth_token=\"NNNNNNNNNNNNNNNNNNN-\
             XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\",\
             oauth_version=\"1.0\",\
             oauth_signature=\"\
             %XX%XX%XX%XX%XX%XX%XX%XX%XX%XX%XX%XX%XX%XX\
             %XX%XX%XX%XX%XX%XX%XX%XX%XX%XX%XX%XX%XX%XX\"",
        );

        let mut authorization = String::with_capacity(standard_header_len);
        authorization.push_str("OAuth ");

        let mut signing_key = String::with_capacity(3 * (cs.len() + ts.map_or(0, str::len)) + 1);
        write!(signing_key, "{}&", percent_encode(cs)).unwrap();
        if let Some(ts) = ts {
            write!(signing_key, "{}", percent_encode(ts)).unwrap();
        }
        let mut signature = MacWrite(Hmac::new_varkey(signing_key.as_bytes()).unwrap());

        let uri = DisplayBefore('?', uri);
        let data = if q {
            let data = uri.to_string();
            write!(signature, "{}&{}&", method, percent_encode(&data)).unwrap();
            data
        } else {
            write!(signature, "{}&{}&", method, PercentEncode(uri)).unwrap();
            String::new()
        };

        let next_append = if q { Append::QUESTION } else { Append::empty() };

        let inner = {
            #[cfg(debug_assertions)]
            {
                Inner {
                    authorization,
                    data,
                    signature,
                    next_append,
                    prev_key: String::new(),
                }
            }
            #[cfg(not(debug_assertions))]
            {
                Inner {
                    authorization,
                    data,
                    signature,
                    next_append,
                }
            }
        };

        Self {
            inner,
            state: PhantomData,
        }
    }

    /// Appends `oauth_*` parameters to the signing key.
    ///
    /// This must be called just after all the keys less than `oauth_*` in byte order (if any)
    /// is appended, and just before a key greater than `oauth_*` (if any) is appended.
    pub fn append_oauth_params<'a>(
        self,
        consumer_key: &str,
        options: impl Into<Option<&'a Options<'a>>>,
    ) -> Signer<Ready> {
        // Let's cross fingers and hope that this will be optimized into a `static`.
        let default = Options::new();
        let options = options.into().unwrap_or(&default);
        self.append_oauth_params_(consumer_key, options)
    }

    fn append_oauth_params_(mut self, ck: &str, opts: &Options) -> Signer<Ready> {
        let mut nonce_buf = [0; 32];
        let nonce = if let Some(n) = opts.nonce {
            n
        } else {
            let mut rng = thread_rng();
            for b in &mut nonce_buf {
                *b = UrlSafe.sample(&mut rng);
            }
            debug_assert!(nonce_buf.is_ascii());
            unsafe { str::from_utf8_unchecked(&nonce_buf) }
        };
        let timestamp = if let Some(t) = opts.timestamp {
            t.get()
        } else {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_secs(),
                #[cold]
                Err(_) => 1,
            }
        };

        self.append_to_header("oauth_consumer_key", ck);
        self.append_to_header_encoded("oauth_nonce", nonce);
        self.append_to_header_encoded("oauth_signature_method", "HMAC-SHA1");
        self.append_to_header_encoded("oauth_timestamp", timestamp);
        if let Some(t) = opts.token {
            self.append_to_header("oauth_token", t);
        }
        self.append_to_header_encoded("oauth_version", "1.0");

        Signer {
            inner: self.inner,
            state: PhantomData,
        }
    }

    fn append_to_header(&mut self, k: &str, v: &str) {
        self.check_dictionary_order(k);
        write!(
            self.inner.authorization,
            r#"{}="{}","#,
            k,
            percent_encode(v),
        ).unwrap();
        self.append_to_signature(k, v);
    }

    fn append_to_header_encoded(&mut self, k: &str, v: impl Display) {
        self.check_dictionary_order(k);
        write!(self.inner.authorization, r#"{}="{}","#, k, v).unwrap();
        self.append_to_signature_encoded(k, PercentEncode(v));
    }
}

impl<S> Signer<S> {
    /// Appends a parameter to the query/form string and signing key.
    ///
    /// This percent encodes the value, but not the key.
    ///
    /// The parameters must be appended in byte ascending order.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if the key is not appended in ascending order
    #[inline]
    pub fn append(&mut self, k: &str, v: &str) -> &mut Self {
        self.check_dictionary_order(k);
        self.append_delim();
        write!(self.inner.data, "{}={}", k, percent_encode(v)).unwrap();
        self.append_to_signature(k, v);
        self
    }

    /// Appends a parameter to the query/form string and signing key.
    ///
    /// Unlike `append`, this will not percent encode the value.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if the key is not appended in ascending order.
    #[inline]
    pub fn append_encoded(&mut self, k: &str, v: impl Display) -> &mut Self {
        self.check_dictionary_order(k);
        self.append_delim();
        write!(self.inner.data, "{}={}", k, v).unwrap();
        self.append_to_signature_encoded(k, PercentEncode(v));
        self
    }

    fn append_delim(&mut self) {
        if self.inner.next_append.contains(Append::QUESTION) {
            self.inner.data.push('?');
            self.inner.next_append.remove(Append::QUESTION);
        }
        if self.inner.next_append.contains(Append::AMPERSAND) {
            self.inner.data.push('&');
        } else {
            self.inner.next_append.insert(Append::AMPERSAND);
        }
    }

    fn append_to_signature(&mut self, k: &str, v: &str) {
        self.append_to_signature_encoded(k, DoublePercentEncode(v));
    }

    fn append_to_signature_encoded(&mut self, k: &str, v: impl Display) {
        if self.inner.next_append.contains(Append::COMMA) {
            self.inner.signature.write_str("%26").unwrap();
        } else {
            self.inner.next_append.insert(Append::COMMA);
        }
        write!(self.inner.signature, "{}%3D{}", k, v).unwrap();
    }

    fn check_dictionary_order(&mut self, _k: &str) {
        #[cfg(debug_assertions)]
        {
            assert!(
                *self.inner.prev_key <= *_k,
                "appended key is less than previously appended one in dictionary order\
                 \n previous: `{:?}`,\
                 \n  current: `{:?}`",
                self.inner.prev_key,
                _k,
            );
            self.inner.prev_key.clear();
            self.inner.prev_key.push_str(_k);
        }
    }
}

impl Signer<Ready> {
    /// Consumes the `Signer` and returns a `Request`.
    ///
    /// This can only be called after `append_oauth_params` is called.
    pub fn finish(self) -> Request {
        let Inner {
            mut authorization,
            data,
            signature,
            ..
        } = self.inner;

        authorization.push_str("oauth_signature=");
        write!(
            authorization,
            r#""{}""#,
            PercentEncode(Base64Display::standard(&signature.0.result().code())),
        ).unwrap();

        Request {
            authorization,
            data,
        }
    }
}

impl Request {
    /// Convenience method for creating a `Request` using `Signer::new`.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate oauth1_request as oauth;
    ///
    /// let oauth::Request { authorization, data } = oauth::Request::new(
    ///     "GET",
    ///     "https://example.com/api/v1/get.json",
    ///     "consumer_key",
    ///     "consumer_secret",
    ///     "token_secret",
    ///     &*oauth::Options::new().token("token"),
    ///     Some(&[("key", "value")].iter().cloned().collect()),
    /// );
    /// ```
    pub fn new<'a>(
        method: &str,
        uri: impl Display,
        consumer_key: &str,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
        options: impl Into<Option<&'a Options<'a>>>,
        params: Option<&BTreeSet<(impl Borrow<str>, impl Borrow<str>)>>,
    ) -> Self {
        Self::new_(
            method,
            uri,
            consumer_key,
            consumer_secret,
            token_secret.into(),
            options.into(),
            params,
            true,
        )
    }

    /// Convenience method for creating a `Request` using `Signer::new_form`.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate oauth1_request as oauth;
    ///
    /// let oauth::Request { authorization, data } = oauth::Request::new(
    ///     "POST",
    ///     "https://example.com/api/v1/post.json",
    ///     "consumer_key",
    ///     "consumer_secret",
    ///     "token_secret",
    ///     &*oauth::Options::new().token("token"),
    ///     Some(&[("key", "value")].iter().cloned().collect()),
    /// );
    /// ```
    pub fn new_form<'a>(
        method: &str,
        uri: impl Display,
        consumer_key: &str,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
        options: impl Into<Option<&'a Options<'a>>>,
        params: Option<&BTreeSet<(impl Borrow<str>, impl Borrow<str>)>>,
    ) -> Self {
        Self::new_(
            method,
            uri,
            consumer_key,
            consumer_secret,
            token_secret.into(),
            options.into(),
            params,
            false,
        )
    }

    fn new_(
        method: &str,
        uri: impl Display,
        ck: &str,
        cs: &str,
        ts: Option<&str>,
        opts: Option<&Options>,
        params: Option<&BTreeSet<(impl Borrow<str>, impl Borrow<str>)>>,
        q: bool,
    ) -> Self {
        let mut signer = Signer::new_(method, uri, cs, ts, q);
        let signer = if let Some(params) = params {
            let mut params = params
                .iter()
                .map(|&(ref k, ref v)| (k.borrow(), v.borrow()));

            let (mut signer, mut pair) = loop {
                let (k, v) = match params.next() {
                    Some(kv) => kv,
                    None => break (signer.append_oauth_params(ck, opts), None),
                };
                if k > "oauth_" {
                    break (signer.append_oauth_params(ck, opts), Some((k, v)));
                }
                signer.append(k, v);
            };

            while let Some((k, v)) = pair {
                signer.append(k, v);
                pair = params.next();
            }

            signer
        } else {
            signer.append_oauth_params(ck, opts)
        };

        signer.finish()
    }

    /// Alias of `Signer::new` for convenience.
    pub fn signer<'a>(
        method: &str,
        uri: impl Display,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
    ) -> Signer<NotReady> {
        Signer::new(method, uri, consumer_secret, token_secret)
    }

    /// Alias of `Signer::new_form` for convenience.
    pub fn signer_form<'a>(
        method: &str,
        uri: impl Display,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
    ) -> Signer<NotReady> {
        Signer::new_form(method, uri, consumer_secret, token_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These values are taken from Twitter's document:
    // https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature.html
    const CK: &str = "xvz1evFS4wEEPTGEFPHBog";
    const CS: &str = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
    const AK: Option<&str> = Some("370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb");
    const AS: Option<&str> = Some("LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE");
    const NONCE: &str = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
    const TIMESTAMP: u64 = 1318622958;

    #[test]
    fn signer() {
        macro_rules! test {
            ($((
                $method:expr, $ep:expr,
                $ck:expr, $t:expr, $cs:expr, $ts:expr,
                $nonce:expr, $timestamp:expr,
                { $($param1:tt)* }, { $($param2:tt)* } $(,)*
            ) -> ($expected_sign:expr, $expected_data:expr $(,)*);)*) => {$(
                #[allow(unused_mut)]
                let mut signer = if $method == "POST" {
                    Signer::new_form
                } else {
                    Signer::new
                }($method, $ep, $cs, $ts);

                test_inner! { signer; $($param1)* }
                #[allow(unused_mut)]
                let mut signer = signer.append_oauth_params(
                    $ck,
                    &*Options::new()
                        .token($t)
                        .nonce($nonce)
                        .timestamp($timestamp),
                );
                test_inner! { signer; $($param2)* }

                let Request { authorization, data } = signer.finish();
                let mut expected = format!(
                    "OAuth \
                     oauth_consumer_key=\"{}\",\
                     oauth_nonce=\"{}\",\
                     oauth_signature_method=\"HMAC-SHA1\",\
                     oauth_timestamp=\"{}\",",
                    $ck,
                    $nonce,
                    $timestamp
                );
                if let Some(ref t) = $t {
                    write!(expected, "oauth_token=\"{}\",", t).unwrap();
                }
                write!(expected, "oauth_version=\"1.0\",oauth_signature=\"{}\"", $expected_sign)
                    .unwrap();
                assert_eq!(authorization, expected);
                assert_eq!(data, $expected_data);
            )*};
        }

        macro_rules! test_inner {
            ($signer:ident; encoded $key:ident: $v:expr, $($rest:tt)*) => {
                $signer.append_encoded(stringify!($key), $v);
                test_inner! { $signer; $($rest)* }
            };
            ($signer:ident; $key:ident: $v:expr, $($rest:tt)*) => {
                $signer.append(stringify!($key), $v);
                test_inner! { signerb; $($rest)* }
            };
            ($_signer:ident;) => ();
        }

        test! {
            (
                "GET", "https://stream.twitter.com/1.1/statuses/sample.json",
                CK, AK, CS, AS, NONCE, TIMESTAMP,
                {}, { encoded stall_warnings: "true", },
            ) -> (
                "OGQqcy4l5xWBFX7t0DrkP5%2FD0rM%3D",
                "https://stream.twitter.com/1.1/statuses/sample.json?stall_warnings=true",
            );
            (
                "POST", "https://api.twitter.com/1.1/statuses/update.json",
                CK, AK, CS, AS, NONCE, TIMESTAMP,
                { encoded include_entities: "true", },
                { status: "Hello Ladies + Gentlemen, a signed OAuth request!", },
            ) -> (
                "hCtSmYh%2BiHYCEqBWrE7C7hYmtUk%3D",
                "include_entities=true&\
                    status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21",
            );
            ("POST", "https://example.com/post.json", CK, AK, CS, AS, NONCE, TIMESTAMP, {}, {})
                -> ("pN52L1gJ6sOyYOyv23cwfWFsIZc%3D", "");
            (
                "GET", "https://example.com/get.json",
                CK, AK, CS, AS, NONCE, TIMESTAMP,
                { encoded bar: "%E9%85%92%E5%A0%B4", foo: "ふー", }, {},
            ) -> (
                "Xp35hf3T21yhpEuxez7p6bV62Bw%3D",
                "https://example.com/get.json?bar=%E9%85%92%E5%A0%B4&foo=%E3%81%B5%E3%83%BC",
            );
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(
        expected = "appended key is less than previously appended one in dictionary order\
                    \n previous: `\"foo\"`,\
                    \n  current: `\"bar\"`"
    )]
    fn panic_on_misordering() {
        Signer::new("", "", "", None)
            .append_encoded("foo", true)
            .append("bar", "ばー！");
    }
}
