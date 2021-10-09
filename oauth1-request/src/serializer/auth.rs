//! An OAuth 1.0 `Authorization` header serializer.

use std::fmt::{Display, Write};
use std::num::NonZeroU64;
use std::str;

use rand::prelude::*;

use crate::signature_method::{Plaintext, Sign, SignatureMethod};
use crate::util::*;
use crate::Credentials;

use super::Serializer;

/// A `Serializer` that produces an HTTP `Authorization` header string by signing a request
/// in OAuth 1.0 protocol.
#[derive(Clone, Debug)]
pub struct Authorizer<'a, SM: SignatureMethod> {
    consumer_key: &'a str,
    token: Option<&'a str>,
    options: &'a Options<'a>,
    authorization: String,
    sign: SM::Sign,
    append_delim_to_sign: bool,
    #[cfg(debug_assertions)]
    prev_key: String,
}

options! {
    /// Optional OAuth parameters.
    #[derive(Clone, Debug, Default)]
    pub struct Options<'a> {
        /// Creates a blank `Options` with default values (`None`).
        new;
        /// Sets `oauth_callback` parameter.
        callback: Option<&'a str>,
        /// Sets `oauth_verifier` parameter.
        verifier: Option<&'a str>,
        /// Sets `oauth_nonce` parameter.
        nonce: Option<&'a str>,
        /// Sets `oauth_timestamp` parameter.
        ///
        /// The OAuth standard ([RFC 5849 section 3.3.][rfc]) says that the timestamp value
        /// MUST be a positive integer.
        ///
        /// [rfc]: https://tools.ietf.org/html/rfc5849#section-3.3
        timestamp: Option<NonZeroU64>,
        /// Sets whether to include `oauth_version="1.0"` parameter in the `Authorization` header.
        version: bool,
    }
}

/// A version of `Signer` that uses the `PLAINTEXT` signature method.
pub type PlaintextAuthorizer<'a> = Authorizer<'a, Plaintext>;

/// A version of `Signer` that uses the `HMAC-SHA1` signature method.
#[cfg(feature = "hmac-sha1")]
pub type HmacSha1Authorizer<'a> = Authorizer<'a, crate::signature_method::HmacSha1>;

impl<'a, SM: SignatureMethod> Authorizer<'a, SM> {
    /// Creates an `Authorizer`.
    ///
    /// `uri` must not contain a query part.
    /// Otherwise, the serializer will produce a wrong signature.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `uri` contains a `'?'` character.
    pub fn new<T: Display>(
        method: &str,
        uri: T,
        client: Credentials<&'a str>,
        token: Option<Credentials<&'a str>>,
        options: &'a Options<'a>,
    ) -> Self
    where
        SM: Default,
    {
        Self::with_signature_method(Default::default(), method, uri, client, token, options)
    }

    /// Same as `new` except that this uses `signature_method` as the signature method.
    pub fn with_signature_method<T: Display>(
        signature_method: SM,
        method: &str,
        uri: T,
        client: Credentials<&'a str>,
        token: Option<Credentials<&'a str>>,
        options: &'a Options<'a>,
    ) -> Self {
        let mut sign = signature_method.sign_with(client.secret, token.map(|t| t.secret));

        let mut authorization = String::with_capacity(512);
        authorization.push_str("OAuth ");

        sign.request_method(method);

        // We can determine if the URI contains a query part by just checking if it containsa `'?'`
        // character, because the scheme and authority part of a valid URI does not contain
        // that character.
        debug_assert!(
            !uri.to_string().contains('?'),
            "`uri` must not contain a query part",
        );

        sign.uri(PercentEncode(uri));

        {
            #[cfg(debug_assertions)]
            {
                Self {
                    consumer_key: client.identifier,
                    token: token.map(|t| t.identifier),
                    options,
                    authorization,
                    sign,
                    append_delim_to_sign: false,
                    prev_key: String::new(),
                }
            }
            #[cfg(not(debug_assertions))]
            {
                Self {
                    consumer_key: client.identifier,
                    token: token.map(|t| t.identifier),
                    options,
                    authorization,
                    sign,
                    append_delim_to_sign: false,
                }
            }
        }
    }
}

impl<'a, SM: SignatureMethod> Authorizer<'a, SM> {
    fn append_to_header_encoded<V: Display>(&mut self, k: &str, v: V) {
        self.check_dictionary_order(k);
        write!(self.authorization, r#"{}="{}","#, k, v).unwrap();
        self.sign_delimiter();
    }

    fn sign_delimiter(&mut self) {
        if self.append_delim_to_sign {
            self.sign.delimiter();
        } else {
            self.append_delim_to_sign = true;
        }
    }

    fn check_dictionary_order(&mut self, _k: &str) {
        #[cfg(debug_assertions)]
        {
            assert!(
                *self.prev_key <= *_k,
                "appended key is less than previously appended one in dictionary order\
                 \n previous: `{:?}`,\
                 \n  current: `{:?}`",
                self.prev_key,
                _k,
            );
            self.prev_key.clear();
            self.prev_key.push_str(_k);
        }
    }
}

macro_rules! append_to_header {
    (@inner $self:expr, $k:ident, $v:expr, $w:expr) => {{
        let this = $self;
        let k = concat!("oauth_", stringify!($k));
        this.append_to_header_encoded(k, $v);
        this.sign.$k($w);
    }};
    ($self:expr, encoded $k:ident, $v:expr) => {{
        let v = $v;
        append_to_header!(@inner $self, $k, v, v);
    }};
    ($self:expr, $k:ident, $v:expr) => {{
        let v = $v;
        append_to_header!(@inner $self, $k, percent_encode(v), DoublePercentEncode(v));
    }};
}

impl<'a, SM: SignatureMethod> Serializer for Authorizer<'a, SM> {
    type Output = String;

    fn serialize_parameter<V: Display>(&mut self, k: &str, v: V) {
        self.check_dictionary_order(k);
        self.sign_delimiter();
        self.sign.parameter(k, DoublePercentEncode(v));
    }

    fn serialize_parameter_encoded<V: Display>(&mut self, k: &str, v: V) {
        self.check_dictionary_order(k);
        self.sign_delimiter();
        self.sign.parameter(k, PercentEncode(v));
    }

    fn serialize_oauth_callback(&mut self) {
        if let Some(c) = self.options.callback {
            append_to_header!(self, callback, c);
        }
    }

    fn serialize_oauth_consumer_key(&mut self) {
        append_to_header!(self, consumer_key, self.consumer_key);
    }

    fn serialize_oauth_nonce(&mut self) {
        if self.sign.use_nonce() {
            let mut nonce_buf;
            if let Some(n) = self.options.nonce {
                append_to_header!(self, nonce, n);
            } else {
                nonce_buf = Default::default();
                append_to_header!(self, encoded nonce, gen_nonce(&mut nonce_buf));
            }
        }
    }

    fn serialize_oauth_signature_method(&mut self) {
        let v = self.sign.get_signature_method_name();
        self.append_to_header_encoded("oauth_signature_method", v);
        self.sign.signature_method();
    }

    fn serialize_oauth_timestamp(&mut self) {
        if self.sign.use_timestamp() {
            let t = if let Some(t) = self.options.timestamp {
                t.get()
            } else {
                get_current_timestamp()
            };
            append_to_header!(self, encoded timestamp, t);
        }
    }

    fn serialize_oauth_token(&mut self) {
        if let Some(t) = self.token {
            append_to_header!(self, token, t);
        }
    }

    fn serialize_oauth_verifier(&mut self) {
        if let Some(v) = self.options.verifier {
            append_to_header!(self, verifier, v);
        }
    }

    fn serialize_oauth_version(&mut self) {
        if self.options.version {
            self.append_to_header_encoded("oauth_version", "1.0");
            self.sign.version();
        }
    }

    fn end(self) -> String {
        let Self {
            mut authorization,
            sign,
            ..
        } = self;

        authorization.push_str("oauth_signature=");
        write!(authorization, r#""{}""#, sign.end()).unwrap();

        authorization
    }
}

fn get_current_timestamp() -> u64 {
    cfg_if::cfg_if! {
        // `std::time::SystemTime::now` is not supported and panics on `wasm32-unknown-unknown` target
        if #[cfg(all(feature = "js", target_arch = "wasm32", target_os = "unknown"))] {
            (js_sys::Date::now() / 1000.0) as u64
        } else {
            use std::time::{SystemTime, UNIX_EPOCH};
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_secs(),
                Err(_) => 1,
            }
        }
    }
}

// This is worth 72 bits of entropy. The nonce is required to be unique across all requests with
// the same timestamp, client and token. Even if you generate the nonce one million times a second
// (which is unlikely unless you are DoS-ing the server or something), the expected time it takes
// until getting a collision is about 299 years (*), which should be sufficient in practice.
//
// (*): the probability that there is at least one nonce collision in a second is:
//     P = 1 - (2^72 - 1)/(2^72) * (2^72 - 2)/(2^72) * ... * (2^72 - 999999)/(2^72)
// (birthday problem), and the expected number of seconds it takes until getting a collision with
// the same timestamp is 1/P.
const NONCE_LEN: usize = 12;

fn gen_nonce(buf: &mut [u8; NONCE_LEN]) -> &str {
    let mut rng = thread_rng();

    let mut rand = [0u8; NONCE_LEN * 3 / 4];
    rng.fill_bytes(&mut rand);

    // Trim leading zeroes to be stingy.
    let i = rand.iter().position(|&b| b != 0).unwrap_or(rand.len());
    let rand = &rand[i..];

    let len = base64::encode_config_slice(&rand, base64::URL_SAFE_NO_PAD, buf);
    let buf = &buf[..len];

    debug_assert!(str::from_utf8(buf).is_ok(), "buf={:?}", buf);
    unsafe { str::from_utf8_unchecked(buf) }
}
