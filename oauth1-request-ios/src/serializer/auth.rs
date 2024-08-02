//! An OAuth 1.0 `Authorization` header serializer.

use core::fmt::{self, Display, Write};
use core::num::NonZeroU64;
use core::str;

use base64::{Engine as _};
use rand::prelude::*;

use crate::signature_method::{Sign, SignatureMethod};
use crate::util::*;
use crate::Credentials;

use super::{Serializer, Urlencoder};

cfg_type_param_hack! {
    /// A `Serializer` that signs a request and produces OAuth 1.0 `oauth_*` parameter values.
    ///
    /// The resulting parameter values are either written to an HTTP `Authorization` header value or
    /// URI query/`x-www-form-urlencoded` string (along with the other request parameters)
    /// depending on the constructor you use.
    #[derive(Clone, Debug)]
    pub struct Authorizer<
        'a,
        SM: SignatureMethod,
        #[cfg(feature = "alloc")] W = alloc::string::String,
        #[cfg(not(feature = "alloc"))] W,
    > {
        consumer_key: &'a str,
        token: Option<&'a str>,
        options: &'a Options<'a>,
        data: Data<W>,
        sign: SM::Sign,
        append_delim_to_sign: bool,
        #[cfg(all(feature = "alloc", debug_assertions))]
        prev_key: alloc::string::String,
    }
}

#[derive(Clone, Debug)]
enum Data<W> {
    Authorization(W),
    Urlencode(Urlencoder<W>),
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

doc_auto_cfg! {
    #[cfg(feature = "alloc")]
    impl<'a, SM: SignatureMethod> Authorizer<'a, SM> {
        /// Creates an `Authorizer` that produces an HTTP `Authorization header value.
        ///
        /// `uri` must not contain a query part.
        /// Otherwise, the serializer will produce a wrong signature.
        ///
        /// # Panics
        ///
        /// In debug builds, panics if `uri` contains a `'?'` character.
        pub fn authorization<T: Display>(
            method: &str,
            uri: T,
            client: Credentials<&'a str>,
            token: Option<Credentials<&'a str>>,
            options: &'a Options<'a>,
            signature_method: SM,
        ) -> Self {
            let buf = alloc::string::String::with_capacity(512);
            Authorizer::authorization_with_buf(
                buf,
                method,
                uri,
                client,
                token,
                options,
                signature_method,
            )
        }

        /// Creates an `Authorizer` that produces an `x-www-form-urlencoded` string.
        ///
        /// `uri` must not contain a query part.
        /// Otherwise, the serializer will produce a wrong signature.
        ///
        /// # Panics
        ///
        /// In debug builds, panics if `uri` contains a `'?'` character.
        pub fn form<T: Display>(
            method: &str,
            uri: T,
            client: Credentials<&'a str>,
            token: Option<Credentials<&'a str>>,
            options: &'a Options<'a>,
            signature_method: SM,
        ) -> Self {
            let buf = alloc::string::String::with_capacity(512);
            Authorizer::form_with_buf(buf, method, uri, client, token, options, signature_method)
        }
    }
}

impl<'a, SM: SignatureMethod, W: Write> Authorizer<'a, SM, W> {
    /// Creates an `Authorizer` that appends a query part to `uri`.
    ///
    /// `uri` must not contain a query part.
    /// Otherwise, the serializer will produce a wrong signature.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `uri` contains a `'?'` character.
    pub fn query(
        method: &str,
        uri: W,
        client: Credentials<&'a str>,
        token: Option<Credentials<&'a str>>,
        options: &'a Options<'a>,
        signature_method: SM,
    ) -> Self
    where
        W: Display,
    {
        let sign = make_sign(method, &uri, client, token, signature_method);
        let data = Data::Urlencode(Urlencoder::query(uri));
        Authorizer::new_(data, sign, client, token, options)
    }

    /// Same as `authorization` except that this writes the resulting `Authorization` header value
    /// into `buf`.
    pub fn authorization_with_buf<T: Display>(
        mut buf: W,
        method: &str,
        uri: T,
        client: Credentials<&'a str>,
        token: Option<Credentials<&'a str>>,
        options: &'a Options<'a>,
        signature_method: SM,
    ) -> Self {
        buf.write_str("OAuth ").unwrap();
        let data = Data::Authorization(buf);
        let sign = make_sign(method, uri, client, token, signature_method);
        Authorizer::new_(data, sign, client, token, options)
    }

    /// Same with `form` except that this writes the resulting form string into `buf`.
    pub fn form_with_buf<T: Display>(
        buf: W,
        method: &str,
        uri: T,
        client: Credentials<&'a str>,
        token: Option<Credentials<&'a str>>,
        options: &'a Options<'a>,
        signature_method: SM,
    ) -> Self {
        let data = Data::Urlencode(Urlencoder::form_with_buf(buf));
        let sign = make_sign(method, uri, client, token, signature_method);
        Authorizer::new_(data, sign, client, token, options)
    }

    fn new_(
        data: Data<W>,
        sign: SM::Sign,
        client: Credentials<&'a str>,
        token: Option<Credentials<&'a str>>,
        options: &'a Options<'a>,
    ) -> Self {
        cfg_if::cfg_if! {
            if #[cfg(all(feature = "alloc", debug_assertions))] {
                Authorizer {
                    consumer_key: client.identifier,
                    token: token.map(|t| t.identifier),
                    options,
                    data,
                    sign,
                    append_delim_to_sign: false,
                    prev_key: alloc::string::String::new(),
                }
            } else {
                Authorizer {
                    consumer_key: client.identifier,
                    token: token.map(|t| t.identifier),
                    options,
                    data,
                    sign,
                    append_delim_to_sign: false,
                }
            }
        }
    }
}

fn make_sign<SM: SignatureMethod, T: Display>(
    method: &str,
    uri: T,
    client: Credentials<&str>,
    token: Option<Credentials<&str>>,
    signature_method: SM,
) -> SM::Sign {
    // This is a no_alloc-equivalent of `assert!(!uri.to_string().contains('?'))`.
    // We can determine if the URI contains a query part by just checking if it contains a `'?'`
    // character, because the scheme and authority part of a valid URI does not contain
    // that character.
    #[cfg(debug_assertions)]
    {
        struct AssertNotContainQuestion;
        impl Write for AssertNotContainQuestion {
            #[track_caller]
            fn write_str(&mut self, uri: &str) -> fmt::Result {
                assert!(!uri.contains('?'), "`uri` must not contain a query part");
                Ok(())
            }
        }
        write!(AssertNotContainQuestion, "{}", uri).unwrap();
    }

    let mut ret = signature_method.sign_with(client.secret, token.map(|t| t.secret));
    ret.request_method(method);
    ret.uri(PercentEncode(uri));

    ret
}

impl<'a, SM: SignatureMethod, W: Write> Authorizer<'a, SM, W> {
    fn append_to_header_encoded<V: Display>(&mut self, k: &str, v: V) {
        self.check_dictionary_order(k);
        match self.data {
            Data::Authorization(ref mut header) => write!(header, r#"{}="{}","#, k, v).unwrap(),
            Data::Urlencode(ref mut encoder) => encoder.serialize_parameter_encoded(k, v),
        }
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
        #[cfg(all(feature = "alloc", debug_assertions))]
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

impl<'a, SM: SignatureMethod, W: Write> Serializer for Authorizer<'a, SM, W> {
    type Output = W;

    fn serialize_parameter<V: Display>(&mut self, key: &str, value: V) {
        self.check_dictionary_order(key);
        self.sign_delimiter();
        self.sign.parameter(key, DoublePercentEncode(value));
    }

    fn serialize_parameter_encoded<V: Display>(&mut self, key: &str, value: V) {
        self.check_dictionary_order(key);
        self.sign_delimiter();
        self.sign.parameter(key, PercentEncode(value));
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
            if let Some(n) = self.options.nonce {
                append_to_header!(self, nonce, n);
            } else {
                let mut nonce_buf = Default::default();
                append_to_header!(self, encoded nonce, gen_nonce(&mut nonce_buf, &mut get_rng()));
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

    fn end(self) -> W {
        let Self { data, sign, .. } = self;

        match data {
            Data::Authorization(mut header) => {
                header.write_str("oauth_signature=").unwrap();
                write!(header, r#""{}""#, sign.end()).unwrap();
                header
            }
            Data::Urlencode(mut encoder) => {
                encoder.serialize_parameter_encoded("oauth_signature", sign.end());
                encoder.end()
            }
        }
    }
}

fn get_current_timestamp() -> u64 {
    cfg_if::cfg_if! {
        // `std::time::SystemTime::now` is not supported and panics on `wasm32-unknown-unknown` target
        if #[cfg(all(feature = "js", target_arch = "wasm32", target_os = "unknown"))] {
            (js_sys::Date::now() / 1000.0) as u64
        } else if #[cfg(feature = "std")] {
            use std::time::{SystemTime, UNIX_EPOCH};
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_secs(),
                Err(_) => 1,
            }
        } else {
            panic!(
                "Attempted to get current timestamp in `no_std` mode. You must either use a \
                signature method that do not use timestamp (i.e. SignatureMethod::Sign::timestamp` \
                returns `true`) or explicitly set the timestamp via `Builder::timestamp` or \
                `serializer::auth::Options::timestamp`",
            );
        }
    }
}

fn get_rng() -> impl RngCore + CryptoRng {
    cfg_if::cfg_if! {
        if #[cfg(feature = "std")] {
            thread_rng()
        } else {
            rand::rngs::OsRng
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

fn gen_nonce<'a, R: RngCore + CryptoRng>(buf: &'a mut [u8; NONCE_LEN], rng: &mut R) -> &'a str {
    let mut rand = [0_u8; NONCE_LEN * 3 / 4];
    rng.fill_bytes(&mut rand);

    // Trim leading zeroes to be stingy.
    let i = rand.iter().position(|&b| b != 0).unwrap_or(rand.len());
    let rand = &rand[i..];

    let len = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(rand, buf)
        .unwrap();
    let buf = &buf[..len];

    str::from_utf8(buf).unwrap()
}
