//! An OAuth 1.0 `Authorization` header serializer.

use std::fmt::{Display, Write};
use std::num::NonZeroU64;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::prelude::*;

use crate::signature_method::{Plaintext, Sign, SignatureMethod};
use crate::util::*;
use crate::{Credentials, Serializer};

/// A `Serializer` that produces an HTTP `Authorization` header string by signing a request
/// in OAuth 1.0 protocol.
#[derive(Clone, Debug)]
pub struct Authorizer<'a, SM: SignatureMethod> {
    consumer_key: &'a str,
    token: Option<&'a str>,
    options: &'a Options<'a>,
    authorization: String,
    sign: SM::Sign,
    append_delim: bool,
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
        /// Sets `oauth_nonce` parameter.
        nonce: Option<&'a str>,
        /// Sets `oauth_timestamp` parameter.
        ///
        /// The OAuth standard ([RFC 5849 section 3.3.][rfc]) says that the timestamp value
        /// MUST be a positive integer, so this method treats `0` as `None`.
        ///
        /// [rfc]: https://tools.ietf.org/html/rfc5849#section-3.3
        timestamp: Option<NonZeroU64>,
        /// Sets `oauth_verifier` parameter.
        verifier: Option<&'a str>,
        /// Sets whether to include `oauth_version="1.0"` parameter in the `Authorization` header.
        version: bool,
    }
}

/// A version of `Signer` that uses the `PLAINTEXT` signature method.
pub type PlaintextAuthorizer<'a> = Authorizer<'a, Plaintext>;

cfg_if::cfg_if! {
    if #[cfg(feature = "hmac-sha1")] {
        use crate::signature_method::HmacSha1;
        /// A version of `Signer` that uses the `HMAC-SHA1` signature method.
        pub type HmacSha1Authorizer<'a> = Authorizer<'a, HmacSha1>;
    }
}

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
        let mut sign = signature_method.sign_with(
            percent_encode(client.secret),
            token.as_ref().map(Credentials::secret).map(percent_encode),
        );

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
                    append_delim: false,
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
                    append_delim: false,
                }
            }
        }
    }

    fn append_to_header_encoded(&mut self, k: &str, v: impl Display) {
        self.check_dictionary_order(k);
        write!(self.authorization, r#"{}="{}","#, k, v).unwrap();
    }
}

impl<'a, SM: SignatureMethod> Authorizer<'a, SM> {
    fn append_to_signature(&mut self, k: &str, v: impl Display) {
        self.append_to_signature_encoded(k, DoublePercentEncode(v));
    }

    fn append_to_signature_encoded(&mut self, k: &str, v: impl Display) {
        self.append_to_signature_with(Sign::parameter, k, v);
    }

    fn append_to_signature_with<K, V, F>(&mut self, f: F, k: K, v: V)
    where
        F: FnOnce(&mut SM::Sign, K, V),
    {
        if self.append_delim {
            self.sign.delimiter();
        } else {
            self.append_delim = true;
        }
        f(&mut self.sign, k, v);
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

impl<'a, SM: SignatureMethod> Serializer for Authorizer<'a, SM> {
    type Output = String;

    fn serialize_parameter<V: Display>(&mut self, k: &str, v: V) {
        self.check_dictionary_order(k);
        self.append_to_signature(k, v);
    }

    fn serialize_parameter_encoded<V: Display>(&mut self, k: &str, v: V) {
        self.check_dictionary_order(k);
        self.append_to_signature_encoded(k, PercentEncode(v));
    }

    fn serialize_oauth_parameters(&mut self) {
        macro_rules! append {
            (@inner $k:ident, $v:expr, $w:expr) => {{
                let k = concat!("oauth_", stringify!($k));
                self.append_to_header_encoded(k, $v);
                self.append_to_signature_with(Sign::$k, k, $w);
            }};
            (encoded $k:ident, $v:expr) => {{
                let v = $v;
                append!(@inner $k, v, v);
            }};
            ($k:ident, $v:expr) => {{
                let v = $v;
                append!(@inner $k, percent_encode(v), DoublePercentEncode(v));
            }};
        }

        if let Some(c) = self.options.callback {
            append!(callback, c);
        }
        append!(consumer_key, self.consumer_key);
        if self.sign.use_nonce() {
            let nonce_buf;
            let nonce = if let Some(n) = self.options.nonce {
                n
            } else {
                nonce_buf = gen_nonce();
                unsafe { str::from_utf8_unchecked(&nonce_buf) }
            };
            append!(nonce, nonce);
        }
        append!(encoded signature_method, self.sign.get_signature_method_name());
        if self.sign.use_timestamp() {
            let t = if let Some(t) = self.options.timestamp {
                t.get()
            } else {
                match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(d) => d.as_secs(),
                    #[cold]
                    Err(_) => 1,
                }
            };
            append!(encoded timestamp, t);
        }
        if let Some(t) = self.token {
            append!(token, t);
        }
        if let Some(v) = self.options.verifier {
            append!(verifier, v);
        }
        if self.options.version {
            append!(encoded version, "1.0");
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

const NONCE_LEN: usize = 32;

fn gen_nonce() -> [u8; NONCE_LEN] {
    let mut ret = [0u8; NONCE_LEN];

    let mut rng = thread_rng();
    let mut rand = [0u8; NONCE_LEN * 6 / 8];
    rng.fill_bytes(&mut rand);

    let config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
    base64::encode_config_slice(&rand, config, &mut ret);

    ret
}
