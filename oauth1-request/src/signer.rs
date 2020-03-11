//! A low-level type for signing requests with OAuth.

use std::fmt::{Display, Write};
use std::marker::PhantomData;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::prelude::*;

use crate::signature_method::{Plaintext, Sign, SignatureMethod};
use crate::util::*;
use crate::{Options, Request};

/// A low-level type for creating a signed `Request`.
///
/// # Example
///
/// Creating a `GET` request:
///
/// ```rust
/// # extern crate oauth1_request as oauth;
/// use oauth::signer;
///
/// let mut sign = signer::HmacSha1Signer::new(
///     "GET",
///     "https://example.com/api/v1/get.json",
///     "consumer_secret",
///     "token_secret", // or `None`
/// );
///
/// // The parameters must be appended in the ascending ordering.
/// sign.parameter("abc", "value")
///     .parameter("lmn", "something");
///
/// // Append `oauth_*` parameters.
/// let mut sign = sign.oauth_parameters(
///     "consumer_key",
///     &*oauth::Options::new()
///         .token("token")
///         .nonce("nonce")
///         .timestamp(9999999999),
/// );
///
/// sign.parameter("qrs", "stuff")
///     .parameter("xyz", "blah-blah");
///
/// let oauth::Request { authorization, data } = sign.finish();
///
/// assert_eq!(
///     authorization,
///     "OAuth \
///      oauth_consumer_key=\"consumer_key\",\
///      oauth_nonce=\"nonce\",\
///      oauth_signature_method=\"HMAC-SHA1\",\
///      oauth_timestamp=\"9999999999\",\
///      oauth_token=\"token\",\
///      oauth_signature=\"R1%2B4C7PHNUwA2TyMeNZDo0T8lSM%3D\"",
/// );
/// assert_eq!(
///     data,
///     "https://example.com/api/v1/get.json?abc=value&lmn=something&qrs=stuff&xyz=blah-blah",
/// );
/// ```
///
/// Creating an `x-www-form-urlencoded` request
///
/// ```rust
/// # extern crate oauth1_request as oauth;
/// # use oauth::signer;
/// // Use `new_form` method to create an `x-www-form-urlencoded` string.
/// let mut sign = signer::HmacSha1Signer::new_form(
///     "POST",
///     "https://example.com/api/v1/post.json",
///     "consumer_secret",
///     "token_secret", // or `None`
/// );
///
/// // ...
/// // (same as the above example...)
/// # sign.parameter("abc", "value").parameter("lmn", "something");
/// # let mut sign = sign.oauth_parameters(
/// #     "consumer_key",
/// #     &*oauth::Options::new().token("token").nonce("nonce").timestamp(9999999999),
/// # );
/// # sign.parameter("qrs", "stuff").parameter("xyz", "blah-blah");
///
/// let oauth::Request { authorization, data } = sign.finish();
///
/// assert_eq!(
///     authorization,
///     "OAuth \
///      oauth_consumer_key=\"consumer_key\",\
///      oauth_nonce=\"nonce\",\
///      oauth_signature_method=\"HMAC-SHA1\",\
///      oauth_timestamp=\"9999999999\",\
///      oauth_token=\"token\",\
///      oauth_signature=\"YUOk%2FeMb2r%2BAF5wW0H%2FgEx%2FoLp0%3D\"",
/// );
/// assert_eq!(
///     data,
///     "abc=value&lmn=something&qrs=stuff&xyz=blah-blah",
/// );
/// ```
#[derive(Clone, Debug)]
pub struct Signer<SM: SignatureMethod, State = NotReady> {
    inner: Inner<SM::Sign>,
    state: PhantomData<fn() -> State>,
}

/// Represents the state of a `Signer` before `oauth_parameters` method is called.
#[derive(Clone, Debug)]
pub struct NotReady(Never);

/// Represents the state of a `Signer` after `oauth_parameters` method is called.
#[derive(Clone, Debug)]
pub struct Ready(Never);

/// A version of `Signer` that uses the `PLAINTEXT` signature method.
pub type PlaintextSigner<State = NotReady> = Signer<Plaintext, State>;

cfg_if::cfg_if! {
    if #[cfg(feature = "hmac-sha1")] {
        use crate::signature_method::HmacSha1;
        /// A version of `Signer` that uses the `HMAC-SHA1` signature method.
        pub type HmacSha1Signer<State = NotReady> = Signer<HmacSha1, State>;
    }
}

#[derive(Clone, Debug)]
struct Inner<S> {
    authorization: String,
    data: String,
    sign: S,
    next_append: Append,
    #[cfg(debug_assertions)]
    prev_key: String,
}

bitflags::bitflags! {
    struct Append: u8 {
        const QUESTION   = 0b001;
        const AMPERSAND  = 0b010;
        const SIGN_DELIM = 0b100;
    }
}

impl<SM: SignatureMethod> Signer<SM, NotReady> {
    /// Returns a `Signer` that appends query string to `uri` and returns it as `Request.data`.
    ///
    /// `uri` must not contain a query part. Otherwise, the `Signer` will produce a wrong signature.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `uri` contains a `'?'` character.
    pub fn new<'a>(
        method: &str,
        uri: impl Display,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
    ) -> Self
    where
        SM: Default,
    {
        Self::with_signature_method(
            Default::default(),
            method,
            uri,
            consumer_secret,
            token_secret,
        )
    }

    /// Same as `new` except that this uses `signature_method` as the signature method.
    pub fn with_signature_method<'a>(
        signature_method: SM,
        method: &str,
        uri: impl Display,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
    ) -> Self {
        Self::new_(
            method,
            uri,
            consumer_secret,
            token_secret.into(),
            signature_method,
            true,
        )
    }

    /// Returns a `Signer` that creates an x-www-form-urlencoded string and returns it as
    /// `Request.data`.
    ///
    /// `uri` must not contain a query part. Otherwise, the `Signer` will produce a wrong signature.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `uri` contains a `'?'` character.
    pub fn new_form<'a>(
        method: &str,
        uri: impl Display,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
    ) -> Self
    where
        SM: Default,
    {
        Self::form_with_signature_method(
            Default::default(),
            method,
            uri,
            consumer_secret,
            token_secret,
        )
    }

    /// Same as `new_form` except that this uses `signature_method` as the signature method.
    pub fn form_with_signature_method<'a>(
        signature_method: SM,
        method: &str,
        uri: impl Display,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
    ) -> Self {
        Self::new_(
            method,
            uri,
            consumer_secret,
            token_secret.into(),
            signature_method,
            false,
        )
    }

    pub(crate) fn new_(
        method: &str,
        uri: impl Display,
        cs: &str,
        ts: Option<&str>,
        sm: SM,
        q: bool,
    ) -> Self {
        let mut sign = sm.sign_with(percent_encode(cs), ts.map(percent_encode));

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

        let data = if q {
            let data = uri.to_string();
            sign.uri(percent_encode(&data));
            data
        } else {
            sign.uri(PercentEncode(uri));
            String::new()
        };

        let next_append = if q { Append::QUESTION } else { Append::empty() };

        let inner = {
            #[cfg(debug_assertions)]
            {
                Inner {
                    authorization,
                    data,
                    sign,
                    next_append,
                    prev_key: String::new(),
                }
            }
            #[cfg(not(debug_assertions))]
            {
                Inner {
                    authorization,
                    data,
                    sign,
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
    pub fn oauth_parameters<'a>(
        self,
        consumer_key: &str,
        options: impl Into<Option<&'a Options<'a>>>,
    ) -> Signer<SM, Ready> {
        // Let's cross fingers and hope that this will be optimized into a `static`.
        let default = Options::new();
        let options = options.into().unwrap_or(&default);
        self.oauth_parameters_(consumer_key, options)
    }

    fn oauth_parameters_(mut self, ck: &str, opts: &Options<'_>) -> Signer<SM, Ready> {
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

        if let Some(c) = opts.callback {
            append!(callback, c);
        }
        append!(consumer_key, ck);
        if self.inner.sign.use_nonce() {
            let nonce_buf;
            let nonce = if let Some(n) = opts.nonce {
                n
            } else {
                nonce_buf = gen_nonce();
                unsafe { str::from_utf8_unchecked(&nonce_buf) }
            };
            append!(nonce, nonce);
        }
        append!(encoded signature_method, self.inner.sign.get_signature_method_name());
        if self.inner.sign.use_timestamp() {
            let t = if let Some(t) = opts.timestamp {
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
        if let Some(t) = opts.token {
            append!(token, t);
        }
        if let Some(v) = opts.verifier {
            append!(verifier, v);
        }
        if opts.version {
            append!(encoded version, "1.0");
        }

        Signer {
            inner: self.inner,
            state: PhantomData,
        }
    }

    fn append_to_header_encoded(&mut self, k: &str, v: impl Display) {
        self.check_dictionary_order(k);
        write!(self.inner.authorization, r#"{}="{}","#, k, v).unwrap();
    }
}

impl<SM: SignatureMethod, State> Signer<SM, State> {
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
    pub fn parameter(&mut self, k: &str, v: impl Display) -> &mut Self {
        self.check_dictionary_order(k);
        self.append_delim();
        write!(self.inner.data, "{}={}", k, PercentEncode(&v)).unwrap();
        self.append_to_signature(k, v);
        self
    }

    /// Appends a parameter to the query/form string and signing key.
    ///
    /// Unlike `parameter`, this will not percent encode the value.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if the key is not appended in ascending order.
    #[inline]
    pub fn parameter_encoded(&mut self, k: &str, v: impl Display) -> &mut Self {
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
        if self.inner.next_append.contains(Append::SIGN_DELIM) {
            self.inner.sign.delimiter();
        } else {
            self.inner.next_append.insert(Append::SIGN_DELIM);
        }
        f(&mut self.inner.sign, k, v);
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

impl<SM: SignatureMethod> Signer<SM, NotReady> {
    /// Shorthand for `self.oauth_parameters(consumer_key, options).finish()`.
    pub fn finish<'a>(
        self,
        consumer_key: &str,
        options: impl Into<Option<&'a Options<'a>>>,
    ) -> Request {
        self.oauth_parameters(consumer_key, options).finish()
    }
}

impl<SM: SignatureMethod> Signer<SM, Ready> {
    /// Consumes the `Signer` and returns a `Request`.
    pub fn finish(self) -> Request {
        let Inner {
            mut authorization,
            data,
            sign,
            ..
        } = self.inner;

        authorization.push_str("oauth_signature=");
        write!(authorization, r#""{}""#, sign.finish()).unwrap();

        Request {
            authorization,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_method::Identity;

    // These values are taken from Twitter's document:
    // https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature.html
    const CK: &str = "xvz1evFS4wEEPTGEFPHBog";
    const CS: &str = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
    const AK: Option<&str> = Some("370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb");
    const AS: Option<&str> = Some("LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE");
    const NONCE: &str = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
    const TIMESTAMP: u64 = 1318622958;

    struct Inspect<SM>(SM);
    struct InspectSign<S>(S);

    impl<SM: SignatureMethod> SignatureMethod for Inspect<SM> {
        type Sign = InspectSign<SM::Sign>;

        fn sign_with(self, cs: impl Display, ts: Option<impl Display>) -> Self::Sign {
            println!("cs: {:?}", cs.to_string());
            println!("ts: {:?}", ts.as_ref().map(ToString::to_string));
            InspectSign(self.0.sign_with(cs, ts))
        }
    }

    #[derive(Clone, Debug)]
    struct AssertImpl(HmacSha1Signer, PlaintextSigner, Identity, Ready);

    impl<S: Sign> Sign for InspectSign<S> {
        type Signature = S::Signature;

        fn get_signature_method_name(&self) -> &'static str {
            self.0.get_signature_method_name()
        }
        fn request_method(&mut self, method: &str) {
            println!("method: {:?}", method);
            self.0.request_method(method);
        }
        fn uri(&mut self, uri: impl Display) {
            println!("uri: {:?}", uri.to_string());
            self.0.uri(uri);
        }
        fn delimiter(&mut self) {
            println!("delimiter");
            self.0.delimiter();
        }
        fn parameter(&mut self, k: &str, v: impl Display) {
            println!("parameter: {:?}={:?}", k, v.to_string());
            self.0.parameter(k, v);
        }
        fn finish(self) -> S::Signature {
            println!("finish");
            self.0.finish()
        }
    }

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
                    Signer::form_with_signature_method
                } else {
                    Signer::with_signature_method
                }(Inspect(HmacSha1), $method, $ep, $cs, $ts);

                test_inner! { signer; $($param1)* }
                #[allow(unused_mut)]
                let mut signer = signer.oauth_parameters(
                    $ck,
                    &*Options::new()
                        .token($t)
                        .nonce($nonce)
                        .timestamp($timestamp)
                        .version(true),
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
                $signer.parameter_encoded(stringify!($key), $v);
                test_inner! { $signer; $($rest)* }
            };
            ($signer:ident; $key:ident: $v:expr, $($rest:tt)*) => {
                $signer.parameter(stringify!($key), $v);
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
        PlaintextSigner::new("", "", "", None)
            .parameter_encoded("foo", true)
            .parameter("bar", "ばー！");
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
