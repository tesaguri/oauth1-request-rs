//! Low-level machinery to convert a `Request` to a signature or a URI query/form string.

pub mod auth;
pub mod urlencode;

pub use auth::Authorizer;
pub use urlencode::Urlencoder;

use core::fmt::Display;

/// Helper macro for implementors of `Serializer` which generates blank implementation of
/// `serialize_oauth_*` methods.
///
/// This is useful for implementing a `Serializer` that does not involve OAuth authorization
/// process (e.g. [`Urlencoder`]).
#[macro_export]
macro_rules! skip_serialize_oauth_parameters {
    () => {
        fn serialize_oauth_callback(&mut self) {}
        fn serialize_oauth_consumer_key(&mut self) {}
        fn serialize_oauth_nonce(&mut self) {}
        fn serialize_oauth_signature_method(&mut self) {}
        fn serialize_oauth_timestamp(&mut self) {}
        fn serialize_oauth_token(&mut self) {}
        fn serialize_oauth_verifier(&mut self) {}
        fn serialize_oauth_version(&mut self) {}
    };
}

#[doc(inline)]
pub use skip_serialize_oauth_parameters;

/// A `Serializer` will be fed with the key-value pairs of a request
/// and produces a single value from them.
///
/// A `Request` implementation `serialize`s itself by feeding a `Serializer` with its key-value
/// pairs through the serializer's `serialize_*` methods. The `serialize_*` method calls correspond
/// to appending parameters to the signature base string ([RFC 5849 section 3.4.1.][rfc]) of
/// the OAuth request, and the key-value pairs must be serialized in ascending dictionary order.
///
/// [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4.1
///
#[cfg_attr(all(feature = "alloc", feature = "hmac-sha1"), doc = " ```")]
#[cfg_attr(not(all(feature = "alloc", feature = "hmac-sha1")), doc = " ```ignore")]
/// # extern crate oauth1_request as oauth;
/// #
/// use std::num::NonZeroU64;
///
/// use oauth::serializer::auth::{self, Authorizer};
/// use oauth::serializer::{Serializer, SerializerExt};
///
/// // Create an OAuth 1.0 `Authorization` header serializer.
/// let client = oauth::Credentials::new("consumer_key", "consumer_secret");
/// let token = oauth::Credentials::new("token", "token_secret");
/// let options = auth::Options::new();
/// # let mut options = options;
/// # options.nonce("mo8_whwD5c91").timestamp(NonZeroU64::new(1234567890));
/// let mut serializer = Authorizer::authorization(
///     "GET",
///     "https://example.com/api/v1/get.json",
///     client,
///     Some(token),
///     &options,
///     oauth::HmacSha1::new(),
/// );
///
/// // The parameters must be serialized in ascending ordering.
/// serializer.serialize_parameter("abc", "value");
/// serializer.serialize_parameter("lmn", "something");
///
/// // Add `oauth_*` parameters to the signature base string.
/// serializer.serialize_oauth_parameters();
///
/// // Continue serializing parameters greater than `oauth_*=...`.
/// serializer.serialize_parameter("qrs", "stuff");
/// serializer.serialize_parameter("xyz", "blah-blah");
///
/// let authorization = serializer.end();
///
/// assert_eq!(
///     authorization,
///     "OAuth \
///      oauth_consumer_key=\"consumer_key\",\
///      oauth_nonce=\"mo8_whwD5c91\",\
///      oauth_signature_method=\"HMAC-SHA1\",\
///      oauth_timestamp=\"1234567890\",\
///      oauth_token=\"token\",\
///      oauth_signature=\"eC5rUmIcYvAaIIWCIvOwhgUDByk%3D\"",
/// );
/// ```
pub trait Serializer {
    /// The type of the value produced by this serializer.
    type Output;

    /// Serializes a key-value pair.
    ///
    /// The serializer percent encodes the value, but not the key.
    ///
    /// # Panics
    ///
    /// The parameters must be serialized in byte ascending order
    /// and implementations may panic otherwise.
    fn serialize_parameter<V>(&mut self, k: &str, v: V)
    where
        V: Display;

    /// Serializes a key-value pair.
    ///
    /// This treats the value as already percent encoded and will not encode it again.
    ///
    /// # Panics
    ///
    /// The parameters must be serialized in byte ascending order
    /// and implementations may panic otherwise.
    fn serialize_parameter_encoded<V>(&mut self, k: &str, v: V)
    where
        V: Display;

    /// Appends `oauth_callback` parameter to the `Authorization` header.
    ///
    /// This must be called exactly once in a serialization process.
    fn serialize_oauth_callback(&mut self);

    /// Appends `oauth_consumer_key` parameter to the `Authorization` header.
    ///
    /// This must be called exactly once in a serialization process.
    fn serialize_oauth_consumer_key(&mut self);

    /// Appends `oauth_nonce` parameter to the `Authorization` header.
    ///
    /// This must be called exactly once in a serialization process.
    fn serialize_oauth_nonce(&mut self);

    /// Appends `oauth_signature_method` parameter to the `Authorization` header.
    ///
    /// This must be called exactly once in a serialization process.
    fn serialize_oauth_signature_method(&mut self);

    /// Appends `oauth_timestamp` parameter to the `Authorization` header.
    ///
    /// This must be called exactly once in a serialization process.
    fn serialize_oauth_timestamp(&mut self);

    /// Appends `oauth_token` parameter to the `Authorization` header.
    ///
    /// This must be called exactly once in a serialization process.
    fn serialize_oauth_token(&mut self);

    /// Appends `oauth_verifier` parameter to the `Authorization` header.
    ///
    /// This must be called exactly once in a serialization process.
    fn serialize_oauth_verifier(&mut self);

    /// Appends `oauth_version` parameter to the `Authorization` header.
    ///
    /// This must be called exactly once in a serialization process.
    fn serialize_oauth_version(&mut self);

    /// Finalizes the serialization and returns the serialized value.
    fn end(self) -> Self::Output;
}

/// An extension trait for `Serializer` that provides convenience methods.
pub trait SerializerExt: Serializer {
    /// Appends all `oauth_*` parameter to the `Authorization` header.
    fn serialize_oauth_parameters(&mut self);
}

impl<S: Serializer> SerializerExt for S {
    fn serialize_oauth_parameters(&mut self) {
        self.serialize_oauth_callback();
        self.serialize_oauth_consumer_key();
        self.serialize_oauth_nonce();
        self.serialize_oauth_signature_method();
        self.serialize_oauth_timestamp();
        self.serialize_oauth_token();
        self.serialize_oauth_verifier();
        self.serialize_oauth_version();
    }
}

#[cfg(test)]
#[cfg(feature = "hmac-sha1")]
mod tests {
    extern crate std;

    use core::num::NonZeroU64;
    use std::format;
    use std::println;
    use std::string::{String, ToString};

    use super::*;

    use crate::serializer::auth;
    use crate::signature_method::{HmacSha1, Identity, Plaintext, Sign, SignatureMethod};
    use crate::Credentials;

    // These values are taken from Twitter's document:
    // https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature.html
    const CK: &str = "xvz1evFS4wEEPTGEFPHBog";
    const CS: &str = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
    const AK: &str = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb";
    const AS: &str = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";
    const NONCE: &str = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
    const TIMESTAMP: u64 = 1318622958;

    struct Inspect<SM>(SM);
    struct InspectSign<S>(S);

    impl<SM: SignatureMethod> SignatureMethod for Inspect<SM> {
        type Sign = InspectSign<SM::Sign>;

        fn sign_with(self, client_secret: &str, token_secret: Option<&str>) -> Self::Sign {
            println!("client_secret: {:?}", client_secret);
            println!("token_secret: {:?}", token_secret);
            InspectSign(self.0.sign_with(client_secret, token_secret))
        }
    }

    #[derive(Clone, Debug)]
    struct AssertImpl<'a>(
        Authorizer<'a, HmacSha1, String>,
        Authorizer<'a, Identity<String>, String>,
        Authorizer<'a, Plaintext<String>, String>,
    );

    impl<S: Sign> Sign for InspectSign<S> {
        type Signature = S::Signature;

        fn get_signature_method_name(&self) -> &'static str {
            self.0.get_signature_method_name()
        }
        fn request_method(&mut self, method: &str) {
            println!("method: {:?}", method);
            self.0.request_method(method);
        }
        fn uri<T: Display>(&mut self, uri: T) {
            println!("uri: {:?}", uri.to_string());
            self.0.uri(uri);
        }
        fn delimiter(&mut self) {
            println!("delimiter");
            self.0.delimiter();
        }
        fn parameter<V: Display>(&mut self, k: &str, v: V) {
            println!("parameter: {:?}={:?}", k, v.to_string());
            self.0.parameter(k, v);
        }
        fn end(self) -> S::Signature {
            println!("end");
            self.0.end()
        }
    }

    #[test]
    fn serialize() {
        macro_rules! test {
            ($((
                $method:expr, $ep:expr,
                $ck:expr, $cs:expr, $t:expr, $ts:expr,
                $nonce:expr, $timestamp:expr,
                { $($param1:tt)* }, { $($param2:tt)* } $(,)*
            ) -> ($expected_sign:expr, $expected_data:expr $(,)*);)*) => {
                let client = Credentials::new(CK, CS);
                let token = Credentials::new(AK, AS);
                let mut options = auth::Options::new();
                $(
                    options.nonce($nonce)
                        .timestamp($timestamp)
                        .version(true);
                    let mut auth = Authorizer::authorization_with_buf(
                        String::new(),
                        $method,
                        $ep,
                        client,
                        Some(token),
                        &options,
                        Inspect(HmacSha1::new()),
                    );

                    test_inner! { auth; $($param1)* }
                    auth.serialize_oauth_parameters();
                    test_inner! { auth; $($param2)* }

                    let authorization = auth.end();
                    let expected = format!(
                        "OAuth \
                        oauth_consumer_key=\"{}\",\
                        oauth_nonce=\"{}\",\
                        oauth_signature_method=\"HMAC-SHA1\",\
                        oauth_timestamp=\"{}\",\
                        oauth_token=\"{}\",\
                        oauth_version=\"1.0\",\
                        oauth_signature=\"{}\"",
                        $ck,
                        $nonce,
                        $timestamp,
                        token.identifier,
                        $expected_sign,
                    );
                    assert_eq!(authorization, expected);

                    let mut urlencoded = if $method == "POST" {
                        Urlencoder::form()
                    } else {
                        Urlencoder::query($ep.to_string())
                    };

                    test_inner! { urlencoded; $($param1)* }
                    urlencoded.serialize_oauth_parameters();
                    test_inner! { urlencoded; $($param2)* }

                    let data = urlencoded.end();
                    assert_eq!(data, $expected_data);
                )*
            };
        }

        macro_rules! test_inner {
            ($ser:ident; encoded $key:ident: $v:expr, $($rest:tt)*) => {
                $ser.serialize_parameter_encoded(stringify!($key), $v);
                test_inner! { $ser; $($rest)* }
            };
            ($ser:ident; $key:ident: $v:expr, $($rest:tt)*) => {
                $ser.serialize_parameter(stringify!($key), $v);
                test_inner! { signerb; $($rest)* }
            };
            ($_signer:ident;) => ();
        }

        let timestamp = NonZeroU64::new(TIMESTAMP).unwrap();

        test! {
            (
                "GET", "https://stream.twitter.com/1.1/statuses/sample.json",
                CK, CS, AK, AS, NONCE, timestamp,
                {}, { encoded stall_warnings: "true", },
            ) -> (
                "OGQqcy4l5xWBFX7t0DrkP5%2FD0rM%3D",
                "https://stream.twitter.com/1.1/statuses/sample.json?stall_warnings=true",
            );
            (
                "POST", "https://api.twitter.com/1.1/statuses/update.json",
                CK, CS, AK, AS, NONCE, timestamp,
                { encoded include_entities: "true", },
                { status: "Hello Ladies + Gentlemen, a signed OAuth request!", },
            ) -> (
                "hCtSmYh%2BiHYCEqBWrE7C7hYmtUk%3D",
                "include_entities=true&\
                    status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21",
            );
            ("POST", "https://example.com/post.json", CK, CS, AK, AS, NONCE, timestamp, {}, {})
                -> ("pN52L1gJ6sOyYOyv23cwfWFsIZc%3D", "");
            (
                "GET", "https://example.com/get.json",
                CK, CS, AK, AS, NONCE, timestamp,
                { encoded bar: "%E9%85%92%E5%A0%B4", foo: "ふー", }, {},
            ) -> (
                "Xp35hf3T21yhpEuxez7p6bV62Bw%3D",
                "https://example.com/get.json?bar=%E9%85%92%E5%A0%B4&foo=%E3%81%B5%E3%83%BC",
            );
        }
    }

    #[cfg(all(feature = "alloc", debug_assertions))]
    #[test]
    #[should_panic(
        expected = "appended key is less than previously appended one in dictionary order\
                    \n previous: `\"foo\"`,\
                    \n  current: `\"bar\"`"
    )]
    fn panic_on_misordering() {
        let client = Credentials::new(CK, CS);
        let token = Credentials::new(AK, AS);
        let options = auth::Options::default();
        let mut ser = Authorizer::authorization_with_buf(
            String::new(),
            "",
            "",
            client,
            Some(token),
            &options,
            Plaintext::<String>::with_buf(),
        );
        ser.serialize_parameter_encoded("foo", true);
        ser.serialize_parameter("bar", "ばー！");
    }
}
