//! Signature methods ([RFC 5849 section 3.4.][rfc]).
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4
//!
//! The OAuth standard allows for servers to implement their own custom signature methods.
//! So the module provides an abstraction over signature methods so that users can implement those
//! custom methods by themselves.

doc_auto_cfg! {
    #[cfg(feature = "hmac-sha1")]
    pub mod hmac_sha1;
    pub mod plaintext;
    #[cfg(feature = "rsa-sha1-06")]
    pub mod rsa_sha1_06;
}

#[cfg(any(feature = "hmac-sha1", feature = "rsa-sha1-06"))]
mod digest_common;
#[cfg(feature = "either")]
mod either;

doc_auto_cfg! {
    #[cfg(feature = "hmac-sha1")]
    pub use self::hmac_sha1::HmacSha1;
    #[cfg(feature = "hmac-sha1")]
    pub use self::hmac_sha1::HMAC_SHA1;
    pub use self::plaintext::Plaintext;
    #[cfg(feature = "alloc")]
    pub use self::plaintext::PLAINTEXT;
    #[cfg(feature = "rsa-sha1-06")]
    pub use self::rsa_sha1_06::RsaSha1;
}

use core::fmt::{self, Display, Write};

use crate::util::percent_encode;

/// Types that represent a signature method.
///
/// This is used to construct a `Self::Sign` and carries configuration data for them.
pub trait SignatureMethod {
    /// The algorithm used by this signature method to sign a signature base string.
    type Sign: Sign;

    /// Creates a `Self::Sign` that signs a signature base string with the given shared-secrets.
    fn sign_with(self, client_secret: &str, token_secret: Option<&str>) -> Self::Sign;
}

macro_rules! provide {
    ($(#[doc = $doc:expr])+ $name:ident, $($rest:tt)*) => {
        $(#[doc = $doc])+
        fn $name<V: Display>(&mut self, value: V) {
            self.parameter(concat!("oauth_", stringify!($name)), value);
        }
        provide! { $($rest)* }
    };
    ($name:ident, $($rest:tt)*) => {
        provide! {
            #[doc = concat!(
"Feeds `self` with the `oauth_", stringify!($name), "` parameter part of the signature base string.

The default implementation forwards to the `parameter` method with `\"oauth_",
stringify!($name), "\"` as the first argument."
            )]
            $name, $($rest)*
        }
    };
    () => {};
}

/// Algorithms to sign a signature base string ([RFC 5849 section 3.4.1.][rfc]).
///
/// [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4.1
///
/// The type will be incrementally passed a signature base string by a `Serializer`. For example,
/// a signature base string like the following (line breaks are for display purposes only):
///
/// ```text
/// POST&
/// http%3A%2F%2Fexample.com%2Frequest&
/// a%3Dr%2520b
/// %26
/// a2%3Da
/// %26
/// oauth_consumer_key%3D9djdj82h48djs9d2
/// %26
/// oauth_nonce%3D7d8f3e4a
/// %26
/// oauth_signature_method%3DHMAC-SHA1
/// %26
/// oauth_timestamp%3D137131201
/// %26
/// oauth_token%3Dkkk9d7dh3k39sjv7
/// %26
/// z%3D
/// ```
///
/// ...is represented by a series of method calls like the following (`sign` is the `Sign` object):
///
#[cfg_attr(feature = "alloc", doc = " ```")]
#[cfg_attr(not(feature = "alloc"), doc = " ```ignore")]
/// # use oauth1_request::signature_method::{Sign, SignatureMethod, PLAINTEXT};
/// # let mut sign = PLAINTEXT.sign_with("", Some(""));
/// sign.request_method("POST");
/// sign.uri("http%3A%2F%2Fexample.com%2Frequest");
/// sign.parameter("a", "r%2520b");
/// sign.delimiter();
/// sign.parameter("a2", "a");
/// sign.delimiter();
/// sign.consumer_key("9djdj82h48djs9d2");
/// sign.delimiter();
/// sign.nonce("7d8f3e4a");
/// sign.delimiter();
/// sign.signature_method();
/// sign.delimiter();
/// sign.timestamp(137131201);
/// sign.delimiter();
/// sign.token("kkk9d7dh3k39sjv7");
/// sign.delimiter();
/// sign.parameter("z", "");
/// let _ = sign.end();
/// ```
pub trait Sign {
    /// The URL-encoded representation of `oauth_signature` string the algorithm produces.
    type Signature: Display;

    /// Returns the `oauth_signature_method` string for the signature method associated with the
    /// algorithm.
    fn get_signature_method_name(&self) -> &'static str;

    /// Feeds `self` with the HTTP request method part of the signature base string.
    fn request_method(&mut self, method: &str);

    /// Feeds `self` with the base string URI part of the signature base string.
    fn uri<T: Display>(&mut self, uri: T);

    /// Feeds `self` with a key-value parameter pair of the signature base string.
    ///
    /// Implementors can reproduce the part of the signature base string the arguments represent
    /// by `format!("{}%3D{}", key, value)`.
    fn parameter<V: Display>(&mut self, key: &str, value: V);

    /// Feeds `self` with the delimiter (`%26`) between parameters.
    fn delimiter(&mut self);

    /// Finalizes the signing process and returns the resulting signature.
    fn end(self) -> Self::Signature;

    provide! { callback, consumer_key, nonce, }

    /// Whether the signature method uses the `oauth_nonce` parameter.
    ///
    /// If this method returns `false`, `Serializer` implementations should not emit the
    /// `oauth_nonce` part of the signature base string.
    ///
    /// The default implementation returns `true`.
    fn use_nonce(&self) -> bool {
        true
    }

    /// Feeds `self` with the `oauth_signature_method` parameter part of the
    /// signature base string.
    ///
    /// The default implementation forwards to the `parameter` method with
    /// `"oauth_signature_method"` and `self.get_signature_method_name()` as the arguments.
    fn signature_method(&mut self) {
        self.parameter("oauth_signature_method", self.get_signature_method_name());
    }

    /// Feeds `self` with the `oauth_timestamp` parameter part of the
    /// signature base string.
    ///
    /// The default implementation forwards to the `parameter` method with
    /// `"oauth_timestamp"` as the first argument.
    fn timestamp(&mut self, value: u64) {
        self.parameter("oauth_timestamp", value);
    }

    /// Whether the signature method uses the `oauth_nonce` parameter.
    ///
    /// If this method returns `false`, `Serializer` implementations should not emit the
    /// `oauth_nonce` part of the signature base string.
    ///
    /// The default implementation returns `true`.
    fn use_timestamp(&self) -> bool {
        true
    }

    provide! { token, verifier, }

    /// Feeds `self` with the `oauth_version` parameter part of the signature base string.
    ///
    /// The default implementation forwards to the `parameter` method with
    /// `"oauth_version"` and `"1.0"` as the arguments.
    fn version(&mut self) {
        self.parameter("oauth_version", "1.0");
    }
}

fn write_signing_key<W: Write>(
    dst: &mut W,
    client_secret: &str,
    token_secret: Option<&str>,
) -> fmt::Result {
    write!(dst, "{}", percent_encode(client_secret))?;
    dst.write_str("&")?;
    if let Some(ts) = token_secret {
        write!(dst, "{}", percent_encode(ts))?;
    }
    Ok(())
}
