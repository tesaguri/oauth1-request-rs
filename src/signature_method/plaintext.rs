//! The `PLAINTEXT` signature method ([RFC 5849 section 3.4.4.][rfc]).
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4.4

use std::fmt::Display;

use super::*;

/// The `PLAINTEXT` signature method.
#[derive(Copy, Clone, Debug, Default)]
pub struct Plaintext;

/// A `Sign` implementation that just returns the signing key used to construct it.
#[derive(Clone, Debug)]
pub struct PlaintextSign(String);

impl SignatureMethod for Plaintext {
    type Sign = PlaintextSign;

    fn sign_with(
        self,
        consumer_secret: impl Display,
        token_secret: Option<impl Display>,
    ) -> PlaintextSign {
        let mut key = String::with_capacity(128);
        write_signing_key(&mut key, consumer_secret, token_secret);
        PlaintextSign(key)
    }
}

impl Sign for PlaintextSign {
    type Signature = String;

    fn get_signature_method_name(&self) -> &'static str {
        "PLAINTEXT"
    }

    fn request_method(&mut self, _method: &str) {}

    fn uri(&mut self, _uri: impl Display) {}

    fn parameter(&mut self, _key: &str, _value: impl Display) {}

    fn delimiter(&mut self) {}

    fn finish(self) -> String {
        self.0
    }

    // The OAuth standard (section 3.1.) says that `oauth_timestamp` and `oauth_nonce` parameters
    // MAY be omitted when using the `PLAINTEXT` signature method. So, technically, we could
    // override `use_nonce` and `use_timestamp` so as not to use the parameters. However,
    // OAuth Core 1.0 Revision A (https://oauth.net/core/1.0a/) specification used to require these
    // parameters. So, we don't override the methods here for compatibility's sake.
}
