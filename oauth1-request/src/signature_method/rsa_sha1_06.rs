//! The `RSA-SHA1` signature method ([RFC 5849 section 3.4.3.][rfc]).
//!
//! [rfc]: https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.3
//!
//! This module is only available when `rsa-sha1-06` feature is activated.

extern crate alloc;

pub use rsa06::pkcs8::DecodePrivateKey;
pub use rsa06::RsaPrivateKey;

use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};

use digest::Digest;
use rsa06::{Hash, PaddingScheme};
use sha1::Sha1;

use super::digest_common::{Base64PercentEncodeDisplay, UpdateSign};
use super::{Sign, SignatureMethod};

/// The `RSA-SHA1` signature method.
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct RsaSha1 {
    key: RsaPrivateKey,
}

/// A type that signs a signature base string with the RSA-SHA1 signature algorithm.
#[derive(Clone, Debug)]
pub struct RsaSha1Sign<K = RsaPrivateKey> {
    inner: UpdateSign<Sha1>,
    key: K,
}

/// A signature produced by an `RsaSha1Sign`.
pub struct RsaSha1Signature {
    inner: Base64PercentEncodeDisplay<Vec<u8>>,
}

impl RsaSha1 {
    /// Creates a new `RsaSha1` that signs a signature base string with the given RSA private key.
    pub const fn new(key: RsaPrivateKey) -> Self {
        RsaSha1 { key }
    }
}

impl From<RsaPrivateKey> for RsaSha1 {
    fn from(key: RsaPrivateKey) -> Self {
        RsaSha1::new(key)
    }
}

impl AsRef<RsaSha1> for RsaPrivateKey {
    fn as_ref(&self) -> &RsaSha1 {
        #[allow(clippy::needless_lifetimes)] // Adding the lifetime annotations just to be sure.
        fn inner<'a>(key: &'a RsaPrivateKey) -> &'a RsaSha1 {
            // Safety:
            // - The `#[repr(transparent)]` attribute ensures that `RsaSha1` has the same layout as
            //   `RsaPrivateKey`.
            // - The lifetime annotations ensure that the output lives for the same lifetime as
            //   the input.
            unsafe { &*(key as *const RsaPrivateKey).cast::<RsaSha1>() }
        }
        inner(self)
    }
}

impl SignatureMethod for RsaSha1 {
    type Sign = RsaSha1Sign;

    fn sign_with(self, _client_secret: &str, _token_secret: Option<&str>) -> Self::Sign {
        RsaSha1Sign {
            inner: UpdateSign(Sha1::default()),
            key: self.key,
        }
    }
}

impl<'a> SignatureMethod for &'a RsaSha1 {
    type Sign = RsaSha1Sign<&'a RsaPrivateKey>;

    fn sign_with(self, _client_secret: &str, _token_secret: Option<&str>) -> Self::Sign {
        RsaSha1Sign {
            inner: UpdateSign(Sha1::default()),
            key: &self.key,
        }
    }
}

impl<'a> Sign for RsaSha1Sign {
    type Signature = RsaSha1Signature;

    fn get_signature_method_name(&self) -> &'static str {
        "RSA-SHA1"
    }

    fn request_method(&mut self, method: &str) {
        self.inner.request_method(method);
    }

    fn uri<T: Display>(&mut self, uri: T) {
        self.inner.uri(uri);
    }

    fn parameter<V: Display>(&mut self, key: &str, value: V) {
        self.inner.parameter(key, value);
    }

    fn delimiter(&mut self) {
        self.inner.delimiter();
    }

    fn end(self) -> RsaSha1Signature {
        RsaSha1Sign {
            inner: self.inner,
            key: &self.key,
        }
        .end()
    }
}

impl<'a> Sign for RsaSha1Sign<&'a RsaPrivateKey> {
    type Signature = RsaSha1Signature;

    fn get_signature_method_name(&self) -> &'static str {
        "RSA-SHA1"
    }

    fn request_method(&mut self, method: &str) {
        self.inner.request_method(method);
    }

    fn uri<T: Display>(&mut self, uri: T) {
        self.inner.uri(uri);
    }

    fn parameter<V: Display>(&mut self, key: &str, value: V) {
        self.inner.parameter(key, value);
    }

    fn delimiter(&mut self) {
        self.inner.delimiter();
    }

    fn end(self) -> RsaSha1Signature {
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1));
        let digest = self.inner.0.finalize();
        let signature = self.key.sign(padding, &digest).unwrap();
        RsaSha1Signature {
            inner: Base64PercentEncodeDisplay(signature),
        }
    }
}

impl Display for RsaSha1Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::util::percent_encode;

    use super::*;

    #[test]
    fn test() {
        // Test case from <https://wiki.oauth.net/w/page/12238556/TestCases>.

        let der =
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8VA7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJhI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8HX9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mmuScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmwrn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0ZzO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+NccnqkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNGWPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUnocn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54Lw03eHTNQghS0A==";
        let der = base64::decode(der).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_der(&der).unwrap();

        let signature_method: &RsaSha1 = private_key.as_ref();
        let mut sign = signature_method.sign_with("", None);

        sign.request_method("GET");
        sign.uri("http%3A%2F%2Fphotos.example.net%2Fphotos");
        sign.parameter("file", "vacaction.jpg");
        sign.delimiter();
        sign.consumer_key("dpf43f3p2l4k3l03");
        sign.delimiter();
        sign.nonce("13917289812797014437");
        sign.delimiter();
        sign.signature_method();
        sign.delimiter();
        sign.timestamp(1196666512);
        sign.delimiter();
        sign.version();
        sign.delimiter();
        sign.parameter("size", "original");

        let signature = sign.end();
        let expected =
            percent_encode("jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26dyF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE=")
                .to_string();
        assert_eq!(signature.to_string(), expected);
    }
}
