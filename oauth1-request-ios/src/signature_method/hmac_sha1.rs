//! The `HMAC-SHA1` signature method ([RFC 5849 section 3.4.2.][rfc]).
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4.2
//!
//! This module is only available when `hmac-sha1` feature is activated.

use core::fmt::{self, Debug, Display, Formatter, Write};

use digest::core_api::BlockSizeUser;
use digest::generic_array::sequence::GenericSequence;
use digest::generic_array::GenericArray;
use digest::OutputSizeUser;
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};

use super::digest_common::{Base64PercentEncodeDisplay, UpdateSign};
use super::{write_signing_key, Sign, SignatureMethod};

/// The `HMAC-SHA1` signature method.
#[derive(Clone, Copy, Default)]
pub struct HmacSha1 {
    _priv: (),
}

/// A type that signs a signature base string with the HMAC-SHA1 signature algorithm.
#[derive(Clone, Debug)]
pub struct HmacSha1Sign {
    inner: UpdateSign<Hmac<Sha1>>,
}

/// A signature produced by an `HmacSha1Sign`.
pub struct HmacSha1Signature {
    inner: Base64PercentEncodeDisplay<GenericArray<u8, <Sha1 as OutputSizeUser>::OutputSize>>,
}

/// The `HMAC-SHA1` signature method with a default configuration.
pub const HMAC_SHA1: HmacSha1 = HmacSha1::new();

#[derive(Clone)]
enum SigningKey {
    Key {
        buf: GenericArray<u8, <Sha1 as BlockSizeUser>::BlockSize>,
        pos: usize,
    },
    Digest(Sha1),
}

impl HmacSha1 {
    /// Creates a new `HmacSha1`.
    pub const fn new() -> Self {
        HmacSha1 { _priv: () }
    }
}

impl Debug for HmacSha1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[derive(Debug)]
        struct HmacSha1;
        HmacSha1.fmt(f)
    }
}

impl SignatureMethod for HmacSha1 {
    type Sign = HmacSha1Sign;

    fn sign_with(self, client_secret: &str, token_secret: Option<&str>) -> HmacSha1Sign {
        let mut key = SigningKey::new();
        write_signing_key(&mut key, client_secret, token_secret).unwrap();
        HmacSha1Sign {
            inner: UpdateSign(key.into_hmac()),
        }
    }
}

impl Sign for HmacSha1Sign {
    type Signature = HmacSha1Signature;

    fn get_signature_method_name(&self) -> &'static str {
        "HMAC-SHA1"
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

    fn end(self) -> HmacSha1Signature {
        HmacSha1Signature {
            inner: Base64PercentEncodeDisplay(self.inner.0.finalize().into_bytes()),
        }
    }
}

impl Display for HmacSha1Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl SigningKey {
    fn new() -> Self {
        SigningKey::Key {
            buf: GenericArray::generate(|_| 0),
            pos: 0,
        }
    }

    fn write(&mut self, input: &[u8]) {
        *self = match *self {
            SigningKey::Key {
                ref mut buf,
                ref mut pos,
            } => {
                if input.len() > buf.len() - *pos {
                    let mut digest = Sha1::default();
                    digest.update(&buf[..*pos]);
                    digest.update(input);
                    SigningKey::Digest(digest)
                } else {
                    buf[*pos..(*pos + input.len())].copy_from_slice(input);
                    *pos += input.len();
                    return;
                }
            }
            SigningKey::Digest(ref mut digest) => {
                digest.update(input);
                return;
            }
        };
    }

    fn into_hmac(self) -> Hmac<Sha1> {
        match self {
            SigningKey::Key { ref buf, pos } => Hmac::new_from_slice(&buf[..pos]).unwrap(),
            SigningKey::Digest(digest) => Hmac::new_from_slice(&digest.finalize()).unwrap(),
        }
    }
}

impl Write for SigningKey {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use digest::generic_array::typenum::Unsigned;

    use super::*;

    #[test]
    fn signing_key() {
        let mut sk = SigningKey::new();
        let mut k = Vec::new();

        for _ in 0..=<Sha1 as BlockSizeUser>::BlockSize::to_usize() + 1 {
            sk.write(&[1]);
            k.extend(&[1]);

            let mut skm = sk.clone().into_hmac();
            let mut m = Hmac::<Sha1>::new_from_slice(&k).unwrap();
            skm.update(b"test");
            m.update(b"test");

            assert_eq!(skm.finalize().into_bytes(), m.finalize().into_bytes());
        }
    }
}
