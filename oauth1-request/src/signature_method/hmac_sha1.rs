//! The `HMAC-SHA1` signature method ([RFC 5849 section 3.4.2.][rfc]).
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4.2
//!
//! This module is only available when `hmac-sha1` feature is activated.

use std::fmt::{self, Formatter};

use base64::display::Base64Display;
use hmac::{Hmac, Mac};
use sha1::digest::core_api::BlockSizeUser;
use sha1::digest::generic_array::sequence::GenericSequence;
use sha1::digest::generic_array::GenericArray;
use sha1::digest::OutputSizeUser;
use sha1::{Digest, Sha1};

use crate::util::PercentEncode;

use super::*;

/// The `HMAC-SHA1` signature method.
#[derive(Copy, Clone, Debug, Default)]
pub struct HmacSha1;

/// A type that signs a signature base string with the HMAC-SHA1 signature algorithm.
#[derive(Clone, Debug)]
pub struct HmacSha1Sign {
    mac: Hmac<Sha1>,
}

/// A signature produced by an `HmacSha1Sign`.
pub struct HmacSha1Signature {
    signature: GenericArray<u8, <Sha1 as OutputSizeUser>::OutputSize>,
}

struct MacWrite<'a, M>(&'a mut M);

#[derive(Clone)]
enum SigningKey {
    Key {
        buf: GenericArray<u8, <Sha1 as BlockSizeUser>::BlockSize>,
        pos: usize,
    },
    Digest(Sha1),
}

impl SignatureMethod for HmacSha1 {
    type Sign = HmacSha1Sign;

    fn sign_with(self, client_secret: &str, token_secret: Option<&str>) -> HmacSha1Sign {
        let mut key = SigningKey::new();
        write_signing_key(&mut key, client_secret, token_secret);
        HmacSha1Sign {
            mac: key.into_hmac(),
        }
    }
}

impl Sign for HmacSha1Sign {
    type Signature = HmacSha1Signature;

    fn get_signature_method_name(&self) -> &'static str {
        "HMAC-SHA1"
    }

    fn request_method(&mut self, method: &str) {
        self.mac.update(method.as_bytes());
        self.mac.update(b"&");
    }

    fn uri<T: Display>(&mut self, uri: T) {
        write!(MacWrite(&mut self.mac), "{}&", uri).unwrap();
    }

    fn parameter<V: Display>(&mut self, key: &str, value: V) {
        self.mac.update(key.as_bytes());
        self.mac.update(b"%3D"); // '='
        write!(MacWrite(&mut self.mac), "{}", value).unwrap();
    }

    fn delimiter(&mut self) {
        self.mac.update(b"%26"); // '&'
    }

    fn end(self) -> HmacSha1Signature {
        HmacSha1Signature {
            signature: self.mac.finalize().into_bytes(),
        }
    }
}

impl Display for HmacSha1Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let d = PercentEncode(Base64Display::with_config(
            &self.signature,
            base64::STANDARD,
        ));
        Display::fmt(&d, f)
    }
}

impl<'a, M: Mac> Write for MacWrite<'a, M> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.update(s.as_bytes());
        Ok(())
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
    use sha1::digest::generic_array::typenum::Unsigned;

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
