//! The `HMAC-SHA1` signature method ([RFC 5849 section 3.4.2.][rfc]).
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4.2
//!
//! This module is only available when `hmac-sha1` feature is activated.

extern crate base64;
extern crate hmac;
extern crate sha1;

use std::fmt::{self, Formatter};

use self::base64::display::Base64Display;
use self::hmac::{Hmac, Mac};
use self::sha1::digest::generic_array::sequence::GenericSequence;
use self::sha1::digest::generic_array::{ArrayLength, GenericArray};
use self::sha1::digest::{BlockInput, FixedOutput, Input, Reset};
use self::sha1::Sha1;

use super::*;
use util::PercentEncode;

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
    signature: GenericArray<u8, <Sha1 as FixedOutput>::OutputSize>,
}

struct MacWrite<'a, M: 'a>(&'a mut M);

#[derive(Clone)]
enum SigningKey<D: BlockInput> {
    Key {
        buf: GenericArray<u8, D::BlockSize>,
        pos: usize,
    },
    Digest(D),
}

impl SignatureMethod for HmacSha1 {
    type Sign = HmacSha1Sign;

    fn sign_with(
        self,
        consumer_secret: impl Display,
        token_secret: Option<impl Display>,
    ) -> HmacSha1Sign {
        let mut key = SigningKey::new();
        write_signing_key(&mut key, consumer_secret, token_secret);
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
        self.mac.input(method.as_bytes());
        self.mac.input(b"&");
    }

    fn uri(&mut self, uri: impl Display) {
        write!(MacWrite(&mut self.mac), "{}&", uri).unwrap();
    }

    fn parameter(&mut self, key: &str, value: impl Display) {
        self.mac.input(key.as_bytes());
        self.mac.input(b"%3D"); // '='
        write!(MacWrite(&mut self.mac), "{}", value).unwrap();
    }

    fn delimiter(&mut self) {
        self.mac.input(b"%26"); // '&'
    }

    fn finish(self) -> HmacSha1Signature {
        HmacSha1Signature {
            signature: self.mac.result().code(),
        }
    }
}

impl Display for HmacSha1Signature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let d = PercentEncode(Base64Display::with_config(&self.signature, base64::STANDARD));
        Display::fmt(&d, f)
    }
}

impl<'a, M: Mac> Write for MacWrite<'a, M> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.input(s.as_bytes());
        Ok(())
    }
}

impl<D> SigningKey<D>
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8> + Clone,
    D::OutputSize: ArrayLength<u8>,
{
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
            } => if input.len() > buf.len() - *pos {
                let mut digest = D::default();
                digest.input(&buf[..*pos]);
                digest.input(input);
                SigningKey::Digest(digest)
            } else {
                buf[*pos..(*pos + input.len())].copy_from_slice(input);
                *pos += input.len();
                return;
            },
            SigningKey::Digest(ref mut digest) => {
                digest.input(input);
                return;
            }
        };
    }

    fn into_hmac(self) -> Hmac<D> {
        match self {
            SigningKey::Key { ref buf, pos } => Hmac::new_varkey(&buf[..pos]).unwrap(),
            SigningKey::Digest(digest) => Hmac::new_varkey(&digest.fixed_result()).unwrap(),
        }
    }
}

impl<D> Write for SigningKey<D>
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8> + Clone,
    D::OutputSize: ArrayLength<u8>,
{
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::hmac::crypto_mac::generic_array::typenum::Unsigned;
    use super::*;

    #[test]
    fn signing_key() {
        let mut sk = SigningKey::<Sha1>::new();
        let mut k = Vec::new();

        for _ in 0..=<Sha1 as BlockInput>::BlockSize::to_usize() + 1 {
            sk.write(&[1]);
            k.extend(&[1]);

            let mut skm = sk.clone().into_hmac();
            let mut m = Hmac::<Sha1>::new_varkey(&k).unwrap();
            skm.input(b"test");
            m.input(b"test");

            assert_eq!(skm.result().code(), m.result().code());
        }
    }
}
