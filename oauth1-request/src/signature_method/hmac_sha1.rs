//! The `HMAC-SHA1` signature method ([RFC 5849 section 3.4.2.][rfc]).
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4.2
//!
//! This module is only available when `hmac-sha1` feature is activated.

use std::fmt::{self, Formatter};

use base64::display::Base64Display;
use hmac::{Hmac, Mac, NewMac};
use sha1::digest::generic_array::sequence::GenericSequence;
use sha1::digest::generic_array::{ArrayLength, GenericArray};
use sha1::digest::{BlockInput, FixedOutput, Reset, Update};
use sha1::Sha1;

use super::*;
use crate::util::PercentEncode;

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

struct MacWrite<'a, M>(&'a mut M);

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

    fn sign_with<C, T>(self, consumer_secret: C, token_secret: Option<T>) -> HmacSha1Sign
    where
        C: Display,
        T: Display,
    {
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

impl<D> SigningKey<D>
where
    D: BlockInput + FixedOutput + Reset + Update + Default + Clone,
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
            } => {
                if input.len() > buf.len() - *pos {
                    let mut digest = D::default();
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

    fn into_hmac(self) -> Hmac<D> {
        match self {
            SigningKey::Key { ref buf, pos } => Hmac::new_varkey(&buf[..pos]).unwrap(),
            SigningKey::Digest(digest) => Hmac::new_varkey(&digest.finalize_fixed()).unwrap(),
        }
    }
}

impl<D> Write for SigningKey<D>
where
    D: BlockInput + FixedOutput + Reset + Update + Default + Clone,
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
    use hmac::crypto_mac::generic_array::typenum::Unsigned;

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
            skm.update(b"test");
            m.update(b"test");

            assert_eq!(skm.finalize().into_bytes(), m.finalize().into_bytes());
        }
    }
}
