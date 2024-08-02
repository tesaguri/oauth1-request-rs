//! The `RSA-SHA1` signature method ([RFC 5849 section 3.4.3.][rfc]).
//!
//! [rfc]: https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.3
//!
//! This module is only available when `rsa-sha1-06` feature is activated.

use rsa06 as rsa;

use self::rsa::{Hash, PaddingScheme};

fn new_pkcs1v15_sign() -> PaddingScheme {
    PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1))
}

include!("rsa_sha1.rs");
