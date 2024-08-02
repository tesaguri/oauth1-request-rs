//! The `RSA-SHA1` signature method ([RFC 5849 section 3.4.3.][rfc]).
//!
//! [rfc]: https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.3
//!
//! This module is only available when `rsa-sha1-09` feature is activated.

use rsa09 as rsa;

use self::rsa::Pkcs1v15Sign;

fn new_pkcs1v15_sign() -> Pkcs1v15Sign {
    Pkcs1v15Sign::new::<Sha1>()
}

include!("rsa_sha1.rs");
