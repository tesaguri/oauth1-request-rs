//! A pseudo signature method for debugging purpose.

use std::fmt::{Display, Write};

use super::{Sign, SignatureMethod};

/// A pseudo signature method that just returns the signature base string as the signature.
#[derive(Copy, Clone, Debug, Default)]
pub struct Identity;

/// A `Sign` implementation that just returns the signature base string.
#[derive(Clone, Debug)]
pub struct IdentitySign(pub String);

impl SignatureMethod for Identity {
    type Sign = IdentitySign;

    fn sign_with(self, _client_secret: &str, _token_secret: Option<&str>) -> IdentitySign {
        IdentitySign(String::new())
    }
}

impl Sign for IdentitySign {
    type Signature = String;

    fn get_signature_method_name(&self) -> &'static str {
        "IDENTITY"
    }

    fn request_method(&mut self, method: &str) {
        self.0.push_str(method);
        self.0.push('&');
    }

    fn uri<T: Display>(&mut self, uri: T) {
        write!(self.0, "{}", uri).unwrap();
        self.0.push('&');
    }

    fn parameter<V: Display>(&mut self, key: &str, value: V) {
        self.0.push_str(key);
        self.0.push_str("%3D"); // '='
        write!(self.0, "{}", value).unwrap();
    }

    fn delimiter(&mut self) {
        self.0.push_str("%26"); // '&'
    }

    fn end(self) -> String {
        self.0
    }
}
