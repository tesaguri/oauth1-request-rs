//! A pseudo signature method for debugging purpose.

use super::*;

/// A pseudo signature method that just returns the signature base string as the signature.
#[derive(Copy, Clone, Debug, Default)]
pub struct Identity;

/// A `Sign` implementation that just returns the signature base string.
#[derive(Clone, Debug)]
pub struct IdentitySign(pub String);

impl SignatureMethod for Identity {
    type Sign = IdentitySign;

    fn sign_with(
        self,
        _consumer_secret: impl Display,
        _token_secret: Option<impl Display>,
    ) -> IdentitySign {
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

    fn uri(&mut self, uri: impl Display) {
        write!(self.0, "{}", uri).unwrap();
        self.0.push('&');
    }

    fn parameter(&mut self, key: &str, value: impl Display) {
        self.0.push_str(key);
        self.0.push_str("%3D"); // '='
        write!(self.0, "{}", value).unwrap();
    }

    fn delimiter(&mut self) {
        self.0.push_str("%26"); // '&'
    }

    fn finish(self) -> String {
        self.0
    }
}
