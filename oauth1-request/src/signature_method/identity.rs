//! A pseudo signature method for debugging purpose.

use core::fmt::{self, Debug, Display, Formatter, Write};
use core::marker::PhantomData;

use super::{Sign, SignatureMethod};

/// A pseudo signature method that just returns the signature base string as the signature.
#[derive(Copy)]
pub struct Identity<
    #[cfg(feature = "alloc")] W = alloc::string::String,
    #[cfg(not(feature = "alloc"))] W,
> {
    marker: PhantomData<fn() -> W>,
}

/// A `Sign` implementation that just returns the signature base string.
#[derive(Clone, Debug)]
pub struct IdentitySign<
    #[cfg(feature = "alloc")] W = alloc::string::String,
    #[cfg(not(feature = "alloc"))] W,
>(pub W);

#[cfg(feature = "alloc")]
impl Identity {
    /// Creates a new `Identity`.
    pub fn new() -> Self {
        Identity {
            marker: PhantomData,
        }
    }
}

impl<W> Identity<W>
where
    W: Default + Display + Write,
{
    // See the comment in `impl<W> Plaintext<W>` block for the rationale behind defining two
    // constructors.

    /// Creates a new `Identity` that writes the resulting signatures into `W` values.
    pub fn with_buf() -> Self {
        Identity {
            marker: PhantomData,
        }
    }
}

impl<W> Clone for Identity<W> {
    fn clone(&self) -> Self {
        Identity {
            marker: PhantomData,
        }
    }
}

impl<W> Debug for Identity<W> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[derive(Debug)]
        struct Identity;
        Identity.fmt(f)
    }
}

impl<W> Default for Identity<W>
where
    W: Default + Display + Write,
{
    fn default() -> Self {
        Self::with_buf()
    }
}

impl<W> SignatureMethod for Identity<W>
where
    W: Default + Display + Write,
{
    type Sign = IdentitySign<W>;

    fn sign_with(self, _client_secret: &str, _token_secret: Option<&str>) -> Self::Sign {
        IdentitySign(W::default())
    }
}

impl<W> Sign for IdentitySign<W>
where
    W: Display + Write,
{
    type Signature = W;

    fn get_signature_method_name(&self) -> &'static str {
        "IDENTITY"
    }

    fn request_method(&mut self, method: &str) {
        self.0.write_str(method).unwrap();
        self.0.write_char('&').unwrap();
    }

    fn uri<T: Display>(&mut self, uri: T) {
        write!(self.0, "{}", uri).unwrap();
        self.0.write_char('&').unwrap();
    }

    fn parameter<V: Display>(&mut self, key: &str, value: V) {
        self.0.write_str(key).unwrap();
        self.0.write_str("%3D").unwrap(); // '='
        write!(self.0, "{}", value).unwrap();
    }

    fn delimiter(&mut self) {
        self.0.write_str("%26").unwrap(); // '&'
    }

    fn end(self) -> W {
        self.0
    }
}
