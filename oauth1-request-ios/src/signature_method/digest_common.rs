use core::fmt::{self, Display, Formatter, Write};

use base64::display::Base64Display;
use digest::Update;

use crate::util::PercentEncode;

#[derive(Clone, Debug)]
pub struct UpdateSign<U>(pub U);

pub struct Base64PercentEncodeDisplay<A>(pub A);

struct UpdateWrite<'a, M>(&'a mut M);

impl<U: Update> UpdateSign<U> {
    pub fn request_method(&mut self, method: &str) {
        self.0.update(method.as_bytes());
        self.0.update(b"&");
    }

    pub fn uri<T: Display>(&mut self, uri: T) {
        write!(UpdateWrite(&mut self.0), "{}&", uri).unwrap();
    }

    pub fn parameter<V: Display>(&mut self, key: &str, value: V) {
        self.0.update(key.as_bytes());
        self.0.update(b"%3D"); // '='
        write!(UpdateWrite(&mut self.0), "{}", value).unwrap();
    }

    pub fn delimiter(&mut self) {
        self.0.update(b"%26"); // '&'
    }
}

impl<A: AsRef<[u8]>> Display for Base64PercentEncodeDisplay<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let d = PercentEncode(Base64Display::new(
            self.0.as_ref(),
            &base64::engine::general_purpose::STANDARD,
        ));
        Display::fmt(&d, f)
    }
}

impl<'a, M: Update> Write for UpdateWrite<'a, M> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.update(s.as_bytes());
        Ok(())
    }
}
