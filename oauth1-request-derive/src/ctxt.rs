use core::fmt::Display;
use std::mem;

use proc_macro2::Span;
use syn::Error;

pub struct Ctxt {
    error: Option<Error>,
}

impl Ctxt {
    pub fn new() -> Self {
        Self { error: None }
    }

    pub fn add_error(&mut self, error: Error) {
        if let Some(ref mut e) = self.error {
            e.combine(error);
        } else {
            self.error = Some(error);
        }
    }

    pub fn add_error_message<T: Display>(&mut self, span: Span, msg: T) {
        self.add_error(Error::new(span, msg));
    }

    pub fn take_error(mut self) -> Option<Error> {
        let error = self.error.take();
        mem::forget(self);
        error
    }
}

impl Drop for Ctxt {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            panic!("must call `Ctxt::take_error`");
        }
    }
}
