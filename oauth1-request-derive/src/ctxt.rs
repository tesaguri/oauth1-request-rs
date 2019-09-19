use std::mem;

use proc_macro2::{Span, TokenStream};
use quote::ToTokens;

use util::error;

pub struct Ctxt {
    errors: Option<TokenStream>,
}

impl Ctxt {
    pub fn new() -> Self {
        Self {
            errors: Some(TokenStream::new()),
        }
    }

    pub fn error(&mut self, msg: &str, span: Span) {
        error(msg, span).to_tokens(self.errors.as_mut().unwrap());
    }

    pub fn emit_errors(mut self) -> Option<TokenStream> {
        let errors = self.errors.take().unwrap();
        mem::forget(self);
        if errors.is_empty() {
            None
        } else {
            Some(errors)
        }
    }
}

impl Drop for Ctxt {
    fn drop(&mut self) {
        if !::std::thread::panicking() {
            panic!("must call `Ctxt::emit_errors`");
        }
    }
}
