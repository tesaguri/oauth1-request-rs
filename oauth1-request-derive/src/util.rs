use std::ops::Deref;

use proc_macro2::{Span, TokenStream};
use quote::ToTokens;

pub struct ReSpanned<T> {
    tokens: T,
    span: Span,
}

impl<T> ReSpanned<T> {
    pub fn new(tokens: T, span: Span) -> Self {
        ReSpanned { tokens, span }
    }

    pub fn as_ref<U: ?Sized>(&self) -> ReSpanned<&U>
    where
        T: AsRef<U>,
    {
        ReSpanned::new(self.tokens.as_ref(), self.span)
    }

    pub fn span(&self) -> Span {
        self.span
    }
}

impl<T> Deref for ReSpanned<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.tokens
    }
}

impl<T: ToTokens> ToTokens for ReSpanned<T> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let toks = (&self.tokens)
            .into_token_stream()
            .into_iter()
            .map(|mut tt| {
                tt.set_span(self.span);
                tt
            });
        tokens.extend(toks)
    }
}

pub fn error(msg: &str, span: Span) -> TokenStream {
    quote_spanned!(span=>
        compile_error!(#msg);
    )
}
