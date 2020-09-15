mod oauth_parameter;

pub use oauth_parameter::OAuthParameter;

use std::ops::Deref;

use proc_macro2::{Ident, Span, TokenStream, TokenTree};
use quote::{quote_spanned, ToTokens};

impl OAuthParameter {
    fn serialize_method_name(self) -> Option<&'static str> {
        match self {
            OAuthParameter::Callback => Some("serialize_oauth_callback"),
            OAuthParameter::ConsumerKey => Some("serialize_oauth_consumer_key"),
            OAuthParameter::Nonce => Some("serialize_oauth_nonce"),
            OAuthParameter::SignatureMethod => Some("serialize_oauth_signature_method"),
            OAuthParameter::Timestamp => Some("serialize_oauth_timestamp"),
            OAuthParameter::Token => Some("serialize_oauth_token"),
            OAuthParameter::Verifier => Some("serialize_oauth_verifier"),
            OAuthParameter::Version => Some("serialize_oauth_version"),
            OAuthParameter::None => None,
        }
    }
}

impl<'a> ToTokens for OAuthParameter {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let method = self
            .serialize_method_name()
            .expect("called `to_tokens` on `OAuthParameter::None`");
        let ident = Ident::new(method, Span::call_site());
        tokens.extend(std::iter::once(TokenTree::Ident(ident)));
    }
}

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
