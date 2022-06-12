mod oauth_parameter;

pub use oauth_parameter::OAuthParameter;

use proc_macro2::{Ident, Span, TokenStream, TokenTree};
use quote::ToTokens;

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

impl ToTokens for OAuthParameter {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let method = self
            .serialize_method_name()
            .expect("called `to_tokens` on `OAuthParameter::None`");
        let ident = Ident::new(method, Span::call_site());
        tokens.extend(::core::iter::once(TokenTree::Ident(ident)));
    }
}
