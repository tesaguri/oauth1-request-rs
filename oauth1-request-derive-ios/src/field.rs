use proc_macro2::{Literal, Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};
use syn::ext::IdentExt;
use syn::{ExprPath, Ident, LitBool, LitStr, Type};

use crate::meta::UriSafe;

pub struct Field {
    pub ident: Ident,
    pub ty: Type,
    pub meta: FieldMeta,
}

def_meta! {
    pub struct FieldMeta {
        pub encoded: bool,
        pub fmt: Option<ExprPath>,
        pub option: Option<LitBool>,
        pub rename: Option<UriSafe>,
        pub skip: bool,
        pub skip_if: Option<ExprPath>,
    }
}

pub enum Name<'a> {
    Original(&'a Ident),
    Renamed(&'a LitStr),
}

impl Field {
    pub fn new(field: syn::Field) -> Self {
        let syn::Field {
            attrs, ident, ty, ..
        } = field;
        let meta = FieldMeta::new(attrs);
        let ident = ident.unwrap().unraw();
        Self { ident, ty, meta }
    }

    /// Returns the (`rename`-ed) field name.
    pub fn name(&self) -> Name<'_> {
        if let Some(ref name) = self.meta.rename {
            Name::Renamed(&name.0)
        } else {
            Name::Original(&self.ident)
        }
    }
}

impl<'a> Name<'a> {
    pub fn span(&self) -> Span {
        match *self {
            Name::Original(ident) => ident.span(),
            Name::Renamed(lit) => lit.span(),
        }
    }

    // This was not named `to_string` to avoid `clippy::inherent_to_string_shadow_display`.
    // We are avoiding implementing `Display` because the underlying `Display` impls in
    // `proc_macro` crate use `to_string` under the hood as of this writing.
    pub fn string_value(&self) -> String {
        match *self {
            Name::Original(ident) => ident.to_string(),
            Name::Renamed(lit) => lit.value(),
        }
    }
}

/// Interpolates `Self` as string literal regardless of its variant.
impl<'a> ToTokens for Name<'a> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match *self {
            Name::Original(ident) => {
                let mut lit = Literal::string(&ident.to_string());
                lit.set_span(ident.span());
                tokens.append(lit);
            }
            Name::Renamed(lit) => lit.to_tokens(tokens),
        }
    }
}
