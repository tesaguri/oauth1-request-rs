use proc_macro2::{Group, Span};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{Expr, ExprLit, ExprPath, Lit, LitBool, LitStr, Path};

macro_rules! def_meta {
    (pub struct $Name:ident { $($field:tt)* }) => {
        decl_meta! {
            pub struct $Name {
                $($field)*
            }
        }

        impl $Name {
            pub fn new(attrs: Vec<syn::Attribute>) -> Self {
                use syn::parse::Parse;

                use $crate::meta::Meta;

                let mut ret = Self::default();

                for attr in attrs {
                    let path = attr.path();
                    if path.get_ident().map_or(true, |ident| ident != "oauth1") {
                        continue;
                    }

                    let parser = |input: syn::parse::ParseStream<'_>| {
                        input.parse_terminated(Meta::parse, syn::Token![,])
                    };
                    let meta_list = match attr.parse_args_with(parser) {
                        Ok(list) => list,
                        Err(e) => {
                            proc_macro_error::emit_error!(e.span(), e.to_string());
                            continue;
                        }
                    };

                    for meta in meta_list {
                        if let Err(e) = ret.add_meta(meta) {
                            proc_macro_error::emit_error!(e.span(), e.to_string());
                        }
                    }
                }

                ret
            }

            fn add_meta(&mut self, meta: $crate::meta::Meta) -> syn::Result<()> {
                use quote::ToTokens;
                #[allow(unused_imports)]
                use syn::spanned::Spanned;

                #[allow(unused_imports)]
                use $crate::meta::{FromExprExt, MetaKind};

                add_meta_impl! { (self, meta) { $($field)* } }
            }
        }
    };
}

macro_rules! decl_meta {
    (pub struct $Name:ident { $(pub $name:ident $(as $_:literal)?: $T:ty),* $(,)? }) => {
        #[derive(Default)]
        pub struct $Name {
            $(pub $name: $T,)*
        }
    };
}

macro_rules! add_meta_impl {
    (($self:expr, $meta:expr) $body:tt) => {
        add_meta_impl! { @accum ($self, $meta) $body {} }
    };
    (@accum ($self:expr, $meta:expr) {
        pub $name:ident $(as $rename:literal)?: bool,
        $($rest:tt)*
    } { $($arms:tt)* }) => {
        add_meta_impl! { @accum ($self, $meta) { $($rest)* } {
            $($arms)*
            meta_name!($name $(as $rename)?) => {
                if !matches!($meta.kind, MetaKind::Path) {
                    return Err(syn::Error::new($meta.span(), "expected meta word"));
                }
                if $self.$name {
                    let message = concat!(
                        "duplicate attribute `",
                        meta_name!($name $(as $rename)?),
                        "`"
                    );
                    return Err(syn::Error::new($meta.path.span(), message));
                }
                $self.$name = true;
                Ok(())
            }
        } }
    };
    (@accum ($self:expr, $meta:expr) {
        pub $name:ident $(as $rename:literal)?: $_:ty,
        $($rest:tt)*
    } { $($arms:tt)* }) => {
        add_meta_impl! { @accum ($self, $meta) { $($rest)* } {
            $($arms)*
            meta_name!($name $(as $rename)?) => {
                let value = if let MetaKind::NameValue(value) = $meta.kind {
                    value
                } else {
                    return Err(syn::Error::new($meta.span(), "expected name-value meta"));
                };
                let value = match <_>::from_expr(value) {
                    Ok(value) => value,
                    Err(e) => return Err(e),
                };
                if $self.$name.is_some() {
                    let message = concat!(
                        "duplicate attribute `",
                        meta_name!($name $(as $rename)?),
                        "`"
                    );
                    return Err(syn::Error::new($meta.path.span(), message));
                }
                $self.$name = Some(value);
                Ok(())
            }
        }}
    };
    (@accum ($self:expr, $meta:expr) {} { $($arms:tt)* }) => {{
        let name = if let Some(name) = $meta.path.get_ident() {
            name
        } else {
            let path = $meta.path.to_token_stream().to_string().replace(' ', "");
            return Err(syn::Error::new(
                $meta.path.span(),
                format_args!("unknown attribute `{}`", path),
            ));
        };
        let name = name.to_string();
        match &*name {
            $($arms)*
            _ => Err(syn::Error::new(
                $meta.path.span(),
                format_args!("unknown attribute `{}`", name),
            ))
        }
    }};
}

macro_rules! meta_name {
    ($name:ident) => {
        stringify!($name)
    };
    ($_:ident as $rename:literal) => {
        $rename
    };
}

/// Like `syn::Meta` but accepts an `Expr` as the value of `MetaNameValue`
pub struct Meta {
    pub path: Path,
    pub kind: MetaKind,
}

#[allow(clippy::large_enum_variant)]
pub enum MetaKind {
    Path,
    List(MetaList),
    NameValue(Expr),
}

pub struct MetaList {
    span: Span,
}

pub struct UriSafe(pub LitStr);

/// Attempts to reinterpret an `Expr` as another syntax tree type value.
pub trait FromExprExt: Sized {
    fn from_expr(expr: Expr) -> syn::Result<Self>;
}

impl Meta {
    pub fn span(&self) -> Span {
        match self.kind {
            MetaKind::Path => self.path.span(),
            MetaKind::List(ref list) => list.span,
            MetaKind::NameValue(ref value) => join(self.path.span(), value.span()),
        }
    }
}

impl Parse for Meta {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let path = input.parse::<Path>()?;
        if input.peek(syn::token::Paren) {
            let span = join(path.span(), input.parse::<Group>().unwrap().span());
            let kind = MetaKind::List(MetaList { span });
            Ok(Meta { path, kind })
        } else if input.peek(syn::Token![=]) {
            let _ = input.parse::<syn::Token![=]>().unwrap();
            let kind = MetaKind::NameValue(input.parse()?);
            Ok(Meta { path, kind })
        } else {
            let kind = MetaKind::Path;
            Ok(Meta { path, kind })
        }
    }
}

impl FromExprExt for ExprPath {
    fn from_expr(expr: Expr) -> syn::Result<Self> {
        if let Expr::Path(path) = expr {
            Ok(path)
        } else {
            Err(syn::Error::new(expr.span(), "expected path"))
        }
    }
}

impl FromExprExt for LitBool {
    fn from_expr(expr: Expr) -> syn::Result<Self> {
        if let Expr::Lit(ExprLit {
            lit: Lit::Bool(lit),
            ..
        }) = expr
        {
            Ok(lit)
        } else {
            Err(syn::Error::new(expr.span(), "expected boolean literal"))
        }
    }
}

impl FromExprExt for UriSafe {
    fn from_expr(expr: Expr) -> syn::Result<Self> {
        let s = if let Expr::Lit(ExprLit {
            lit: Lit::Str(lit), ..
        }) = expr
        {
            lit
        } else {
            return Err(syn::Error::new(expr.span(), "expected string literal"));
        };
        for b in s.value().as_bytes() {
            match b {
                b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'.' | b'_' | b'~' => (),
                _ => {
                    return Err(syn::Error::new(s.span(), "parameter name must be URI-safe"));
                }
            }
        }
        Ok(UriSafe(s))
    }
}

/// Joins two `Span`s or returns the first one if failed.
fn join(first: Span, last: Span) -> Span {
    first.join(last).unwrap_or(first)
}
