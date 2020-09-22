use proc_macro2::{Group, Span};
use proc_macro_error::emit_error;
use quote::ToTokens;
use syn::parse::{Parse, ParseStream, Parser};
use syn::spanned::Spanned;
use syn::{Attribute, Expr, ExprLit, ExprPath, Ident, Lit, LitBool, LitStr, Path, Token, Type};

pub struct Field {
    pub ident: Ident,
    pub ty: Type,
    pub meta: FieldMeta,
}

macro_rules! def_meta {
    ($(#[$attr:meta])* pub struct $Name:ident { $($field:tt)* }) => {
        $(#[$attr])*
        pub struct $Name {
            $($field)*
        }

        impl $Name {
            fn add_meta(&mut self, meta: Meta) -> syn::Result<()> {
                add_meta_impl! { (self, meta) { $($field)* } }
            }
        }
    };
}

macro_rules! add_meta_impl {
    (($self:expr, $meta:expr) $body:tt) => {
        add_meta_impl! { @accum ($self, $meta) $body -> {} }
    };
    (@accum ($self:expr, $meta:expr) { pub $name:ident: bool, $($rest:tt)* } -> { $($arms:tt)* })
    => {
        add_meta_impl! { @accum ($self, $meta) { $($rest)* } -> {
            $($arms)*
            stringify!($name) => {
                if !matches!($meta.kind, MetaKind::Path) {
                    return Err(syn::Error::new($meta.span(), "expected meta word"));
                }
                if $self.$name {
                    let message = concat!("duplicate attribute `", stringify!($name), "`");
                    return Err(syn::Error::new($meta.path.span(), message));
                } else {
                    $self.$name = true;
                }
                Ok(())
            }
        } }
    };
    (@accum ($self:expr, $meta:expr) { pub $name:ident: $_:ty, $($rest:tt)* } -> { $($arms:tt)* })
    => {
        add_meta_impl! { @accum ($self, $meta) { $($rest)* } -> {
            $($arms)*
            stringify!($name) => {
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
                    let message = concat!("duplicate attribute `", stringify!($name), "`");
                    return Err(syn::Error::new($meta.path.span(), message));
                }
                $self.$name = Some(value);
                Ok(())
            }
        }}
    };
    (@accum ($self:expr, $meta:expr) {} -> { $($arms:tt)* }) => {{
        let name = if let Some(name) = path_as_ident(&$meta.path) {
            name
        } else {
            let path = $meta.path.to_token_stream().to_string().replace(' ', "");
            let message = format!("unknown attribute `{}`", path);
            return Err(syn::Error::new($meta.path.span(), &*message));
        };
        match &*name.to_string() {
            $($arms)*
            _ => {
                let message = format!("unknown attribute `{}`", name);
                Err(syn::Error::new($meta.path.span(), &*message))
            }
        }
    }};
}

def_meta! {
    #[derive(Default)]
    pub struct FieldMeta {
        pub encoded: bool,
        pub fmt: Option<ExprPath>,
        pub option: Option<LitBool>,
        pub rename: Option<UriSafe>,
        pub skip: bool,
        pub skip_if: Option<ExprPath>,
    }
}

pub struct UriSafe(pub LitStr);

/// Like `syn::Meta` but accepts an `Expr` as the value of `MetaNameValue`
struct Meta {
    path: Path,
    kind: MetaKind,
}

#[allow(clippy::large_enum_variant)]
enum MetaKind {
    Path,
    List(MetaList),
    NameValue(Expr),
}

struct MetaList {
    span: Span,
}

/// Attempts to reinterpret an `Expr` as another syntax tree type value.
trait FromExprExt: Sized {
    fn from_expr(expr: Expr) -> syn::Result<Self>;
}

impl Field {
    pub fn new(field: syn::Field) -> Self {
        let syn::Field {
            attrs, ident, ty, ..
        } = field;
        let meta = FieldMeta::new(&attrs);
        let ident = ident.unwrap();
        Self { ident, ty, meta }
    }

    /// Executes the closure with a string token representing the (`rename`-ed) field name.
    pub fn with_renamed<T, F: FnOnce(&LitStr) -> T>(&self, f: F) -> T {
        if let Some(ref name) = self.meta.rename {
            f(&name.0)
        } else {
            f(&LitStr::new(&self.ident.to_string(), self.ident.span()))
        }
    }
}

impl FieldMeta {
    pub fn new(attrs: &[Attribute]) -> Self {
        let mut ret = Self::default();

        for attr in attrs {
            if attr.path.segments.len() != 1 || attr.path.segments[0].ident != "oauth1" {
                continue;
            }

            let parser = |input: ParseStream<'_>| {
                if input.is_empty() {
                    // Manually create an error to work around `syn::parenthesized`'s behavior
                    // to span the error at call site in this case.
                    let message = "expected parentheses after `oauth1`";
                    return Err(syn::Error::new(attr.path.span(), message));
                }
                let content;
                syn::parenthesized!(content in input);
                content.parse_terminated::<_, Token![,]>(Meta::parse)
            };
            let meta_list = match parser.parse2(attr.tokens.clone()) {
                Ok(list) => list,
                Err(e) => {
                    emit_error!(e);
                    continue;
                }
            };

            for meta in meta_list {
                if let Err(e) = ret.add_meta(meta) {
                    emit_error!(e);
                }
            }
        }

        ret
    }
}

impl Meta {
    fn span(&self) -> Span {
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
        } else if input.peek(Token![=]) {
            let _ = input.parse::<Token![=]>().unwrap();
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

fn path_as_ident(path: &Path) -> Option<Ident> {
    if path.leading_colon.is_none() && path.segments.len() == 1 {
        let s = &path.segments[0];
        if let syn::PathArguments::None = s.arguments {
            return Some(s.ident.clone());
        }
    }

    None
}

/// Joins two `Span`s or returns the first one if failed.
fn join(first: Span, last: Span) -> Span {
    first.join(last).unwrap_or(first)
}
