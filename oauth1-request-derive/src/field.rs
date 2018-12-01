use syn::spanned::Spanned;
use syn::{Attribute, Ident, Lit, LitStr, Meta, NestedMeta, Path, Type};

use ctxt::Ctxt;
use util::ReSpanned;

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

        def_set_state! {
            struct MetaSetState {
                $($field)*
            }
        }

        impl $Name {
            fn add_meta(&mut self, meta: Meta, set_state: &mut MetaSetState, cx: &mut Ctxt) {
                struct Args<'a> {
                    this: &'a mut $Name,
                    meta: Meta,
                    name: Ident,
                    set_state: &'a mut MetaSetState,
                    cx: &'a mut Ctxt,
                }

                let args = Args {
                    this: self,
                    name: meta.name(),
                    meta,
                    set_state,
                    cx,
                };

                add_meta_impl! { args; $($field)* }
            }
        }
    };
}

macro_rules! def_set_state {
    (struct $Name:ident { $(pub $field:ident: $_ty:ty,)* }) => {
        #[allow(dead_code)]
        #[derive(Default)]
        struct $Name { $($field: bool,)* }
    };
}

macro_rules! add_meta_impl {
    ($args:expr; pub $name:ident $($rest:tt)*) => {
        if $args.name == stringify!($name) {
            add_meta_impl! { $args; @matches $name $($rest)* }
        } else {
            add_meta_impl! { $args; @skip $($rest)* }
        }
    };
    ($args:expr; @skip: $_ty:ty, $($rest:tt)*) => {
        add_meta_impl! { $args; $($rest)* }
    };
    ($args:expr; @matches $name:ident: bool, $($rest:tt)*) => {
        if let Meta::Word(ref ident) = $args.meta {
            if $args.this.$name {
                $args.cx.error(
                    concat!("duplicate attribute `", stringify!($name), "`"),
                    ident.span(),
                );
            } else {
                $args.this.$name = true;
            }
        } else {
            $args.cx.error("expected meta word", $args.meta.span());
        }
    };
    ($args:expr; @matches $name:ident: MetaValue<$ty:ty>, $($rest:tt)*) => {
        if let Meta::NameValue(ref nv) = $args.meta {
            match nv.lit {
                Lit::Str(ref val) => {
                    if $args.set_state.$name {
                        $args.cx.error(
                            concat!("duplicate attribute `", stringify!($name), "`"),
                            nv.span(),
                        );
                    }
                    $args.this.$name.set(val, $args.cx);
                    $args.set_state.$name = true;
                }
                _ => $args.cx.error("expected string literal", nv.lit.span()),
            }
        } else {
            $args.cx.error("expected name-value meta", $args.meta.span());
        }
    };
    ($args:expr;) => {
        $args.cx.error(&format!("unknown attribute `{}`", $args.name), $args.meta.span());
    };
}

def_meta! {
    #[derive(Default)]
    pub struct FieldMeta {
        pub encoded: bool,
        pub fmt: MetaValue<Path>,
        pub option: bool,
        pub rename: MetaValue<UriSafe>,
        pub skip: bool,
        pub skip_if: MetaValue<Path>,
    }
}

pub struct MetaValue<T> {
    value: Option<ReSpanned<T>>,
}

pub struct UriSafe(pub String);

pub trait FromLitStrExt: Sized {
    fn from_lit_str(lit: &LitStr, cx: &mut Ctxt) -> Option<Self>;
}

impl Field {
    pub fn new(field: ::syn::Field, cx: &mut Ctxt) -> Self {
        let ::syn::Field {
            attrs, ident, ty, ..
        } = field;
        let meta = FieldMeta::new(&attrs, cx);
        let ident = ident.unwrap();
        let ret = Self { ident, ty, meta };
        ret.with_renamed(|name| {
            if name.starts_with("oauth_") {
                cx.error("paramter name must not start with \"oauth_\"", name.span());
            }
        });
        ret
    }

    /// Executes the closure with a string token representing the (`rename`-ed) field name.
    pub fn with_renamed<T, F: FnOnce(ReSpanned<&str>) -> T>(&self, f: F) -> T {
        if let Some(name) = self.meta.rename.get() {
            f(name.as_ref())
        } else {
            f(ReSpanned::new(&self.ident.to_string(), self.ident.span()))
        }
    }
}

impl FieldMeta {
    pub fn new(attrs: &[Attribute], cx: &mut Ctxt) -> Self {
        let mut ret = Self::default();
        let mut set_state = MetaSetState::default();

        for attr in attrs {
            if attr.path.segments.len() != 1 || attr.path.segments[0].ident != "oauth1" {
                continue;
            }

            let meta = match attr.parse_meta() {
                Ok(m) => m,
                Err(e) => {
                    cx.error(&e.to_string(), e.span());
                    continue;
                }
            };

            let list = if let Meta::List(list) = meta {
                list
            } else {
                cx.error("expected meta list", meta.span());
                continue;
            };

            for nested in list.nested {
                let meta = match nested {
                    NestedMeta::Meta(meta) => meta,
                    NestedMeta::Literal(lit) => {
                        cx.error("expected meta item", lit.span());
                        continue;
                    }
                };
                ret.add_meta(meta, &mut set_state, cx);
            }
        }

        ret
    }
}

impl<T> MetaValue<T> {
    pub fn get(&self) -> Option<&ReSpanned<T>> {
        self.value.as_ref()
    }
}

impl<T: FromLitStrExt> MetaValue<T> {
    fn set(&mut self, lit: &LitStr, cx: &mut Ctxt) {
        self.value = T::from_lit_str(lit, cx).map(|v| ReSpanned::new(v, lit.span()));
    }
}

impl<T> Default for MetaValue<T> {
    fn default() -> Self {
        Self { value: None }
    }
}

impl AsRef<str> for UriSafe {
    fn as_ref(&self) -> &str {
        &*self.0
    }
}

impl FromLitStrExt for UriSafe {
    fn from_lit_str(lit: &LitStr, cx: &mut Ctxt) -> Option<Self> {
        let s = lit.value();
        for b in s.as_bytes() {
            match b {
                b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'.' | b'_' | b'~' => (),
                _ => {
                    cx.error("parameter name must be URI-safe", lit.span());
                    return None;
                }
            }
        }
        Some(UriSafe(lit.value()))
    }
}

impl FromLitStrExt for Path {
    fn from_lit_str(lit: &LitStr, cx: &mut Ctxt) -> Option<Self> {
        let s = lit.value();
        ::syn::parse_str(&s)
            .map_err(|_| cx.error(&format!("invalid path: \"{}\"", s), lit.span()))
            .ok()
    }
}
