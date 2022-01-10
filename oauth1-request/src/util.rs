mod oauth_parameter;
mod percent_encoding;

pub use self::oauth_parameter::OAuthParameter;
pub use self::percent_encoding::{percent_encode, DoublePercentEncode, PercentEncode};

/// A macro to replicate `#[feature(doc_auto_cfg)]` behavior.
// The real `doc_auto_cfg` as of this writing shows feature flags in other crates when re-exporting
// items from them, which is undesirable.
// TODO: Remove this macro once the issue is resolved.
macro_rules! doc_auto_cfg {
    // Add `#[doc(cfg($pred))]` for each `#[cfg($pred)]`.
    (@inner $(#[$accum:meta])* { #[cfg($pred:meta)] $($rest:tt)+ }) => {
        doc_auto_cfg! {@inner
            $(#[$accum])*
            #[cfg_attr(docsrs, doc(cfg($pred)))]
            #[cfg($pred)]
            { $($rest)+ }
        }
    };
    // Pass through other attributes.
    (@inner $(#[$accum:meta])* { #[$attr:meta] $($rest:tt)+ }) => {
        doc_auto_cfg! {@inner
            $(#[$accum])*
            #[$attr]
            { $($rest)+ }
        }
    };
    (@inner $(#[$accum:meta])* { $item:item $($rest:tt)* }) => {
        $(#[$accum])*
        $item
        doc_auto_cfg! {@inner { $($rest)* }}
    };
    (@inner {}) => {};
    ($($arg:tt)*) => {
        doc_auto_cfg! {@inner { $($arg)* }}
    };
}

macro_rules! options {
    ($(
        $(#[$attr:meta])*
        pub struct $O:ident<$lifetime:tt> {
            $(#[$ctor_attr:meta])* $ctor:ident;
            $($field:tt)*
        }
    )*) => {$(
        $(#[$attr])*
        pub struct $O<$lifetime> {
            $($field)*
        }

        impl<$lifetime> $O<$lifetime> {
            $(#[$ctor_attr])*
            pub fn $ctor() -> Self {
                Default::default()
            }

            impl_setters! { $($field)* }
        }
    )*};
}

macro_rules! impl_setters {
    ($(#[$attr:meta])* $setter:ident: Option<$t:ty>, $($rest:tt)*) => {
        $(#[$attr])*
        pub fn $setter(&mut self, $setter: impl Into<Option<$t>>) -> &mut Self {
            self.$setter = $setter.into();
            self
        }
        impl_setters! { $($rest)* }
    };
    ($(#[$attr:meta])* $setter:ident: bool, $($rest:tt)*) => {
        $(#[$attr])*
        pub fn $setter(&mut self, $setter: bool) -> &mut Self {
            self.$setter = $setter;
            self
        }
        impl_setters! { $($rest)* }
    };
    ($(#[$attr:meta])* $setter:ident: $t:ty, $($rest:tt)*) => {
        $(#[$attr])*
        pub fn $setter(&mut self, $setter: impl Into<Option<$t>>) -> &mut Self {
            self.$setter = $setter;
            self
        }
        impl_setters! { $($rest)* }
    };
    () => {};
}

// TODO: Use `!` type once it's stable and we've bumped minimum supported Rust version.
#[allow(clippy::empty_enum)]
#[derive(Clone, Debug)]
pub enum Never {}

impl OAuthParameter {
    pub fn serialize<S: crate::serializer::Serializer>(self, serializer: &mut S) {
        match self {
            OAuthParameter::Callback => serializer.serialize_oauth_callback(),
            OAuthParameter::ConsumerKey => serializer.serialize_oauth_consumer_key(),
            OAuthParameter::Nonce => serializer.serialize_oauth_nonce(),
            OAuthParameter::SignatureMethod => serializer.serialize_oauth_signature_method(),
            OAuthParameter::Timestamp => serializer.serialize_oauth_timestamp(),
            OAuthParameter::Token => serializer.serialize_oauth_token(),
            OAuthParameter::Verifier => serializer.serialize_oauth_verifier(),
            OAuthParameter::Version => serializer.serialize_oauth_version(),
            OAuthParameter::None => panic!("called `serialize` on a `OAuthParameter::None`"),
        }
    }
}
