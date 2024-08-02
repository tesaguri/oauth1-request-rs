use ::either::Either;

use super::*;

/// A `SignatureMethod` implementation that behaves like `L` or `R` depending on `self`'s variant.
///
/// This may be useful when you want to decide on a method to use at runtime.
impl<L: SignatureMethod, R: SignatureMethod> SignatureMethod for Either<L, R> {
    type Sign = Either<L::Sign, R::Sign>;

    fn sign_with(self, client_secret: &str, token_secret: Option<&str>) -> Self::Sign {
        match self {
            Either::Left(l) => Either::Left(l.sign_with(client_secret, token_secret)),
            Either::Right(r) => Either::Right(r.sign_with(client_secret, token_secret)),
        }
    }
}

macro_rules! delegate {
    (
        fn $method:ident$([$($tp:tt)*])?(&mut self $(, $arg:ident: $typ:ty)*) $(-> $ret:ty)*;
        $($rest:tt)*
    ) => {
        fn $method$(<$($tp)*>)?(&mut self $(, $arg: $typ)*) $(-> $ret)* {
            delegate! { @body $method(self.as_mut(), $($arg),*); }
        }
        delegate! { $($rest)* }
    };
    (
        fn $method:ident$([$($tp:tt)*])?(&self $(, $arg:ident: $typ:ty)*) $(-> $ret:ty)*;
        $($rest:tt)*
    ) => {
        fn $method$(<$($tp)*>)?(&self $(, $arg: $typ)*) $(-> $ret)* {
            delegate! { @body $method(self.as_ref(), $($arg),*); }
        }
        delegate! { $($rest)* }
    };
    (@body $method:ident($this:expr, $($arg:ident),*);) => {
        $this.either_with(
            ($($arg,)*),
            |($($arg,)*), l| l.$method($($arg,)*),
            |($($arg,)*), r| r.$method($($arg,)*),
        )
    };
    () => {};
}

impl<L: Sign, R: Sign> Sign for Either<L, R> {
    type Signature = Either<L::Signature, R::Signature>;

    delegate! {
        fn get_signature_method_name(&self) -> &'static str;
        fn request_method(&mut self, method: &str);
        fn uri[T: Display](&mut self, uri: T);
        fn parameter[V: Display](&mut self, key: &str, value: V);
        fn delimiter(&mut self);
    }

    fn end(self) -> Self::Signature {
        self.map_left(L::end).map_right(R::end)
    }

    delegate! {
        fn callback[V: Display](&mut self, value: V);
        fn nonce[V: Display](&mut self, value: V);
        fn use_nonce(&self) -> bool;
        fn signature_method(&mut self);
        fn timestamp(&mut self, value: u64);
        fn use_timestamp(&self) -> bool;
        fn token[V: Display](&mut self, value: V);
        fn verifier[V: Display](&mut self, value: V);
        fn version(&mut self);
    }
}
