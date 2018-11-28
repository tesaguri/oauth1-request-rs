extern crate either;

use self::either::Either;

use super::*;

/// A `SignatureMethod` implementation that behaves like `L` or `R` depending on `self`'s variant.
///
/// This may be useful when you want to decide on a method to use at runtime.
impl<L: SignatureMethod, R: SignatureMethod> SignatureMethod for Either<L, R> {
    type Sign = Either<L::Sign, R::Sign>;

    fn sign_with(
        self,
        consumer_secret: impl Display,
        token_secret: Option<impl Display>,
    ) -> Self::Sign {
        match self {
            Either::Left(l) => Either::Left(l.sign_with(consumer_secret, token_secret)),
            Either::Right(r) => Either::Right(r.sign_with(consumer_secret, token_secret)),
        }
    }
}

macro_rules! delegate {
    (fn $method:ident(&mut self $(, $arg:ident: $typ:ty)*) $(-> $ret:ty)*; $($rest:tt)*) => {
        fn $method(&mut self $(, $arg: $typ)*) $(-> $ret)* {
            delegate! { @body $method(self.as_mut(), $($arg),*); }
        }
        delegate! { $($rest)* }
    };
    (fn $method:ident(&self $(, $arg:ident: $typ:ty)*) $(-> $ret:ty)*; $($rest:tt)*) => {
        fn $method(&self $(, $arg: $typ)*) $(-> $ret)* {
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
        fn uri(&mut self, uri: impl Display);
        fn parameter(&mut self, key: &str, value: impl Display);
        fn delimiter(&mut self);
    }

    fn finish(self) -> Self::Signature {
        self.map_left(L::finish).map_right(R::finish)
    }

    delegate! {
        fn callback(&mut self, default_value: &'static str, value: impl Display);
        fn nonce(&mut self, default_key: &'static str, value: impl Display);
        fn use_nonce(&self) -> bool;
        fn signature_method(&mut self, default_key: &'static str, default_value: &'static str);
        fn timestamp(&mut self, default_key: &'static str, value: u64);
        fn use_timestamp(&self) -> bool;
        fn token(&mut self, default_key: &'static str, value: impl Display);
        fn verifier(&mut self, default_key: &'static str, value: impl Display);
        fn version(&mut self, default_key: &'static str, default_value: &'static str);
    }
}
