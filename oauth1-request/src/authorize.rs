use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::fmt::Display;

use crate::signer::Signer;
use crate::{Options, Request, SignatureMethod};

/// Types that can be made into a `Request` using given credentials.
///
/// ## `#[derive(Authorize)]`
///
/// `oauth1-request` crate provides a derive macro for `Authorize`trait.
///
/// It generates a code to create a query string using the struct's field names and
/// `Display` implementation of the values.
///
/// You can customize the trait implementation produced by the derive macro with the following
/// field attributes:
///
/// - `#[oauth1(encoded)]`
///
/// Do not percent encode the value when appending it to query string.
///
/// - `#[oauth1(fmt = "path")]`
///
/// Format the value using the given function. The function must be callable as
/// `fn(&T, &mut Formatter<'_>) -> fmt::Result` (same as `Display::fmt`).
///
/// - `#[oauth1(option = "true")]` (or `#[oauth1(option = "false")]`)
///
/// If set to "true", skip the field when the value is `None` or use the unwrapped value otherwise.
/// The value's type must be `Option<T>` in that case.
///
/// When the field's type name is `Option<_>`, the attribute is implicitly set to `"true"`.
/// Use `#[oauth1(option = "false")]` if you need to opt out of that behavior.
///
/// - `#[oauth1(rename = "name")]`
///
/// Use the given string as the key of the query pair. The given string must be URI-safe.
///
/// - `#[oauth1(skip)]`
///
/// Unconditionally skip the field.
///
/// - `#[oauth1(skip_if = "path")]`
///
/// Call the given function and skip the field if the function returns `true`.
/// The function must be callable as `fn(&T) -> bool`.
pub trait Authorize {
    /// Signs `self` using `signer`.
    ///
    /// Users of the trait should use `authorize` or `authorize_form` instead.
    fn authorize_with<SM>(
        &self,
        signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options<'_>>,
    ) -> Request
    where
        SM: SignatureMethod;

    /// Signs `self` using the given credentials and returns a `Request` with a URI with query
    /// string.
    fn authorize<'a, SM>(
        &self,
        method: &str,
        uri: impl Display,
        consumer_key: &str,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
        signature_method: SM,
        options: impl Into<Option<&'a Options<'a>>>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        let signer = Signer::with_signature_method(
            signature_method,
            method,
            uri,
            consumer_secret,
            token_secret,
        );
        self.authorize_with(signer, consumer_key, options.into())
    }

    /// Signs `self` using the given credentials and returns a `Request` with
    /// an `x-www-form-urlencoded` string.
    fn authorize_form<'a, SM>(
        &self,
        method: &str,
        uri: impl Display,
        consumer_key: &str,
        consumer_secret: &str,
        token_secret: impl Into<Option<&'a str>>,
        signature_method: SM,
        options: impl Into<Option<&'a Options<'a>>>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        let signer = Signer::form_with_signature_method(
            signature_method,
            method,
            uri,
            consumer_secret,
            token_secret,
        );
        self.authorize_with(signer, consumer_key, options.into())
    }
}

impl<'a, A: Authorize + ?Sized> Authorize for &'a A {
    fn authorize_with<SM>(
        &self,
        signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options<'_>>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        (**self).authorize_with(signer, consumer_key, options)
    }
}

impl<'a, A: Authorize + ?Sized> Authorize for &'a mut A {
    fn authorize_with<SM>(
        &self,
        signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options<'_>>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        (**self).authorize_with(signer, consumer_key, options)
    }
}

/// Authorizes a request with no query pairs.
impl Authorize for () {
    fn authorize_with<SM>(
        &self,
        signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options<'_>>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        signer.finish(consumer_key, options)
    }
}

impl<K: Borrow<str>, V: Borrow<str>> Authorize for BTreeSet<(K, V)> {
    fn authorize_with<SM>(
        &self,
        mut signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options<'_>>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        let mut params = self.iter().map(|&(ref k, ref v)| (k.borrow(), v.borrow()));

        let (mut signer, mut pair) = loop {
            let (k, v) = match params.next() {
                Some(kv) => kv,
                None => break (signer.oauth_parameters(consumer_key, options), None),
            };
            if k > "oauth_" {
                break (signer.oauth_parameters(consumer_key, options), Some((k, v)));
            }
            signer.parameter(k, v);
        };

        while let Some((k, v)) = pair {
            signer.parameter(k, v);
            pair = params.next();
        }

        signer.finish()
    }
}

impl<A: Authorize> Authorize for Option<A> {
    fn authorize_with<SM>(
        &self,
        signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options<'_>>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        if let Some(ref this) = *self {
            this.authorize_with(signer, consumer_key, options)
        } else {
            signer.finish(consumer_key, options)
        }
    }
}
