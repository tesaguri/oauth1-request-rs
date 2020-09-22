//! Requests to be authorized with OAuth.

use std::borrow::Borrow;
use std::collections::BTreeSet;

use crate::serializer::{Serializer, SerializerExt};
use crate::util::OAuthParameter;

/// Types that represent an HTTP request to be authorized with OAuth.
///
/// This trait can be implemented automatically by `#[derive(Request)]` derive macro
/// and in most cases you won't need to implement it manually.
///
/// A `Request` is composed of a sequence of key-value pairs which will eventually be represented by
/// a query part of a URI or an `x-www-form-urlencoded` string, and the derive macro uses
/// the struct's field names and `Display` implementation of the values.
///
/// ## `#[derive(Request)]`
///
/// You can customize the behavior of the derive macro with the following field attributes:
///
/// - `#[oauth1(encoded)]`
///
/// Do not percent encode the value when serializing it.
///
/// - `#[oauth1(fmt = path)]`
///
/// Format the value using the function at `path`. The function must be callable as
/// `fn(&T, &mut Formatter<'_>) -> fmt::Result` (same as `Display::fmt`).
///
/// - `#[oauth1(option = true)]` (or `#[oauth1(option = false)]`)
///
/// If set to `true`, skip the field when the value is `None` or use the unwrapped value otherwise.
/// The value's type must be `Option<T>` in that case.
///
/// When the field's type name is `Option<_>`, the attribute is implicitly set to `true`.
/// Use `#[oauth1(option = "false")]` if you need to opt out of that behavior.
///
/// - `#[oauth1(rename = "name")]`
///
/// Use the given string as the key. The given string must be URI-safe.
///
/// - `#[oauth1(skip)]`
///
/// Unconditionally skip the field.
///
/// - `#[oauth1(skip_if = path)]`
///
/// Call the function at `path` and skip the field if the function returns `true`.
/// The function must be callable as `fn(&T) -> bool`.
pub trait Request {
    /// Feeds a [`Serializer`] implementation with the key-value pair of the request
    /// and returns the serializer's output.
    fn serialize<S>(&self, serializer: S) -> S::Output
    where
        S: Serializer;
}

impl<'a, R> Request for &'a R
where
    R: Request + ?Sized,
{
    fn serialize<S>(&self, serializer: S) -> S::Output
    where
        S: Serializer,
    {
        (**self).serialize(serializer)
    }
}

impl<'a, R> Request for &'a mut R
where
    R: Request + ?Sized,
{
    fn serialize<S>(&self, serializer: S) -> S::Output
    where
        S: Serializer,
    {
        (**self).serialize(serializer)
    }
}

/// Authorizes a request with no query pairs.
impl Request for () {
    fn serialize<S>(&self, mut serializer: S) -> S::Output
    where
        S: Serializer,
    {
        serializer.serialize_oauth_parameters();
        serializer.end()
    }
}

impl<K: Borrow<str>, V: Borrow<str>> Request for BTreeSet<(K, V)> {
    fn serialize<S>(&self, mut serializer: S) -> S::Output
    where
        S: Serializer,
    {
        let mut next_param = OAuthParameter::default();

        for (k, v) in self {
            let (k, v) = (k.borrow(), v.borrow());
            while next_param < *k {
                next_param.serialize(&mut serializer);
                next_param = next_param.next();
            }
            serializer.serialize_parameter(k, v);
        }

        while next_param != OAuthParameter::None {
            next_param.serialize(&mut serializer);
            next_param = next_param.next();
        }

        serializer.end()
    }
}

impl<R: Request> Request for Option<R> {
    fn serialize<S>(&self, mut serializer: S) -> S::Output
    where
        S: Serializer,
    {
        if let Some(ref this) = *self {
            this.serialize(serializer)
        } else {
            serializer.serialize_oauth_parameters();
            serializer.end()
        }
    }
}
