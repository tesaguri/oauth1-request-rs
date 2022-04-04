//! Requests to be authorized with OAuth.

pub mod parameter_list;

pub use self::parameter_list::ParameterList;

use core::fmt::Display;

use crate::serializer::{Serializer, SerializerExt};
use crate::util::OAuthParameter;

/// Types that represent an HTTP request to be authorized with OAuth.
///
/// `Request` is an abstraction of a sequence of key-value pairs of a query part of a URI
/// and `x-www-form-urlencoded` string.
///
/// This trait can be implemented automatically by
/// [`#[derive(Request)]`][oauth1_request_derive::Request] derive macro.
/// In most cases, you won't need to implement it manually.
pub trait Request {
    /// Feeds a [`Serializer`] implementation with the key-value pairs of the request
    /// and returns the serializer's output.
    fn serialize<S>(&self, serializer: S) -> S::Output
    where
        S: Serializer;
}

/// A wrapper type that implements [`Request`] with key-value pairs returned by the wrapped
/// iterator.
///
/// The key-value pairs must be sorted as required by the [`Serializer`] trait. Otherwise, the
/// behavior of this wrapper is unspecified.
///
/// Note that the required ordering is alphabetical ordering of `AsRef<str>` value of the key and
/// `Display` representation of the value and does not necessarily match that of the one provided by
/// the [`Ord`] trait, which may provide, for example, numerical ordering instead.
///
/// If you have a slice instead of an iterator, consider using [`ParameterList`], which guarantees
/// the correct ordering.
///
/// ## Example
///
#[cfg_attr(feature = "alloc", doc = " ```edition2021")]
#[cfg_attr(not(feature = "alloc"), doc = " ```edition2021,ignore")]
/// # extern crate oauth1_request as oauth;
/// #
/// use std::collections::BTreeMap;
///
/// let request = BTreeMap::from_iter([
///     ("article_id", "123456789"),
///     ("text", "A request signed with OAuth & Rust 🦀 🔏"),
/// ]);
/// let request = oauth::request::AssertSorted::new(&request);
///
/// let form = oauth::to_form(&request);
/// assert_eq!(
///     form,
///     "article_id=123456789&text=A%20request%20signed%20with%20OAuth%20%26%20Rust%20%F0%9F%A6%80%20%F0%9F%94%8F",
/// );
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct AssertSorted<I> {
    inner: I,
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

impl<I, K, V> AssertSorted<I>
where
    I: Clone + Iterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Display,
{
    /// Creates a new `AssertSorted`.
    pub fn new<J>(iterator: J) -> Self
    where
        J: IntoIterator<Item = (K, V), IntoIter = I>,
    {
        AssertSorted {
            inner: iterator.into_iter(),
        }
    }
}

impl<I, K, V> Request for AssertSorted<I>
where
    I: Clone + Iterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Display,
{
    fn serialize<S>(&self, mut serializer: S) -> S::Output
    where
        S: Serializer,
    {
        let mut next_param = OAuthParameter::default();

        for (k, v) in self.inner.clone() {
            let k = k.as_ref();
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
