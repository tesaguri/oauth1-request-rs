//! Requests to be authorized with OAuth.

pub mod parameter_list;

pub use self::parameter_list::ParameterList;

use crate::serializer::{Serializer, SerializerExt};

/// Types that represent an HTTP request to be authorized with OAuth.
///
/// `Request` is an abstraction of a sequence of key-value pairs of a query part of a URI
/// and `x-www-form-urlencoded` string.
///
/// This trait can be implemented automatically by
/// [`#[derive(Request)]`][oauth1_request_derive::Request] derive macro.
/// In most cases, you won't need to implement it manually.
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
