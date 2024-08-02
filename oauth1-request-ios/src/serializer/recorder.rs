//! A utility serializer for debugging purpose.

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt::Display;

use super::Serializer;

/// A `Serializer` that records the history of operations done to itself.
///
/// This is useful for testing a manually implemented `Request` implementation.
///
/// ## Example
///
/// Checking that a `Request` implementation works as intended:
///
/// ```
/// # extern crate oauth1_request as oauth;
/// #
/// use oauth::serializer::recorder::{Record, Recorder};
/// use oauth::serializer::{Serializer, SerializerExt};
/// use oauth::Request;
///
/// #[derive(Request)]
/// struct MyRequest {
///     foo: u32,
///     qux: u32,
/// }
///
/// let request = MyRequest { foo: 1, qux: 2 };
/// let records = request.serialize(Recorder::new());
///
/// // `records` is a vector whose elements represent the history of operations.
/// assert_eq!(records[0], Record::Parameter("foo", request.foo));
/// assert_eq!(records[1], <Record>::Callback);
/// // ...
/// assert_eq!(records[9], Record::Parameter("qux", request.qux));
///
/// // Reproduce the `Record`s by repeating the operations `MyRequest::serialize` is expected to do.
/// let expected = {
///     let mut recorder = Recorder::new();
///     recorder.serialize_parameter("foo", request.foo);
///     recorder.serialize_oauth_parameters();
///     recorder.serialize_parameter("qux", request.qux);
///     recorder.end()
/// };
/// assert_eq!(records, expected);
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recorder {
    history: Vec<Record>,
}

/// Represents a record of an operation done to a serializer.
#[derive(Clone, Debug)]
pub enum Record<K = String, V = String> {
    /// Represents a `serialize_parameter` method call.
    Parameter(K, V),
    /// Represents a `serialize_parameter_encoded` method call.
    ParameterEncoded(K, V),
    /// Represents a `serialize_oauth_callback` method call.
    Callback,
    /// Represents a `serialize_oauth_consumer_key` method call.
    ConsumerKey,
    /// Represents a `serialize_oauth_nonce` method call.
    Nonce,
    /// Represents a `serialize_oauth_signature_method` method call.
    SignatureMethod,
    /// Represents a `serialize_oauth_timestamp` method call.
    Timestamp,
    /// Represents a `serialize_oauth_token` method call.
    Token,
    /// Represents a `serialize_oauth_verifier` method call.
    Verifier,
    /// Represents a `serialize_oauth_version` method call.
    Version,
}

impl Recorder {
    /// Creates a new `Recorder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the history of operations done to this serializer.
    pub fn history(&self) -> &[Record] {
        &self.history
    }
}

impl Serializer for Recorder {
    type Output = Vec<Record>;

    fn serialize_parameter<V>(&mut self, key: &str, value: V)
    where
        V: Display,
    {
        self.history
            .push(Record::Parameter(key.to_owned(), value.to_string()));
    }

    fn serialize_parameter_encoded<V>(&mut self, key: &str, value: V)
    where
        V: Display,
    {
        self.history
            .push(Record::ParameterEncoded(key.to_owned(), value.to_string()));
    }

    fn serialize_oauth_callback(&mut self) {
        self.history.push(Record::Callback);
    }

    fn serialize_oauth_consumer_key(&mut self) {
        self.history.push(Record::ConsumerKey);
    }

    fn serialize_oauth_nonce(&mut self) {
        self.history.push(Record::Nonce);
    }

    fn serialize_oauth_signature_method(&mut self) {
        self.history.push(Record::SignatureMethod);
    }

    fn serialize_oauth_timestamp(&mut self) {
        self.history.push(Record::Timestamp);
    }

    fn serialize_oauth_token(&mut self) {
        self.history.push(Record::Token);
    }

    fn serialize_oauth_verifier(&mut self) {
        self.history.push(Record::Verifier);
    }

    fn serialize_oauth_version(&mut self) {
        self.history.push(Record::Version);
    }

    fn end(self) -> Self::Output {
        self.history
    }
}

impl<K, V> Record<K, V> {
    /// Represents a sequence of standard OAuth protocol paramters.
    ///
    /// ```
    /// # extern crate oauth1_request as oauth;
    /// #
    /// use oauth::serializer::recorder::{Record, Recorder};
    /// use oauth::Request;
    ///
    /// assert_eq!(().serialize(Recorder::new()), <Record>::OAUTH_PARAMETERS);
    /// ```
    pub const OAUTH_PARAMETERS: [Self; 8] = [
        Record::Callback,
        Record::ConsumerKey,
        Record::Nonce,
        Record::SignatureMethod,
        Record::Timestamp,
        Record::Token,
        Record::Verifier,
        Record::Version,
    ];
}

impl<K, V, K2, V2> PartialEq<Record<K2, V2>> for Record<K, V>
where
    K: AsRef<str>,
    V: Display,
    K2: AsRef<str>,
    V2: Display,
{
    fn eq(&self, other: &Record<K2, V2>) -> bool {
        match (self, other) {
            (&Record::Parameter(ref k1, ref v1), &Record::Parameter(ref k2, ref v2))
            | (
                &Record::ParameterEncoded(ref k1, ref v1),
                &Record::ParameterEncoded(ref k2, ref v2),
            ) => k1.as_ref() == k2.as_ref() && fmt_cmp::cmp(v1, v2) == Ordering::Equal,
            (&Record::Callback, &Record::Callback)
            | (&Record::ConsumerKey, &Record::ConsumerKey)
            | (&Record::Nonce, &Record::Nonce)
            | (&Record::SignatureMethod, &Record::SignatureMethod)
            | (&Record::Timestamp, &Record::Timestamp)
            | (&Record::Token, &Record::Token)
            | (&Record::Verifier, &Record::Verifier)
            | (&Record::Version, &Record::Version) => true,
            _ => false,
        }
    }
}

impl<K, V> Eq for Record<K, V>
where
    K: AsRef<str>,
    V: Display,
{
}
