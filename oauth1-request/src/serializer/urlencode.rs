//! A URI query/`x-www-form-urlencoded` string serializer.

use std::fmt::Write;

use crate::util::PercentEncode;
use crate::Serializer;

/// A `Serializer` that produces a URI query or an `x-www-form-urlencoded` string from a request.
pub struct Urlencoder {
    data: String,
    next_append: Append,
}

enum Append {
    None,
    Question,
    Ampersand,
}

impl Urlencoder {
    /// Creates a `Urlencoder` that produces an `x-www-form-urlencoded` string.
    pub fn form() -> Self {
        Urlencoder {
            data: String::new(),
            next_append: Append::None,
        }
    }

    /// Creates a `Urlencoder` that appends a query part to the given URI.
    pub fn query(uri: String) -> Self {
        Urlencoder {
            data: uri,
            next_append: Append::Question,
        }
    }

    fn append_delim(&mut self) {
        match self.next_append {
            Append::None => self.next_append = Append::Ampersand,
            Append::Question => {
                self.data.push('?');
                self.next_append = Append::Ampersand;
            }
            Append::Ampersand => self.data.push('&'),
        }
    }
}

impl Serializer for Urlencoder {
    type Output = String;

    fn serialize_parameter<V>(&mut self, k: &str, v: V)
    where
        V: std::fmt::Display,
    {
        self.append_delim();
        write!(self.data, "{}={}", k, PercentEncode(&v)).unwrap();
    }

    fn serialize_parameter_encoded<V>(&mut self, k: &str, v: V)
    where
        V: std::fmt::Display,
    {
        self.append_delim();
        write!(self.data, "{}={}", k, v).unwrap();
    }

    fn serialize_oauth_parameters(&mut self) {}

    fn end(self) -> Self::Output {
        self.data
    }
}
