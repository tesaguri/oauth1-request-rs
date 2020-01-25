//! Types for representing the credential pairs ([RFC 5849 section 1.1][rfc]) of the OAuth 1.0
//! protocol.
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-1.1

#![doc(html_root_url = "https://docs.rs/oauth-credentials/0.1.0")]
#![cfg_attr(feature = "cargo-clippy", allow(renamed_and_removed_lints))]
#![cfg_attr(feature = "cargo-clippy", allow(redundant_field_names))]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate core as std;

use std::borrow::Borrow;
use std::fmt::{self, Debug, Formatter};

/// A "credentials" pair defined in [RFC 5849 section 1.1][rfc].
///
/// [rfc]: https://tools.ietf.org/html/rfc5849#section-1.1
///
/// This type represents:
///
/// - Client credentials (consumer key and secret)
/// - Temporary credentials (request token and secret)
/// - Token credentials (access token and secret)
#[derive(Clone, Copy)]
pub struct Credentials<T> {
    /// The unique identifier part of the credentials pair.
    pub identifier: T,
    /// The shared secret part of the credentials pair.
    pub secret: T,
}

/// A set of client credentials and token/temporary credentials used for authorizing requests
/// on behalf of a resource owner.
#[derive(Clone, Copy, Debug)]
pub struct Token<C, T> {
    /// Client credentials.
    pub client: Credentials<C>,
    /// Token/temporary credentials.
    pub token: Credentials<T>,
}

impl<T: Borrow<str>> Credentials<T> {
    /// Creates a new `Credentials`.
    pub fn new(identifier: T, secret: T) -> Self {
        Credentials {
            identifier: identifier,
            secret: secret,
        }
    }

    /// Returns the unique identifier part of the credentials pair.
    pub fn identifier(&self) -> &str {
        self.identifier.borrow()
    }

    /// Returns the shared secret part of the credentials pair.
    pub fn secret(&self) -> &str {
        self.secret.borrow()
    }

    /// Converts from `&Credentials<T>` to `Credentials<&str>`.
    pub fn as_ref(&self) -> Credentials<&str> {
        Credentials {
            identifier: self.identifier.borrow(),
            secret: self.secret.borrow(),
        }
    }
}

impl<'a, T: Borrow<str>> From<&'a Credentials<T>> for Credentials<&'a str> {
    fn from(credentials: &'a Credentials<T>) -> Self {
        credentials.as_ref()
    }
}

impl<T: Debug> Debug for Credentials<T> {
    fn fmt<'a>(&self, f: &mut Formatter<'a>) -> fmt::Result {
        struct Hidden;
        impl Debug for Hidden {
            fn fmt<'a>(&self, f: &mut Formatter<'a>) -> fmt::Result {
                f.write_str("<hidden>")
            }
        }

        #[derive(Debug)]
        struct Credentials<T> {
            identifier: T,
            secret: Hidden,
        }

        Credentials {
            identifier: &self.identifier,
            secret: Hidden,
        }
        .fmt(f)
    }
}

impl<C: Borrow<str>, T: Borrow<str>> Token<C, T> {
    /// Creates a new `Token`.
    pub fn new(client: Credentials<C>, token: Credentials<T>) -> Self {
        Token {
            client: client,
            token: token,
        }
    }

    /// Creates a new `Token` out of identifier and shared-secret strings.
    pub fn from_parts(client_identifier: C, client_secret: C, token: T, token_secret: T) -> Self {
        let client = Credentials::new(client_identifier, client_secret);
        let token = Credentials::new(token, token_secret);
        Token::new(client, token)
    }

    /// Returns the client credentials part.
    pub fn client(&self) -> Credentials<&str> {
        self.client.as_ref()
    }

    /// Returns the token credentials part.
    pub fn token(&self) -> Credentials<&str> {
        self.token.as_ref()
    }

    /// Converts from `&Token<C, T>` to `Token<&str, &str>`.
    pub fn as_ref(&self) -> Token<&str, &str> {
        Token::new(self.client(), self.token())
    }
}

impl<'a, 'b> Token<&'a str, &'b str> {
    /// Creates a new `Token<&str, &str>` from a pair of `&Credentials<_>`.
    pub fn from_ref<C: Borrow<str>, T: Borrow<str>>(
        client: &'a Credentials<C>,
        token: &'b Credentials<T>,
    ) -> Self {
        Token::new(client.as_ref(), token.as_ref())
    }
}

impl<'a, C: Borrow<str>, T: Borrow<str>> From<&'a Token<C, T>> for Token<&'a str, &'a str> {
    fn from(token: &'a Token<C, T>) -> Self {
        token.as_ref()
    }
}
