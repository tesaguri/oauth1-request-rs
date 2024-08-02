//! Types related to the credential pairs ([RFC 5849 section 1.1][rfc]) of the OAuth 1.0
//! protocol.
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-1.1

#![doc(html_root_url = "https://docs.rs/oauth-credentials-ios/0.0.1")]
#![allow(deprecated)]
#![
    allow(
        // We unconditionally allow Clippy lints since `cfg_attr(feature = "cargo-clippy", …)`
        // won't work since toolchain 1.80.0 as the `cfg` condition raises
        // `clippy::unexpected_cfgs` warning, which triggers just as the `cfg` is evaluated and thus
        // cannot be conditionally allowed.
        unknown_lints,
        renamed_and_removed_lints,
        needless_lifetimes,
    )
]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
extern crate core as std;

#[cfg(feature = "serde")]
mod serde_imp;

use std::fmt::{self, Debug, Formatter};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::string::String;

/// An OAuth "credentials" pair defined in [RFC 5849 section 1.1][rfc].
///
/// [rfc]: https://tools.ietf.org/html/rfc5849#section-1.1
///
/// This type represents:
///
/// - Client credentials (consumer key and secret) used to authenticate as a client.
/// - Temporary credentials (request token and secret) which represent an authorization request.
/// - Token credentials (access token and secret) which represent an access grant from
/// a resource owner to a client.
///
/// In order to make requests on behalf of a resource owner, you (the client) need a set of
/// client credentials and token credentials, which is represented by the [Token] type.
///
/// In a typical authorization flow, you only have client credentials at the beginning. To obtain
/// token credentials, you first obtain a set of temporary credentials using the client
/// credentials. And after the resource owner approves the authorization request, you use the
/// temporary credentials to request a set of token credentials from the server.
#[derive(Clone, Copy)]
#[cfg(feature = "alloc")]
pub struct Credentials<T = String> {
    /// The unique identifier part of the credentials pair.
    pub identifier: T,
    /// The shared secret part of the credentials pair.
    pub secret: T,
}

// XXX: These almost-identical (modulo default type param) items should certainly be defined with a
// macro, but doing so would break the build on toolchains prior to nightly-2016-05-29 (7746a334d).
// Maybe <https://github.com/rust-lang/rust/pull/33926> is relevant?
// Also, `<#[cfg(feature = "alloc")] T = String, #[cfg(not(feature = "alloc"))] T>` cannot be used
// on toolchains prior to 1.27.0.

/// An OAuth "credentials" pair defined in [RFC 5849 section 1.1][rfc].
///
/// [rfc]: https://tools.ietf.org/html/rfc5849#section-1.1
///
/// This type represents:
///
/// - Client credentials (consumer key and secret) used to authenticate as a client.
/// - Temporary credentials (request token and secret) which represent an authorization request.
/// - Token credentials (access token and secret) which represent an access grant from
///   a resource owner to a client.
///
/// In order to make requests on behalf of a resource owner, you (the client) need a set of
/// client credentials and token credentials, which is represented by the [Token] type.
///
/// In a typical authorization flow, you only have client credentials at the beginning. To obtain
/// token credentials, you first obtain a set of temporary credentials using the client
/// credentials. And after the resource owner approves the authorization request, you use the
/// temporary credentials to request a set of token credentials from the server.
#[derive(Clone, Copy)]
#[cfg(not(feature = "alloc"))]
pub struct Credentials<T> {
    /// The unique identifier part of the credentials pair.
    pub identifier: T,
    /// The shared secret part of the credentials pair.
    pub secret: T,
}

/// A set of OAuth client credentials and token/temporary credentials used for authorizing requests
/// on behalf of a resource owner.
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "alloc")]
pub struct Token<C = String, T = C> {
    /// Client credentials.
    pub client: Credentials<C>,
    /// Token/temporary credentials.
    pub token: Credentials<T>,
}

/// A set of OAuth client credentials and token/temporary credentials used for authorizing requests
/// on behalf of a resource owner.
#[derive(Clone, Copy, Debug)]
#[cfg(not(feature = "alloc"))]
pub struct Token<C, T = C> {
    /// Client credentials.
    pub client: Credentials<C>,
    /// Token/temporary credentials.
    pub token: Credentials<T>,
}

impl<T: AsRef<str>> Credentials<T> {
    /// Creates a new `Credentials`.
    pub fn new(identifier: T, secret: T) -> Self {
        Credentials {
            identifier: identifier,
            secret: secret,
        }
    }

    /// Returns the unique identifier part of the credentials pair.
    pub fn identifier(&self) -> &str {
        self.identifier.as_ref()
    }

    /// Returns the shared secret part of the credentials pair.
    pub fn secret(&self) -> &str {
        self.secret.as_ref()
    }

    /// Converts from `&Credentials<T>` to `Credentials<&str>`.
    pub fn as_ref(&self) -> Credentials<&str> {
        Credentials::new(self.identifier(), self.secret())
    }
}

impl<T> Credentials<T> {
    /// Maps a `Credentials<T>` to `Credentials<U>` by applying a function to contained values.
    ///
    /// # Example
    ///
    /// ```edition2018
    /// # use oauth_credentials_ios::Credentials;
    /// # const _: &str = stringify! {
    /// async fn get_temporary_credentials() -> Credentials { /* ... */ }
    /// # };
    /// # async fn f() {
    /// # async fn get_temporary_credentials() -> Credentials {
    /// #     Credentials::new("", "").map(Into::into)
    /// # }
    /// let boxed: Credentials<Box<str>> = get_temporary_credentials().await.map(Into::into);
    /// # }
    /// ```
    pub fn map<U, F>(self, mut f: F) -> Credentials<U>
    where
        F: FnMut(T) -> U,
        U: AsRef<str>,
    {
        Credentials::new(f(self.identifier), f(self.secret))
    }
}

impl<'a, T: AsRef<str>> From<&'a Credentials<T>> for Credentials<&'a str> {
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
            #[allow(dead_code)]
            identifier: T,
            #[allow(dead_code)]
            secret: Hidden,
        }

        Credentials {
            identifier: &self.identifier,
            secret: Hidden,
        }
        .fmt(f)
    }
}

impl<C: AsRef<str>, T: AsRef<str>> Token<C, T> {
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
    pub fn as_ref(&self) -> Token<&str> {
        Token::new(self.client(), self.token())
    }
}

impl<C, T> Token<C, T> {
    /// Maps a `Token<C, T>` to `Token<C2, T>` by applying a function to a contained `client`
    /// value, leaving a `token` value untouched.
    ///
    /// # Example
    ///
    /// ```edition2018
    /// # use oauth_credentials_ios::{Credentials, Token};
    /// async fn get_token<C: AsRef<str>, T: AsRef<str>>(temporary: Token<C, T>) -> Token<C, String> {
    ///     // ...
    /// #     Token::new(temporary.client, Credentials::new("", "").map(Into::into))
    /// }
    /// # async fn f() {
    /// # let temporary = Token::from_parts("", "", "", "");
    /// let token: Token<&str, String> = get_token(temporary.as_ref()).await;
    /// let owned: Token = token.map_client(String::from);
    /// # }
    /// ```
    pub fn map_client<C2, F>(self, f: F) -> Token<C2, T>
    where
        F: FnMut(C) -> C2,
        C2: AsRef<str>,
    {
        Token {
            client: self.client.map(f),
            token: self.token,
        }
    }

    /// Maps a `Token<C, T>` to `Token<C, T2>` by applying a function to a contained `token`
    /// value, leaving a `client` value untouched.
    ///
    /// # Example
    ///
    /// ```edition2018
    /// # use oauth_credentials_ios::{Credentials, Token};
    /// async fn get_token<C: AsRef<str>, T: AsRef<str>>(temporary: Token<C, T>) -> Token<C, String> {
    ///     // ...
    /// #     Token::new(temporary.client, Credentials::new("", "").map(Into::into))
    /// }
    /// # async fn f() {
    /// # let temporary = Token::from_parts("", "", "", "").map_client(Into::into);
    /// let token: Token<Box<str>, String> = get_token(temporary).await;
    /// let boxed: Token<Box<str>> = token.map_token(Into::into);
    /// # }
    /// ```
    pub fn map_token<T2, F>(self, f: F) -> Token<C, T2>
    where
        F: FnMut(T) -> T2,
        T2: AsRef<str>,
    {
        Token {
            client: self.client,
            token: self.token.map(f),
        }
    }
}

impl<T> Token<T> {
    /// Maps a `Token<T, T>` to `Token<U, U>` by applying a function to contained string values.
    ///
    /// # Example
    ///
    /// ```edition2018
    /// # use oauth_credentials_ios::Token;
    /// async fn get_token() -> Token {
    ///     // ...
    /// #     Token::from_parts("", "", "", "").map(Into::into)
    /// }
    /// # async fn f() {
    /// let token: Token = get_token().await;
    /// let boxed: Token<Box<str>> = token.map(Into::into);
    /// # }
    /// ```
    pub fn map<U, F>(self, mut f: F) -> Token<U>
    where
        F: FnMut(T) -> U,
        U: AsRef<str>,
    {
        self.map_client(&mut f).map_token(f)
    }
}

impl<'a, 'b> Token<&'a str, &'b str> {
    /// Creates a new `Token<&str, &str>` from a pair of `&Credentials<_>`.
    pub fn from_ref<C: AsRef<str>, T: AsRef<str>>(
        client: &'a Credentials<C>,
        token: &'b Credentials<T>,
    ) -> Self {
        Token::new(client.as_ref(), token.as_ref())
    }
}

impl<'a, C: AsRef<str>, T: AsRef<str>> From<&'a Token<C, T>> for Token<&'a str> {
    fn from(token: &'a Token<C, T>) -> Self {
        token.as_ref()
    }
}
