extern crate serde;

use std::fmt::{self, Formatter};
use std::marker::PhantomData;

use self::serde::ser::SerializeStruct;
use self::serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use super::Credentials;

enum Field {
    Identifier,
    Secret,
    Other,
}

const CREDENTIALS: &'static str = "Credentials";
const IDENTIFIER: &'static str = "oauth_token";
const SECRET: &'static str = "oauth_token_secret";

/// Deserializes a `Credentials` from a response from the Temporary Credential Request
/// and Token Request endpoints described in [RFC 5849 section 2][rfc].
///
/// [rfc]: https://tools.ietf.org/html/rfc5849#section-2
///
/// # Example
///
/// ```
/// use oauth_credentials_ios::Credentials;
///
/// # fn main() -> Result<(), serde_urlencoded::de::Error> {
/// // Response body from a Temporary Credential Request endpoint.
/// let response = b"oauth_token=token&oauth_token_secret=secret&oauth_callback_confirmed=true";
/// let deserialized: Credentials = serde_urlencoded::from_bytes(response)?;
/// assert!(matches!(
///     deserialized.as_ref(),
///     Credentials {
///         identifier: "token",
///         secret: "secret",
///     }
/// ));
/// # Ok(())
/// # }
/// ```
///
/// # Define a custom `Deserialize`
///
/// This implementation is not intended for general purpose use. Especially, using it for
/// deserializing a set of client credentials is strongly discouraged because it uses
/// `oauth_token` and `oauth_token_secret` as the field name.
///
/// If you want to deserialize a `Credentials` in a general context, you should use
/// the [`#[serde(remote = "Credentials")]`][remote] attribute:
///
/// [remote]: https://serde.rs/remote-derive.html
///
/// ```
/// # extern crate serde;
/// # #[macro_use]
/// # extern crate serde_derive;
/// #
/// use oauth_credentials_ios::Credentials;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// #[serde(remote = "Credentials")]
/// struct CredentialsDef<T> {
///     #[serde(rename = "client_identifier")]
///     identifier: T,
///     #[serde(rename = "client_secret")]
///     secret: T,
/// }
///
/// #[derive(Deserialize)]
/// struct Helper(#[serde(with = "CredentialsDef")] Credentials);
///
/// # fn main() -> Result<(), serde_json::Error> {
/// let json = r#"{"client_identifier":"client","client_secret":"secret"}"#;
/// let deserialized = serde_json::from_str(json).map(|Helper(c)| c)?;
/// assert!(matches!(
///     deserialized.as_ref(),
///     Credentials {
///         identifier: "client",
///         secret: "secret",
///     }
/// ));
/// # Ok(())
/// # }
/// ```

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Credentials<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Visitor<T> {
            type Value = Credentials<T>;

            fn expecting<'a>(&self, f: &mut Formatter<'a>) -> fmt::Result {
                f.write_str("struct Credentials")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut identifier = None;
                let mut secret = None;

                while let Some(k) = try!(map.next_key::<Field>()) {
                    match k {
                        Field::Identifier => {
                            if identifier.is_some() {
                                return Err(de::Error::duplicate_field(IDENTIFIER));
                            }
                            identifier = Some(try!(map.next_value()));
                        }
                        Field::Secret => {
                            if secret.is_some() {
                                return Err(de::Error::duplicate_field(SECRET));
                            }
                            secret = Some(try!(map.next_value()));
                        }
                        Field::Other => {
                            try!(map.next_value::<de::IgnoredAny>());
                        }
                    }
                }

                let identifier =
                    try!(identifier.ok_or_else(|| de::Error::missing_field(IDENTIFIER)));
                let secret = try!(secret.ok_or_else(|| de::Error::missing_field(SECRET)));

                Ok(Credentials {
                    identifier: identifier,
                    secret: secret,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &[IDENTIFIER, SECRET];
        d.deserialize_struct(CREDENTIALS, FIELDS, Visitor(PhantomData))
    }
}

/// Serializes a `Credentials` into a response of the Temporary Credential Request
/// and Token Request endpoints described in [RFC 5849 section 2][rfc].
///
/// [rfc]: https://tools.ietf.org/html/rfc5849#section-2
///
/// # Example
///
/// ```
/// # extern crate serde;
/// # #[macro_use]
/// # extern crate serde_derive;
/// #
/// use oauth_credentials_ios::Credentials;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct TemporaryCredentialResponse<'a> {
///     #[serde(flatten)]
///     credentials: Credentials<&'a str>,
///     oauth_callback_confirmed: bool,
/// }
///
/// # fn main() -> Result<(), serde_urlencoded::ser::Error> {
/// let client = Credentials {
///     identifier: "token",
///     secret: "secret",
/// };
/// // Create a response body of a Temporary Credential Request endpoint.
/// let response = TemporaryCredentialResponse {
///     credentials: client,
///     oauth_callback_confirmed: true,
/// };
/// let serialized = serde_urlencoded::to_string(&response)?;
/// let expected = "oauth_token=token&oauth_token_secret=secret&oauth_callback_confirmed=true";
/// assert_eq!(serialized, expected);
/// # Ok(())
/// # }
/// ```
///
/// # Define a custom `Serialize`
///
/// This implementation is not intended for general purpose use. Especially, using it for
/// serializing a set of client credentials is strongly discouraged because it uses
/// `oauth_token` and `oauth_token_secret` as the field name.
///
/// If you want to serialize a `Credentials` in a general context, you should use
/// the [`#[serde(remote = "Credentials")]`][remote] attribute:
///
/// [remote]: https://serde.rs/remote-derive.html
///
/// ```
/// # extern crate serde;
/// # #[macro_use]
/// # extern crate serde_derive;
/// #
/// use oauth_credentials_ios::Credentials;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// #[serde(remote = "Credentials")]
/// struct CredentialsDef<T> {
///     #[serde(rename = "client_identifier")]
///     identifier: T,
///     #[serde(rename = "client_secret")]
///     secret: T,
/// }
///
/// #[derive(Serialize)]
/// struct Helper<'a>(#[serde(with = "CredentialsDef")] Credentials<&'a str>);
///
/// # fn main() -> Result<(), serde_json::Error> {
/// let client = Credentials {
///     identifier: "client",
///     secret: "secret",
/// };
/// let serialized = serde_json::to_string(&Helper(client.as_ref()))?;
/// let expected = r#"{"client_identifier":"client","client_secret":"secret"}"#;
/// assert_eq!(serialized, expected);
/// # Ok(())
/// # }
/// ```
impl<T> Serialize for Credentials<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = try!(s.serialize_struct(CREDENTIALS, 2));
        try!(s.serialize_field(IDENTIFIER, &self.identifier));
        try!(s.serialize_field(SECRET, &self.secret));
        s.end()
    }
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;

        fn visit_bytes(v: &[u8]) -> Field {
            match v {
                b"oauth_token" => Field::Identifier,
                b"oauth_token_secret" => Field::Secret,
                _ => Field::Other,
            }
        }

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Field;

            fn expecting<'a>(&self, f: &mut Formatter<'a>) -> fmt::Result {
                f.write_str("a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Field, E> {
                Ok(visit_bytes(v.as_bytes()))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Field, E> {
                Ok(visit_bytes(v))
            }
        }

        d.deserialize_identifier(Visitor)
    }
}
