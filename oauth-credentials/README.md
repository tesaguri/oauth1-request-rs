# oauth-credentials

[![crates.io](https://img.shields.io/crates/v/oauth-credentials.svg)](https://crates.io/crates/oauth-credentials)
[![docs.rs](https://docs.rs/oauth-credentials/badge.svg)](https://docs.rs/oauth-credentials/)

`oauth-credentials` crate defines a Rust type for the "credentials" pair
([RFC 5849 section 1.1][rfc]) of the OAuth 1.0 protocol.

[rfc]: https://tools.ietf.org/html/rfc5849#section-1.1

## Stability

The goal of `oauth-credentials` is to provide a stable foundation for OAuth implementations.

The crate is still unstable in the sense of Semantic Versioning. However, we are not planning to
make any breaking change and are going to publish the API as it is as version 1.0.0 using the
[semver trick] unless we find a flaw in the API significant enough to justify a breaking change.

[semver trick]: https://github.com/dtolnay/semver-trick

While you should not use it as a public dependency of a stable crate yet
(see [C-STABLE] of Rust API Guidelines), it is ready as a public dependency of an unstable crate
and as a private dependency of a stable crate.

[C-STABLE]: https://rust-lang.github.io/api-guidelines/necessities.html#public-dependencies-of-a-stable-crate-are-stable-c-stable

## MSRV

The minimum supported Rust version of `oauth-credentials` is Rust 1.6.0.
When `std` Cargo feature is enabled, it compiles with Rust 1.0.0 and later.