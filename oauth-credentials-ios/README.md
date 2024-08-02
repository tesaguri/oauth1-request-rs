#oauth-credentials-ios

[![crates.io](https://img.shields.io/crates/v/oauth-credentials-ios.svg)](https://crates.io/crates/oauth-credentials-ios)
[![docs.rs](https://docs.rs/oauth-credentials-ios/badge.svg)](https://docs.rs/oauth-credentials-ios/)
[![Rust 1.0.0+](https://img.shields.io/badge/rust-1.0.0%2B-blue.svg)](#section-msrv)

`oauth-credentials-ios` crate defines Rust types related to the "credentials" pair
([RFC 5849 section 1.1][rfc]) of the OAuth 1.0 protocol.

[rfc]: https://tools.ietf.org/html/rfc5849#section-1.1

## Stability

The goal of `oauth-credentials-ios` is to provide a stable and interoperable
foundation for OAuth implementations.

However, the crate is still unstable in the sense of Semantic Versioning. But we
are not planning to make any breaking change and are going to publish the API
as it is as version 1.0.0 using the [semver trick] unless we find a flaw in the
API significant enough to justify a breaking change.

[semver trick]: https://github.com/dtolnay/semver-trick
[#5]: https://github.com/tesaguri/oauth1-request-rs/pull/5

While you should not use it as a public dependency of a stable crate yet
(see [C-STABLE] of Rust API Guidelines), it is ready as a public dependency of
an unstable crate and as a private dependency of a stable crate.

[C-STABLE]: https://rust-lang.github.io/api-guidelines/necessities.html#public-dependencies-of-a-stable-crate-are-stable-c-stable

## <span id="section-msrv">MSRV</span>

The minimum supported Rust version of `oauth-credentials-ios` is Rust 1.0.0.

Some Cargo features require newer Rust toolchain as shown below.

Feature | MSRV
-|-
(none) | 1.6.0
`std` (default) | 1.0.0
`serde` | (See [Serde's `rust-version`][serde-cargo-toml])
`alloc` (without `std`) | 1.36.0

Note that if your crate uses the `serde` feature (even if optionally!), it
cannot be compiled directly with Rust 1.7.x and older due to
[rust-lang/cargo#3763], but it can somehow be compiled as a dependency of
another crate if the feature is disabled.

[serde-cargo-toml]: https://docs.rs/crate/serde/latest/source/Cargo.toml.orig
[rust-lang/cargo#3763]: https://github.com/rust-lang/cargo/issues/3763
