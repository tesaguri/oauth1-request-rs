# oauth1-request

[![Build Status](https://travis-ci.org/tesaguri/oauth1-request.svg?branch=master)](https://travis-ci.org/tesaguri/oauth1-request/)
[![Current Version](https://img.shields.io/crates/v/oauth1-request.svg)](https://crates.io/crates/oauth1-request)
[![Documentation](https://docs.rs/oauth1-request/badge.svg)](https://docs.rs/oauth1-request/)

Yet yet yet another OAuth 1 client library for Rust.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
oauth1-request = "0.2"
```

and this to your crate root:

```rust
extern crate oauth1_request;
```

## Pros

* No dependency on `ring` (which can cause some compatibility issues).
* *Slightly* lower memory footprint (*maybe*): it avoids allocating memory for sorting query pairs unlike other crates.

## Cons

* Only dogfed on Twitter and likely to break on other sites.
* Less ergonomic API: it requires you to explicitly handle the ordering of query/OAuth parameters.
