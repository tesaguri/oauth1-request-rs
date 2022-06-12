# oauth1-request

[![Build Status](https://github.com/tesaguri/oauth1-request-rs/workflows/CI/badge.svg)](https://github.com/tesaguri/oauth1-request-rs/actions)
[![Current Version](https://img.shields.io/crates/v/oauth1-request.svg)](https://crates.io/crates/oauth1-request)
[![Documentation](https://docs.rs/oauth1-request/badge.svg)](https://docs.rs/oauth1-request/)

Yet yet yet another OAuth 1.0 client library for Rust.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
oauth = { version = "0.6", package = "oauth1-request" }
```

A typical authorization flow looks like this:

```rust
// Define a type to represent your request.
#[derive(oauth::Request)]
struct CreateComment<'a> {
    article_id: u64,
    text: &'a str,
}

let uri = "https://example.com/api/v1/comments/create.json";

let request = CreateComment {
    article_id: 123456789,
    text: "A request signed with OAuth & Rust 🦀 🔏",
};

// Prepare your credentials.
let token =
    oauth::Token::from_parts("consumer_key", "consumer_secret", "token", "token_secret");

// Create the `Authorization` header.
let authorization_header = oauth::post(uri, &request, &token, oauth::HmacSha1);
// `oauth_nonce` and `oauth_timestamp` vary on each execution.
assert_eq!(
    authorization_header,
    "OAuth \
         oauth_consumer_key=\"consumer_key\",\
         oauth_nonce=\"Dk-OGluFEQ4f\",\
         oauth_signature_method=\"HMAC-SHA1\",\
         oauth_timestamp=\"1234567890\",\
         oauth_token=\"token\",\
         oauth_signature=\"n%2FrUgos4CFFZbZK8Z8wFR7drU4c%3D\"",
);

// You can create an `x-www-form-urlencoded` string or a URI with query pairs from the request.

let form = oauth::to_form(&request);
assert_eq!(
    form,
    "article_id=123456789&text=A%20request%20signed%20with%20OAuth%20%26%20Rust%20%F0%9F%A6%80%20%F0%9F%94%8F",
);

let uri = oauth::to_query(uri.to_owned(), &request);
assert_eq!(
    uri,
    "https://example.com/api/v1/comments/create.json?article_id=123456789&text=A%20request%20signed%20with%20OAuth%20%26%20Rust%20%F0%9F%A6%80%20%F0%9F%94%8F",
);
```
