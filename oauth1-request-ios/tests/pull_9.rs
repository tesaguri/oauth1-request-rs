//! Test for <https://github.com/tesaguri/oauth1-request-rs/pull/9>.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
fn pull_9() {
    let _ = oauth1_request_ios::get(
        "",
        &(),
        &oauth_credentials_ios::Token::from_parts("", "", "", ""),
        oauth1_request_ios::PLAINTEXT,
    );
}
