#[derive(oauth1_request_derive::Request)]
struct Test {
    #[oauth1(rename = 0)]
    //~^ ERROR: expected string literal
    non_str_lit: u8,

    #[oauth1(skip = "")]
    //~^ ERROR: expected meta word
    expected_word_unexpected_name_value: u8,

    #[oauth1(skip(""))]
    //~^ ERROR: expected meta word
    expected_word_unexpected_list: u8,

    #[oauth1(skip_if)]
    //~^ ERROR: expected name-value meta
    expected_name_value_unexpected_word: u8,

    #[oauth1(skip_if(""))]
    //~^ ERROR: expected name-value meta
    expected_name_value_unexpected_list: u8,

    #[oauth1(unknown)]
    //~^ ERROR: unknown attribute `unknown`
    unknown_word: u8,

    #[oauth1(unknown::path)]
    //~^ ERROR: unknown attribute `unknown::path`
    unknown_path_word: u8,

    #[oauth1(unknown = "")]
    //~^ ERROR: unknown attribute `unknown`
    unknown_name_value: u8,

    #[oauth1(unknown::path = "")]
    //~^ ERROR: unknown attribute `unknown::path`
    unknown_path_name: u8,

    #[oauth1(unknown(""))]
    //~^ ERROR: unknown attribute `unknown`
    unknown_list: u8,

    #[oauth1(unknown::path(""))]
    //~^ ERROR: unknown attribute `unknown::path`
    unknown_path_list_name: u8,

    #[oauth1(skip, skip)]
    //~^ ERROR: duplicate attribute `skip`
    duplicate_word: u8,

    #[oauth1(encoded)]
    #[oauth1(encoded)]
    //~^ ERROR: duplicate attribute `encoded`
    duplicate_word_2: u8,

    #[oauth1(rename = "a", rename = "b")]
    //~^ ERROR: duplicate attribute `rename`
    duplicate_name_value: u8,

    #[oauth1(rename = "c")]
    #[oauth1(rename = "d")]
    //~^ ERROR: duplicate attribute `rename`
    duplicate_name_value_2: u8,

    #[oauth1(option = FALSE)]
    //~^ ERROR: expected boolean literal
    invalid_boolean: u8,

    #[oauth1(fmt = |_, _| Ok(()))]
    //~^ ERROR: expected path
    invalid_path: u8,

    duplicate: u8,
    #[oauth1(rename = "duplicate")]
    //~^ ERROR: duplicate parameter "duplicate"
    duplicate_renamed: u8,

    #[oauth1(rename = "?")]
    //~^ ERROR: parameter name must be URI-safe
    uri_unsafe: u8,
}

fn main() {}
