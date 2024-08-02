#[derive(oauth1_request_ios::Request)]
#[oauth1(unknown)]
struct UnknownWord {}

#[derive(oauth1_request_ios::Request)]
#[oauth1(unknown::path)]
struct UnknownPathWord {}

#[derive(oauth1_request_ios::Request)]
#[oauth1(unknown = "")]
struct UnknownNameValue {}

#[derive(oauth1_request_ios::Request)]
#[oauth1(unknown::path = "")]
struct UnknownPathName {}

#[derive(oauth1_request_ios::Request)]
#[oauth1(unknown::path(""))]
struct UnknownList {}

#[derive(oauth1_request_ios::Request)]
#[oauth1(crate)]
struct ExpectedNameValueUnexpectedWord {}

#[derive(oauth1_request_ios::Request)]
#[oauth1(crate(""))]
struct ExpectedNameValueUnexpectedList {}

#[derive(oauth1_request_ios::Request)]
#[oauth1(crate = oauth1_request)]
#[oauth1(crate = oauth1_request)]
struct DuplicateNameValue {}

#[derive(oauth1_request_ios::Request)]
#[oauth1(crate = oauth1_request, crate = oauth1_request)]
struct DuplicateNameValue2 {}

#[derive(oauth1_request_ios::Request)]
struct Fields {
    #[oauth1(rename = 0)]
    non_str_lit: u8,

    #[oauth1(skip = "")]
    expected_word_unexpected_name_value: u8,

    #[oauth1(skip(""))]
    expected_word_unexpected_list: u8,

    #[oauth1(skip_if)]
    expected_name_value_unexpected_word: u8,

    #[oauth1(skip_if(""))]
    expected_name_value_unexpected_list: u8,

    #[oauth1(unknown)]
    unknown_word: u8,

    #[oauth1(unknown::path)]
    unknown_path_word: u8,

    #[oauth1(unknown = "")]
    unknown_name_value: u8,

    #[oauth1(unknown::path = "")]
    unknown_path_name: u8,

    #[oauth1(unknown(""))]
    unknown_list: u8,

    #[oauth1(unknown::path(""))]
    unknown_path_list_name: u8,

    #[oauth1(skip, skip)]
    duplicate_word: u8,

    #[oauth1(encoded)]
    #[oauth1(encoded)]
    duplicate_word_2: u8,

    #[oauth1(rename = "a", rename = "b")]
    duplicate_name_value: u8,

    #[oauth1(rename = "c")]
    #[oauth1(rename = "d")]
    duplicate_name_value_2: u8,

    #[oauth1(option = FALSE)]
    invalid_boolean: u8,

    #[oauth1(fmt = |_, _| Ok(()))]
    invalid_path: u8,

    duplicate: u8,
    #[oauth1(rename = "duplicate")]
    duplicate_renamed: u8,

    #[oauth1(rename = "?")]
    uri_unsafe: u8,
}

fn main() {}
