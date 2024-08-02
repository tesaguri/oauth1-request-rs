#[derive(oauth1_request_ios::Request)]
struct Test {
    #[oauth1]
    meta_word: u8,

    #[oauth1 = ""]
    meta_name_value: u8,

    #[oauth1("")]
    meta_list_lit: u8,

    #[oauth1(word word)]
    redundant_word: u8,

    #[oauth1(word word word)]
    redundant_words: u8,

    #[oauth1(name = value value)]
    redundant_value: u8,

    #[oauth1(name = value value value)]
    redundant_values: u8,

    #[oauth1(name = )]
    missing_value: u8,

    #[oauth1(, meta)]
    empty_head: u8,

    #[oauth1(meta, , meta)]
    empty_mid: u8,

    #[oauth1(meta, ,)]
    empty_tail: u8,
}

fn main() {}
