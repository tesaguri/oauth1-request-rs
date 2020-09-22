#[derive(oauth1_request::Request)]
struct Test {
    #[oauth1]
    //~^ ERROR: expected parentheses after `oauth1`
    meta_word: u8,

    #[oauth1 = ""]
    //~^ ERROR: expected parentheses
    meta_name_value: u8,

    #[oauth1("")]
    //~^ ERROR: expected identifier
    meta_list_lit: u8,

    #[oauth1(word word)]
    //~^ ERROR: expected `,`
    redundant_word: u8,

    #[oauth1(word word word)]
    //~^ ERROR: expected `,`
    redundant_words: u8,

    #[oauth1(name = value value)]
    //~^ ERROR: expected `,`
    redundant_value: u8,

    #[oauth1(name = value value value)]
    //~^ ERROR: expected `,`
    redundant_values: u8,

    #[oauth1(name = )]
    //~^ ERROR: unexpected end of input, expected expression
    missing_value: u8,

    #[oauth1(, meta)]
    //~^ ERROR: expected identifier
    empty_head: u8,

    #[oauth1(meta, , meta)]
    //~^ ERROR: expected identifier
    empty_mid: u8,

    #[oauth1(meta, ,)]
    //~^ ERROR: expected identifier
    empty_tail: u8,
}

fn main() {}
