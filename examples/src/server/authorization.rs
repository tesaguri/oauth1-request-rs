//! Constructs to parse the HTTP `Authorization` header values.
//!
//! The `Authorization` header has the following grammar:
//!
//! ```text
//! Authorization = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
//! ```
//!
//! but the OAuth 1.0 specification expects `auth-param`s only, so we adopt the following grammar:
//!
//! ```text
//! Authorization = auth-scheme [ 1*SP #auth-param ]
//! ```
//!
//! https://tools.ietf.org/html/rfc7235

use std::borrow::Cow;

use nom::branch::alt;
use nom::bytes::complete::{escaped_transform, tag, take_while1, take_while_m_n};
use nom::character::complete::space0;
use nom::character::{is_alphanumeric, is_space};
use nom::error::Error;
use nom::sequence::delimited;
use nom::{IResult, Parser};

/// An iterator that parses `[F *(G F)]` and yields the output of `F`.
pub struct Punctuated<I, E, F, G> {
    input: I,
    parser: F,
    punct: G,
    state: State<E>,
}

enum State<E> {
    Head,
    Mid,
    Done,
    Err(nom::Err<E>),
}

impl<I, O, O2, E, F, G> Punctuated<I, E, F, G>
where
    I: Clone,
    F: FnMut(I) -> IResult<I, O, E>,
    G: FnMut(I) -> IResult<I, O2, E>,
{
    pub fn new(input: I, parser: F, punct: G) -> Self {
        Punctuated {
            input,
            parser,
            punct,
            state: State::Head,
        }
    }

    pub fn finish(self) -> IResult<I, (), E> {
        match self.state {
            State::Head | State::Mid | State::Done => Ok((self.input, ())),
            State::Err(e) => Err(e),
        }
    }
}

impl<I, O, O2, E, F, G> Iterator for Punctuated<I, E, F, G>
where
    I: Clone,
    F: FnMut(I) -> IResult<I, O, E>,
    G: FnMut(I) -> IResult<I, O2, E>,
{
    type Item = O;

    fn next(&mut self) -> Option<O> {
        macro_rules! try_parse {
            ($e:expr) => {
                match $e {
                    Ok(t) => t,
                    Err(nom::Err::Error(_)) => {
                        self.state = State::Done;
                        return None;
                    }
                    Err(e) => {
                        self.state = State::Err(e);
                        return None;
                    }
                }
            };
        }

        match self.state {
            State::Head => {
                let (input, o) = try_parse!(self.parser.parse(self.input.clone()));
                self.input = input;
                self.state = State::Mid;
                Some(o)
            }
            State::Mid => {
                let (input, _) = try_parse!(self.punct.parse(self.input.clone()));
                let (input, o) = try_parse!(self.parser.parse(input));
                self.input = input;
                Some(o)
            }
            State::Done | State::Err(_) => None,
        }
    }
}

/// ```text
/// auth-scheme = token
/// ```
pub fn auth_scheme<'a>(input: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    token(input)
}

/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
#[allow(clippy::type_complexity)]
pub fn auth_param<'a>(input: &'a [u8]) -> IResult<&'a [u8], (&'a [u8], Cow<'a, [u8]>)> {
    let (input, key) = token(input)?;
    let (input, _) = ows(input)?;
    let (input, _) = tag(b"=")(input)?;
    let (input, _) = ows(input)?;
    let (input, value) = alt((quoted_string.map(Cow::Owned), token.map(Cow::Borrowed)))(input)?;
    Ok((input, (key, value)))
}

/// ```text
/// #f => [f *( OWS "," OWS f )]
/// ```
pub fn hash<'a, O, F>(
    input: &'a [u8],
    f: F,
) -> Punctuated<&'a [u8], Error<&'a [u8]>, F, impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()>>
where
    F: FnMut(&'a [u8]) -> IResult<&'a [u8], O>,
{
    let punct = |input| {
        let (input, _) = ows(input)?;
        let (input, _) = tag(b",")(input)?;
        let (input, _) = ows(input)?;
        Ok((input, ()))
    };
    Punctuated::new(input, f, punct)
}

/// ```text
/// token = 1*tchar
/// ```
fn token<'a>(input: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    take_while1(is_tchar)(input)
}

/// ```text
/// OWS = *( SP / HTAB )
/// ```
fn ows<'a>(input: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    space0(input)
}

/// ```text
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
/// ```
fn is_tchar(b: u8) -> bool {
    is_alphanumeric(b) || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// ```text
/// quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
/// quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
/// ```
fn quoted_string<'a>(input: &'a [u8]) -> IResult<&'a [u8], Vec<u8>> {
    let qdtext0 = take_while1(is_qdtext);
    let escaped = take_while_m_n(1, 1, |b| is_space(b) || is_vchar(b) || is_obs_text(b));
    let sep = escaped_transform(qdtext0, '\\', escaped);
    delimited(tag(b"\""), sep, tag(b"\""))(input)
}

/// ```text
/// qdtext = HTAB / SP /%x21 / %x23-5B / %x5D-7E / obs-text
/// ```
fn is_qdtext(b: u8) -> bool {
    is_space(b)
        || b == 0x21
        || (0x23..=0x5B).contains(&b)
        || (0x5D..=0x7E).contains(&b)
        || is_obs_text(b)
}

/// ```text
/// obs-text = %x80-FF
/// ```
fn is_obs_text(b: u8) -> bool {
    (0x80..).contains(&b)
}

/// ```text
/// VCHAR = %x21-7E
/// ```
fn is_vchar(b: u8) -> bool {
    (0x21..=0x7E).contains(&b)
}
