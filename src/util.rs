use std::fmt::{self, Display, Formatter, Write};
use std::str;

use percent_encoding::{EncodeSet as EncodeSet_, PercentEncode as PercentEncode_};
use rand::prelude::*;

macro_rules! options {
    ($(
        $(#[$attr:meta])*
        pub struct $O:ident<$lifetime:tt> {
            $($field:tt)*
        }
    )*) => {$(
        $(#[$attr])*
        pub struct $O<$lifetime> {
            $($field)*
        }

        impl<$lifetime> $O<$lifetime> {
            pub fn new() -> Self {
                Default::default()
            }

            impl_setters! { $($field)* }
        }
    )*};
}

macro_rules! impl_setters {
    ($(#[$attr:meta])* $setter:ident: Option<NonZeroU64>, $($rest:tt)*) => {
        $(#[$attr])*
        pub fn $setter(&mut self, $setter: impl Into<Option<u64>>) -> &mut Self {
            self.$setter = $setter.into().and_then(NonZeroU64::new);
            self
        }
        impl_setters! { $($rest)* }
    };
    ($(#[$attr:meta])* $setter:ident: Option<$t:ty>, $($rest:tt)*) => {
        $(#[$attr])*
        pub fn $setter(&mut self, $setter: impl Into<Option<$t>>) -> &mut Self {
            self.$setter = $setter.into();
            self
        }
        impl_setters! { $($rest)* }
    };
    ($(#[$attr:meta])* $setter:ident: $t:ty, $($rest:tt)*) => {
        $(#[$attr])*
        pub fn $setter(&mut self, $setter: impl Into<Option<$t>>) -> &mut Self {
            self.$setter = $setter;
            self
        }
        impl_setters! { $($rest)* }
    };
    () => {};
}

pub struct DisplayBefore<D>(pub char, pub D);

pub struct DoublePercentEncode<'a>(pub &'a str);

#[derive(Clone)]
pub struct EncodeSet;

pub struct PercentEncode<D>(pub D);

pub struct UrlSafe;

impl<D: Display> Display for DisplayBefore<D> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        struct Adapter<'a, 'b: 'a> {
            f: &'a mut Formatter<'b>,
            sep: char,
            finished: bool,
        }

        impl<'a, 'b: 'a> Write for Adapter<'a, 'b> {
            fn write_str(&mut self, mut s: &str) -> fmt::Result {
                if self.finished {
                    return Ok(());
                }
                if let Some(i) = s.find(self.sep) {
                    self.finished = true;
                    s = &s[..i];
                }
                self.f.write_str(s)
            }
            fn write_char(&mut self, c: char) -> fmt::Result {
                if self.finished {
                    return Ok(());
                }
                if c == self.sep {
                    self.finished = true;
                    return Ok(());
                }
                self.f.write_char(c)
            }
        }

        let mut a = Adapter {
            f,
            sep: self.0,
            finished: false,
        };
        write!(a, "{}", self.1)
    }
}

impl<'a> Display for DoublePercentEncode<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut bytes = self.0.as_bytes();
        while let Some((&b, rem)) = bytes.split_first() {
            if EncodeSet.contains(b) {
                f.write_str(double_encode_byte(b))?;
                bytes = rem;
                continue;
            }

            // Write as much characters as possible at once:
            if let Some((i, &b)) = bytes
                .iter()
                .enumerate()
                .skip(1)
                .find(|&(_, &b)| EncodeSet.contains(b))
            {
                let rem = &bytes[i + 1..];
                let s = &bytes[..i];
                debug_assert!(s.is_ascii());
                f.write_str(unsafe { str::from_utf8_unchecked(s) })?;
                f.write_str(double_encode_byte(b))?;
                bytes = rem;
            } else {
                debug_assert!(bytes.is_ascii());
                return f.write_str(unsafe { str::from_utf8_unchecked(bytes) });
            }
        }

        Ok(())
    }
}

impl EncodeSet_ for EncodeSet {
    fn contains(&self, b: u8) -> bool {
        // https://tools.ietf.org/html/rfc3986#section-2.1
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const ENCODE_MAP: [bool; 0x100] = [
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true, false, false,  true,
            false, false, false, false, false, false, false, false,
            false, false,  true,  true,  true,  true,  true,  true,
             true, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false,  true,  true,  true,  true, false,
             true, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false,  true,  true,  true, false,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
             true,  true,  true,  true,  true,  true,  true,  true,
        ];

        ENCODE_MAP[usize::from(b)]
    }
}

impl<D: Display> Display for PercentEncode<D> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        struct Adapter<'a, 'b: 'a>(&'a mut Formatter<'b>);
        impl<'a, 'b: 'a> Write for Adapter<'a, 'b> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                Display::fmt(&percent_encode(s), self.0)
            }
        }
        write!(Adapter(f), "{}", self.0)
    }
}

impl Distribution<u8> for UrlSafe {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> u8 {
        const MAP: &[u8; 64] = b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";
        MAP[(rng.next_u32() >> (32 - 6)) as usize]
    }
}

fn double_encode_byte(b: u8) -> &'static str {
    const ENCODE: &[u8; 0x100 * 5] = b"\
        %2500%2501%2502%2503%2504%2505%2506%2507%2508%2509%250A%250B%250C%250D%250E%250F\
        %2510%2511%2512%2513%2514%2515%2516%2517%2518%2519%251A%251B%251C%251D%251E%251F\
        %2520%2521%2522%2523%2524%2525%2526%2527%2528%2529%252A%252B%252C%252D%252E%252F\
        %2530%2531%2532%2533%2534%2535%2536%2537%2538%2539%253A%253B%253C%253D%253E%253F\
        %2540%2541%2542%2543%2544%2545%2546%2547%2548%2549%254A%254B%254C%254D%254E%254F\
        %2550%2551%2552%2553%2554%2555%2556%2557%2558%2559%255A%255B%255C%255D%255E%255F\
        %2560%2561%2562%2563%2564%2565%2566%2567%2568%2569%256A%256B%256C%256D%256E%256F\
        %2570%2571%2572%2573%2574%2575%2576%2577%2578%2579%257A%257B%257C%257D%257E%257F\
        %2580%2581%2582%2583%2584%2585%2586%2587%2588%2589%258A%258B%258C%258D%258E%258F\
        %2590%2591%2592%2593%2594%2595%2596%2597%2598%2599%259A%259B%259C%259D%259E%259F\
        %25A0%25A1%25A2%25A3%25A4%25A5%25A6%25A7%25A8%25A9%25AA%25AB%25AC%25AD%25AE%25AF\
        %25B0%25B1%25B2%25B3%25B4%25B5%25B6%25B7%25B8%25B9%25BA%25BB%25BC%25BD%25BE%25BF\
        %25C0%25C1%25C2%25C3%25C4%25C5%25C6%25C7%25C8%25C9%25CA%25CB%25CC%25CD%25CE%25CF\
        %25D0%25D1%25D2%25D3%25D4%25D5%25D6%25D7%25D8%25D9%25DA%25DB%25DC%25DD%25DE%25DF\
        %25E0%25E1%25E2%25E3%25E4%25E5%25E6%25E7%25E8%25E9%25EA%25EB%25EC%25ED%25EE%25EF\
        %25F0%25F1%25F2%25F3%25F4%25F5%25F6%25F7%25F8%25F9%25FA%25FB%25FC%25FD%25FE%25FF\
    ";
    let b = usize::from(b);
    unsafe { str::from_utf8_unchecked(&ENCODE[b * 5..(b + 1) * 5]) }
}

pub fn percent_encode(input: &str) -> PercentEncode_<EncodeSet> {
    ::percent_encoding::utf8_percent_encode(input, EncodeSet)
}

#[cfg(test)]
mod tests {
    use super::*;

    use percent_encoding::percent_encode_byte;

    #[test]
    fn double_percent_encode() {
        for b in 0u8..=0xFF {
            assert_eq!(
                double_encode_byte(b),
                &percent_encode(percent_encode_byte(b)).to_string(),
            );
        }
    }

    #[test]
    fn encode_set() {
        for b in 0u8..=0xFF {
            let expected = match b {
                b'0'...b'9' | b'A'...b'Z' | b'a'...b'z' | b'-' | b'.' | b'_' | b'~' => false,
                _ => true,
            };
            assert_eq!(
                EncodeSet.contains(b),
                expected,
                "byte = {} ({:?})",
                b,
                char::from(b),
            );
        }
    }
}
