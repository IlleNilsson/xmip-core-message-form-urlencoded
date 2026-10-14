#![forbid(unsafe_code)]

//! Form-urlencoded: what a browser posts and a token endpoint answers,
//! `key=value&key=value` with every byte outside the unreserved set written
//! as `%XX` and a space as `+`. One part per pair, in order, named by the
//! decoded key and carrying the decoded value as its bytes; no announced
//! type, because a form says nothing about itself (ADR-0047).
//!
//! A pair without `=` is a key with an empty value, as the WHATWG parser
//! reads it. A key may repeat; the parts repeat with it. What is refused is
//! a `%` not followed by two hex digits, at that byte, because nothing can
//! be decoded past it.

use message::{Part, Shape, ShapeError, Shaped, Stop};
use stream::Stream;

/// The form-urlencoded shape.
#[derive(Clone, Copy, Debug, Default)]
pub struct FormUrlencoded;

/// The bytes a pair may carry as written, before decoding.
fn is_encoded_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~%+*!'()".contains(&byte)
}

/// Whether `bytes` are pairs as written: ASCII, no whitespace, `=` in
/// every pair.
fn looks_encoded(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.split(|b| *b == b'&').all(|pair| {
            pair.contains(&b'=') && pair.iter().all(|b| is_encoded_byte(*b) || *b == b'=')
        })
}

/// `text` percent-decoded with `+` as a space; the offset of a `%` that
/// two hex digits do not follow.
///
/// The `+` is the form's rule and is read here; the escapes are RFC 3986's
/// and are read by `net::percent`, strictly. A `+` becomes a space before
/// the escapes are read, which is the same thing: an escaped `%2B` is not
/// a `+` until it is decoded.
fn decode(text: &[u8], offset: usize) -> Result<Vec<u8>, Stop> {
    let spaced: Vec<u8> = text
        .iter()
        .map(|byte| if *byte == b'+' { b' ' } else { *byte })
        .collect();
    net::percent::decode_strict(&spaced)
        .map_err(|broken| ("a % without two hex digits", offset + broken.at))
}

/// One part per pair.
fn pairs(bytes: &[u8]) -> Result<Vec<Part>, Stop> {
    let mut parts = Vec::new();
    let mut offset = 0;
    for pair in bytes.split(|b| *b == b'&') {
        if !pair.is_empty() {
            let (key, value) = pair
                .iter()
                .position(|b| *b == b'=')
                .map_or((pair, &b""[..]), |eq| (&pair[..eq], &pair[eq + 1..]));
            let name = String::from_utf8_lossy(&decode(key, offset)?).into_owned();
            let value = decode(value, offset + key.len() + 1)?;
            parts.push(Part::new(Some(name), value, None));
        }
        offset += pair.len() + 1;
    }
    Ok(parts)
}

impl Shape for FormUrlencoded {
    fn technology(&self) -> &'static str {
        "form-urlencoded"
    }

    fn media_types(&self) -> &'static [&'static str] {
        &["application/x-www-form-urlencoded"]
    }

    fn recognises(&self, bytes: &[u8]) -> bool {
        looks_encoded(bytes)
    }

    fn shape(&self, stream: &Stream) -> Result<Shaped, ShapeError> {
        let parts =
            pairs(stream.bytes()).map_err(|stop| ShapeError::refused("form-urlencoded", stop))?;
        Ok(Shaped {
            parts,
            message_type: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::StreamId;

    fn stream(bytes: &[u8], media: Option<&str>) -> Stream {
        Stream::new(StreamId::new(1), bytes.to_vec(), media.map(str::to_string))
    }

    #[test]
    fn every_pair_is_a_part_named_by_its_decoded_key_with_its_decoded_value() {
        let form = b"grant_type=client_credentials&scope=a+b%20c&q=%C3%A9&flag&flag=2&&";
        let shaped = FormUrlencoded
            .shape(&stream(form, Some("application/x-www-form-urlencoded")))
            .expect("well-formed");
        let names: Vec<_> = shaped.parts.iter().map(|p| p.name.as_deref()).collect();
        assert_eq!(
            names,
            [
                Some("grant_type"),
                Some("scope"),
                Some("q"),
                Some("flag"),
                Some("flag")
            ]
        );
        assert_eq!(shaped.parts[0].bytes, b"client_credentials");
        assert_eq!(shaped.parts[1].bytes, b"a b c");
        assert_eq!(shaped.parts[2].bytes, "é".as_bytes());
        assert_eq!(shaped.parts[3].bytes, b"");
        assert_eq!(shaped.parts[4].bytes, b"2");
        assert!(shaped.parts.iter().all(|p| p.media_type.is_none()));
        assert_eq!(shaped.message_type, None);
        assert_eq!(
            FormUrlencoded
                .shape(&stream(b"", None))
                .expect("empty")
                .parts,
            Vec::<Part>::new()
        );
    }

    #[test]
    fn a_percent_without_two_hex_digits_is_refused_at_that_byte() {
        let refused = FormUrlencoded
            .shape(&stream(b"a=1&b=x%zz", None))
            .expect_err("bad escape");
        assert_eq!(refused.offset, Some(7));
        assert_eq!(
            refused.to_string(),
            "form-urlencoded: a % without two hex digits at byte 7"
        );
        let cut = FormUrlencoded
            .shape(&stream(b"k%4=v", None))
            .expect_err("bad escape in a key");
        assert_eq!(cut.offset, Some(1));
    }

    #[test]
    fn the_shape_claims_the_form_type_and_recognises_ascii_pairs_without_whitespace() {
        assert_eq!(FormUrlencoded.technology(), "form-urlencoded");
        assert_eq!(
            FormUrlencoded.media_types(),
            &["application/x-www-form-urlencoded"]
        );
        assert!(FormUrlencoded.recognises(b"a=1&b=two+words%21"));
        assert!(FormUrlencoded.recognises(b"a="));
        assert!(!FormUrlencoded.recognises(b"a=1&b"));
        assert!(!FormUrlencoded.recognises(b"a=1 &b=2"));
        assert!(!FormUrlencoded.recognises(b"{\"a\":1}"));
        assert!(!FormUrlencoded.recognises("a=é".as_bytes()));
        assert!(!FormUrlencoded.recognises(b""));
    }

    #[test]
    fn choose_picks_the_form_by_media_type_and_by_look() {
        let shapes: [&dyn Shape; 1] = [&FormUrlencoded];
        let media = Some("application/x-www-form-urlencoded; charset=utf-8");
        let by_media = message::choose(&shapes, &stream(b"plain words", media));
        assert_eq!(by_media.map(Shape::technology), Some("form-urlencoded"));
        let by_look = message::choose(&shapes, &stream(b"a=1&b=2", None));
        assert_eq!(by_look.map(Shape::technology), Some("form-urlencoded"));
        assert!(message::choose(&shapes, &stream(b"plain words", None)).is_none());
    }
}
