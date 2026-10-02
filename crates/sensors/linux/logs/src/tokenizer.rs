//! Quote-aware field reader shared by the access-log presets.
//!
//! Escapes: inside a quoted field `\"` and `\\` are decoded; every other backslash
//! sequence (`\xhh`, `\n`, ...) is kept literally. Apache writes non-printable bytes
//! as `\xhh` and nginx writes `"` as `\x22`, and decoding them could produce invalid
//! UTF-8 or hide a quote from a later signature, so they stay as written.

use crate::ParseError;

pub(crate) struct Cursor<'a> {
    rest: &'a str,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(line: &'a str) -> Self {
        Self { rest: line }
    }

    fn skip_spaces(&mut self) {
        self.rest = self.rest.trim_start_matches(' ');
    }

    /// True when only spaces remain.
    pub(crate) fn at_end(&mut self) -> bool {
        self.skip_spaces();
        self.rest.is_empty()
    }

    /// A bare token up to the next space.
    pub(crate) fn word(&mut self, field: &'static str) -> Result<&'a str, ParseError> {
        self.skip_spaces();
        if self.rest.is_empty() {
            return Err(ParseError::MissingField(field));
        }
        let end = self.rest.find(' ').unwrap_or(self.rest.len());
        let (word, rest) = self.rest.split_at(end);
        self.rest = rest;
        Ok(word)
    }

    fn expect_open(&mut self, open: char, field: &'static str) -> Result<&'a str, ParseError> {
        self.skip_spaces();
        if self.rest.is_empty() {
            return Err(ParseError::MissingField(field));
        }
        self.rest
            .strip_prefix(open)
            .ok_or_else(|| ParseError::BadField(field, format!("expected {open:?}")))
    }

    /// `[...]`, as used for the timestamp. No escapes: the content cannot contain `]`.
    pub(crate) fn bracketed(&mut self, field: &'static str) -> Result<&'a str, ParseError> {
        let inner = self.expect_open('[', field)?;
        let end = inner.find(']').ok_or(ParseError::Unterminated)?;
        self.rest = &inner[end + 1..];
        Ok(&inner[..end])
    }

    /// `"..."` with `\"` and `\\` decoded.
    pub(crate) fn quoted(&mut self, field: &'static str) -> Result<String, ParseError> {
        let inner = self.expect_open('"', field)?;
        let mut out = String::new();
        let mut chars = inner.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    self.rest = &inner[i + 1..];
                    return Ok(out);
                }
                '\\' => match chars.next() {
                    Some((_, e @ ('"' | '\\'))) => out.push(e),
                    Some((_, e)) => {
                        out.push('\\');
                        out.push(e);
                    }
                    None => return Err(ParseError::Unterminated),
                },
                c => out.push(c),
            }
        }
        Err(ParseError::Unterminated)
    }
}
