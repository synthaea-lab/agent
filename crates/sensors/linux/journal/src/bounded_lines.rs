//! Line reading with a byte cap, so one line without a newline cannot grow the agent's
//! memory without limit.
//!
//! `BufRead::lines` buffers a whole line before returning it. The journal tail reads the
//! stdout of `journalctl`, so an oversized line is a bound on memory, not a parsing detail.

use std::io::{self, BufRead, ErrorKind};

/// The longest line kept, in bytes, newline excluded. `journalctl -o json` writes a field
/// larger than 4096 bytes as `null`, so a record of ordinary size is a few kilobytes; the
/// cap is 256 maximum-size fields. A memory bound chosen by reasoning, not measured on a
/// busy host.
pub(crate) const MAX_LINE_BYTES: usize = 1024 * 1024;

/// One line read from the stream.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Line {
    /// A line within the cap, without its `\n` or `\r\n`.
    Text(String),
    /// A line over the cap, read to its end and dropped.
    Oversize,
}

/// Iterator over the lines of a [`BufRead`], each held to at most `max_bytes`.
///
/// Like [`BufRead::lines`], a line that is not UTF-8 is an `InvalidData` error and the next
/// call goes on with the following line.
pub(crate) struct BoundedLines<R> {
    reader: R,
    max_bytes: usize,
}

impl<R: BufRead> BoundedLines<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self::with_cap(reader, MAX_LINE_BYTES)
    }

    pub(crate) fn with_cap(reader: R, max_bytes: usize) -> Self {
        Self { reader, max_bytes }
    }
}

impl<R: BufRead> Iterator for BoundedLines<R> {
    type Item = io::Result<Line>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = Vec::new();
        let mut oversize = false;
        loop {
            let chunk = match self.reader.fill_buf() {
                Ok(chunk) => chunk,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Some(Err(e)),
            };
            if chunk.is_empty() {
                return match (oversize, line.is_empty()) {
                    (true, _) => Some(Ok(Line::Oversize)),
                    (false, true) => None,
                    (false, false) => Some(finish(line)),
                };
            }
            let newline = chunk.iter().position(|&byte| byte == b'\n');
            let body = &chunk[..newline.unwrap_or(chunk.len())];
            if !oversize {
                if line.len() + body.len() > self.max_bytes {
                    oversize = true;
                    line = Vec::new();
                } else {
                    line.extend_from_slice(body);
                }
            }
            let used = newline.map_or(chunk.len(), |at| at + 1);
            self.reader.consume(used);
            if newline.is_some() {
                return Some(if oversize {
                    Ok(Line::Oversize)
                } else {
                    finish(line)
                });
            }
        }
    }
}

fn finish(mut line: Vec<u8>) -> io::Result<Line> {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line)
        .map(Line::Text)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "stream did not contain valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    fn lines(input: &[u8], cap: usize) -> Vec<io::Result<Line>> {
        BoundedLines::with_cap(Cursor::new(input.to_vec()), cap).collect()
    }

    fn text(value: &str) -> Line {
        Line::Text(value.to_owned())
    }

    #[test]
    fn a_line_at_the_cap_is_kept_and_one_byte_over_is_dropped() {
        let got = lines(b"abcd\nabcde\nabcd\n", 4);
        assert_eq!(
            got.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            vec![text("abcd"), Line::Oversize, text("abcd")]
        );
    }

    #[test]
    fn the_stream_goes_on_after_an_oversize_line() {
        let got = lines(b"ok\nxxxxxxxxxxxxxxxxxxxx\nnext\n", 8);
        assert_eq!(
            got.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            vec![text("ok"), Line::Oversize, text("next")]
        );
    }

    #[test]
    fn an_oversize_line_with_no_newline_at_the_end_of_the_stream_is_reported() {
        let got = lines(b"ok\nxxxxxxxxxxxxxxxxxxxx", 8);
        assert_eq!(
            got.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            vec![text("ok"), Line::Oversize]
        );
    }

    #[test]
    fn a_last_line_without_a_newline_is_kept() {
        let got = lines(b"one\ntwo", 8);
        assert_eq!(
            got.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            vec![text("one"), text("two")]
        );
    }

    #[test]
    fn a_carriage_return_before_the_newline_is_dropped_and_blank_lines_stay() {
        let got = lines(b"one\r\n\ntwo\n", 8);
        assert_eq!(
            got.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            vec![text("one"), text(""), text("two")]
        );
    }

    #[test]
    fn an_empty_stream_yields_nothing() {
        assert!(lines(b"", 8).is_empty());
    }

    #[test]
    fn a_line_that_is_not_utf8_is_an_error_and_the_next_line_is_still_read() {
        let got = lines(b"\xff\xfe\nok\n", 8);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].as_ref().unwrap_err().kind(), ErrorKind::InvalidData);
        assert_eq!(got[1].as_ref().unwrap(), &text("ok"));
    }

    #[test]
    fn a_line_longer_than_the_reader_buffer_is_read_whole_within_the_cap() {
        let long = "y".repeat(100);
        let input = format!("{long}\n{long}z\n");
        let reader = BufReader::with_capacity(8, Cursor::new(input.into_bytes()));
        let got: Vec<_> = BoundedLines::with_cap(reader, 100)
            .map(Result::unwrap)
            .collect();
        assert_eq!(got, vec![Line::Text(long), Line::Oversize]);
    }

    #[test]
    fn the_default_cap_keeps_a_line_of_the_cap_size_and_drops_the_next_byte() {
        let kept = "a".repeat(MAX_LINE_BYTES);
        let dropped = "b".repeat(MAX_LINE_BYTES + 1);
        let input = format!("{kept}\n{dropped}\n");
        let got: Vec<_> = BoundedLines::new(Cursor::new(input.into_bytes()))
            .map(Result::unwrap)
            .collect();
        assert_eq!(got, vec![Line::Text(kept), Line::Oversize]);
    }
}
