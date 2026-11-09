//! Line reading with a byte cap, so one line without a newline cannot grow the agent's
//! memory without limit.
//!
//! `BufRead::lines` buffers a whole line before returning it. The journal tail reads the
//! stdout of `journalctl`, so an oversized line is a bound on memory, not a parsing detail.

use std::io::{self, BufRead, ErrorKind};

/// The longest line kept, in bytes, `\n` excluded. A trailing `\r` counts toward it. `journalctl -o json` writes a field
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
    /// The line being read. Kept here, not local to `next`, so a read error in the middle of
    /// a line does not lose the state: the next call goes on with the same line.
    line: Vec<u8>,
    oversize: bool,
}

impl<R: BufRead> BoundedLines<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self::with_cap(reader, MAX_LINE_BYTES)
    }

    pub(crate) fn with_cap(reader: R, max_bytes: usize) -> Self {
        Self {
            reader,
            max_bytes,
            line: Vec::new(),
            oversize: false,
        }
    }
}

impl<R: BufRead> Iterator for BoundedLines<R> {
    type Item = io::Result<Line>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let chunk = match self.reader.fill_buf() {
                Ok(chunk) => chunk,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Some(Err(e)),
            };
            if chunk.is_empty() {
                let oversize = std::mem::take(&mut self.oversize);
                let line = std::mem::take(&mut self.line);
                return match (oversize, line.is_empty()) {
                    (true, _) => Some(Ok(Line::Oversize)),
                    (false, true) => None,
                    (false, false) => Some(finish(line)),
                };
            }
            let newline = chunk.iter().position(|&byte| byte == b'\n');
            let body = &chunk[..newline.unwrap_or(chunk.len())];
            if !self.oversize {
                if self.line.len() + body.len() > self.max_bytes {
                    self.oversize = true;
                    self.line = Vec::new();
                } else {
                    self.line.extend_from_slice(body);
                }
            }
            let used = newline.map_or(chunk.len(), |at| at + 1);
            self.reader.consume(used);
            if newline.is_some() {
                let oversize = std::mem::take(&mut self.oversize);
                let line = std::mem::take(&mut self.line);
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

    /// Reference answer for one `\n`-separated segment of the input.
    fn expected(segment: &[u8], cap: usize) -> Result<Line, ()> {
        if segment.len() > cap {
            return Ok(Line::Oversize);
        }
        let body = segment.strip_suffix(b"\r").unwrap_or(segment);
        String::from_utf8(body.to_vec())
            .map(Line::Text)
            .map_err(|_| ())
    }

    #[test]
    fn random_bytes_with_random_caps_never_panic_and_cover_every_segment() {
        // xorshift64: a fixed seed keeps a failure reproducible without a dependency.
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let len = (next() % 200) as usize;
            let input: Vec<u8> = (0..len)
                .map(|_| match next() % 8 {
                    0 => b'\n',
                    1 => b'\r',
                    2 => 0xFF,
                    _ => b'a' + (next() % 26) as u8,
                })
                .collect();
            let cap = (next() % 40) as usize;
            let buffer = 1 + (next() % 16) as usize;

            let got: Vec<_> =
                BoundedLines::with_cap(BufReader::with_capacity(buffer, Cursor::new(&input)), cap)
                    .map(|item| item.map_err(|_| ()))
                    .collect();

            let mut segments: Vec<&[u8]> = input.split(|&b| b == b'\n').collect();
            if segments.last().is_some_and(|last| last.is_empty()) {
                segments.pop();
            }
            let want: Vec<_> = segments.iter().map(|s| expected(s, cap)).collect();
            assert_eq!(got, want, "input {input:?}, cap {cap}, buffer {buffer}");
        }
    }

    /// Serves its parts one after the other; an `Err` part fails once, then reading goes on.
    struct FailsOnce {
        parts: Vec<io::Result<Vec<u8>>>,
        current: Vec<u8>,
    }

    impl io::Read for FailsOnce {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            unreachable!("only BufRead is used")
        }
    }

    impl BufRead for FailsOnce {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.current.is_empty() && !self.parts.is_empty() {
                self.current = self.parts.remove(0)?;
            }
            Ok(&self.current)
        }
        fn consume(&mut self, amount: usize) {
            self.current.drain(..amount);
        }
    }

    #[test]
    fn a_read_error_in_the_middle_of_an_oversize_line_does_not_turn_its_tail_into_a_line() {
        let reader = FailsOnce {
            parts: vec![
                Ok(b"xxxxxxxxxx".to_vec()),
                Err(io::Error::other("boom")),
                Ok(b"yyyy\nnext\n".to_vec()),
            ],
            current: Vec::new(),
        };
        let mut it = BoundedLines::with_cap(reader, 4);
        assert!(it.next().unwrap().is_err());
        assert_eq!(it.next().unwrap().unwrap(), Line::Oversize);
        assert_eq!(it.next().unwrap().unwrap(), text("next"));
        assert!(it.next().is_none());
    }

    #[test]
    fn a_read_error_in_the_middle_of_a_normal_line_does_not_lose_its_head() {
        let reader = FailsOnce {
            parts: vec![
                Ok(b"ab".to_vec()),
                Err(io::Error::other("boom")),
                Ok(b"cd\nnext\n".to_vec()),
            ],
            current: Vec::new(),
        };
        let mut it = BoundedLines::with_cap(reader, 16);
        assert!(it.next().unwrap().is_err());
        assert_eq!(it.next().unwrap().unwrap(), text("abcd"));
        assert_eq!(it.next().unwrap().unwrap(), text("next"));
        assert!(it.next().is_none());
    }

    #[test]
    fn a_crlf_line_counts_its_carriage_return_toward_the_cap() {
        let got = lines(b"abcd\r\nabc\r\n", 4);
        assert_eq!(
            got.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            vec![Line::Oversize, text("abc")]
        );
    }
}
