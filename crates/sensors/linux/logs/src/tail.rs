//! Follows one log file: new complete lines only, a persistable position, and
//! rotation handled by file identity (ADR-0022 §2).
//!
//! - **First start** (no saved position) begins at the end of the file, like the
//!   journal tail begins at "now": replaying a log's history would flood the case
//!   engine with old requests.
//! - **Restart** resumes at the saved offset when the file is the same one (same
//!   device and inode) and has not shrunk; otherwise it starts the current file at 0.
//! - **Rename and recreate** (`logrotate` default): the old file is drained through the
//!   handle still held on it, then the new one is read from 0.
//! - **Copy-truncate**: same file, shorter than the offset: restart from 0.
//! - **Overlong lines** keep their first `MAX_LINE_BYTES + 1` bytes and drop the rest
//!   as it arrives, so the memory held per source is bounded whatever the file holds.
//!   The `+ 1` is what lets the parsers' own cap flag the record `truncated`.
//!
//! The position is only the *start of the first unconsumed line*: a half-written line
//! is read again after a restart instead of being lost. File identity needs Unix
//! (`dev` and `ino`); elsewhere only copy-truncate and missing files are detected.
//!
//! Persisting [`Position`] (next to the alerts output, like the journal cursor) is the
//! agent's job, not this crate's.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::MAX_LINE_BYTES;

/// Identity of an open file: survives a rename, changes when the path is recreated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
fn file_id(meta: &std::fs::Metadata) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    Some(FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(not(unix))]
fn file_id(_meta: &std::fs::Metadata) -> Option<FileId> {
    None
}

/// Where a source was read up to: the file and the offset of the next line to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub id: Option<FileId>,
    pub offset: u64,
}

impl Position {
    /// One line of text, for the agent to store: `v1 <dev> <ino> <offset>`, with `-`
    /// for an unknown identity.
    #[must_use]
    pub fn encode(&self) -> String {
        match self.id {
            Some(FileId { dev, ino }) => format!("v1 {dev} {ino} {}", self.offset),
            None => format!("v1 - - {}", self.offset),
        }
    }

    /// Inverse of [`Self::encode`]. `None` for anything else, which the caller treats
    /// as "no saved position".
    #[must_use]
    pub fn decode(text: &str) -> Option<Self> {
        let mut parts = text.split_whitespace();
        if parts.next()? != "v1" {
            return None;
        }
        let (dev, ino) = (parts.next()?, parts.next()?);
        let offset = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        let id = match (dev, ino) {
            ("-", "-") => None,
            (d, i) => Some(FileId {
                dev: d.parse().ok()?,
                ino: i.parse().ok()?,
            }),
        };
        Some(Self { id, offset })
    }
}

/// What one [`Tailer::poll`] saw besides lines, for the source's health counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PollOutcome {
    /// Non-empty lines handed to the callback.
    pub lines: u64,
    /// Times the path started pointing at a new file.
    pub rotations: u32,
    /// Times the file shrank under the offset (copy-truncate).
    pub truncations: u32,
}

/// Buffers and offsets, split from the file handle so both can be borrowed at once.
#[derive(Default)]
struct State {
    /// Bytes read from the current file.
    read_pos: u64,
    /// Offset after the last complete line: what [`Position`] reports.
    consumed: u64,
    /// The line being assembled, at most `MAX_LINE_BYTES + 1` bytes.
    line: Vec<u8>,
    /// The current line already exceeded the cap; the rest is dropped to its newline.
    overlong: bool,
}

impl State {
    fn reset(&mut self, offset: u64) {
        self.read_pos = offset;
        self.consumed = offset;
        self.line.clear();
        self.overlong = false;
    }

    fn emit(&mut self, on_line: &mut impl FnMut(&str), out: &mut PollOutcome) {
        if !self.line.is_empty() {
            on_line(&String::from_utf8_lossy(&self.line));
            out.lines += 1;
        }
        self.line.clear();
        self.overlong = false;
    }

    fn feed(&mut self, bytes: &[u8], on_line: &mut impl FnMut(&str), out: &mut PollOutcome) {
        for chunk in bytes.split_inclusive(|b| *b == b'\n') {
            let (body, ended) = match chunk.split_last() {
                Some((b'\n', body)) => (body, true),
                _ => (chunk, false),
            };
            self.read_pos += chunk.len() as u64;
            if !self.overlong {
                let room = MAX_LINE_BYTES + 1 - self.line.len();
                if body.len() > room {
                    self.line.extend_from_slice(&body[..room]);
                    self.overlong = true;
                } else {
                    self.line.extend_from_slice(body);
                }
            }
            if ended {
                self.emit(on_line, out);
                self.consumed = self.read_pos;
            }
        }
    }
}

/// Follows one file. Poll it on a timer; it never blocks waiting for data.
pub struct Tailer {
    path: PathBuf,
    /// Position loaded at startup, used by the first successful open only.
    saved: Option<Position>,
    /// No saved position and the file already existed at startup: begin at its end.
    from_end: bool,
    /// After a rotation the new file is read from its start.
    from_start: bool,
    file: Option<File>,
    id: Option<FileId>,
    state: State,
}

impl Tailer {
    /// `saved` is the last [`Position`] the agent persisted for this source, if any.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, saved: Option<Position>) -> Self {
        let path = path.into();
        let from_end = saved.is_none() && path.exists();
        Self {
            path,
            saved,
            from_end,
            from_start: false,
            file: None,
            id: None,
            state: State::default(),
        }
    }

    /// The path being followed.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The position to persist now, or `None` before anything was read or saved.
    #[must_use]
    pub fn position(&self) -> Option<Position> {
        if self.file.is_some() {
            Some(Position {
                id: self.id,
                offset: self.state.consumed,
            })
        } else {
            self.saved
        }
    }

    fn open(&mut self) -> io::Result<bool> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        let id = file_id(&meta);
        let start = if self.from_start {
            0
        } else {
            match self.saved {
                Some(p) if p.id == id && p.offset <= meta.len() => p.offset,
                Some(_) => 0,
                None if self.from_end => meta.len(),
                None => 0,
            }
        };
        file.seek(SeekFrom::Start(start))?;
        self.saved = None;
        self.from_end = false;
        self.from_start = false;
        self.state.reset(start);
        self.id = id;
        self.file = Some(file);
        Ok(true)
    }

    /// Reads whatever complete lines were appended since the last call and hands each
    /// to `on_line`, without its terminator. A missing file is not an error: the log
    /// may not exist yet, or may be between a rename and a recreate.
    ///
    /// # Errors
    /// Any I/O error other than the file being absent. The tailer stays usable.
    pub fn poll(&mut self, mut on_line: impl FnMut(&str)) -> io::Result<PollOutcome> {
        let mut out = PollOutcome::default();
        loop {
            if self.file.is_none() && !self.open()? {
                return Ok(out);
            }
            self.drain(&mut on_line, &mut out)?;
            match std::fs::metadata(&self.path) {
                Ok(m) if self.id.is_some() && file_id(&m) != self.id => {
                    // The path now names another file. What the old one still had
                    // was drained above; a last unterminated line is kept, not lost.
                    self.state.emit(&mut on_line, &mut out);
                    self.file = None;
                    self.from_start = true;
                    out.rotations += 1;
                }
                Ok(_) => return Ok(out),
                // Renamed away and not recreated yet: keep the handle, retry later.
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
                Err(e) => return Err(e),
            }
        }
    }

    fn drain(&mut self, on_line: &mut impl FnMut(&str), out: &mut PollOutcome) -> io::Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        if file.metadata()?.len() < self.state.read_pos {
            file.seek(SeekFrom::Start(0))?;
            self.state.reset(0);
            out.truncations += 1;
        }
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            self.state.feed(&buf[..n], on_line, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    use super::*;

    fn lines(t: &mut Tailer) -> Vec<String> {
        let mut got = Vec::new();
        t.poll(|l| got.push(l.to_owned())).unwrap();
        got
    }

    fn append(path: &Path, text: &str) {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn first_start_skips_history_then_follows() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        append(&p, "old1\nold2\n");
        let mut t = Tailer::new(&p, None);
        assert!(lines(&mut t).is_empty());
        append(&p, "new1\nnew2\n");
        assert_eq!(lines(&mut t), ["new1", "new2"]);
        assert!(lines(&mut t).is_empty());
    }

    #[test]
    fn a_file_that_did_not_exist_at_startup_is_read_whole_once_it_appears() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("late.log");
        let mut t = Tailer::new(&p, None);
        assert!(lines(&mut t).is_empty(), "a missing file is not an error");
        assert_eq!(t.position(), None);
        append(&p, "a\nb\n");
        assert_eq!(lines(&mut t), ["a", "b"]);
    }

    #[test]
    fn a_half_written_line_waits_for_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        append(&p, "");
        let mut t = Tailer::new(&p, None);
        lines(&mut t);
        append(&p, "par");
        assert!(lines(&mut t).is_empty());
        append(&p, "tial\r\nnext\n");
        assert_eq!(lines(&mut t), ["partial\r", "next"]);
    }

    #[test]
    fn position_round_trips_and_resumes_without_replay_or_loss() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        append(&p, "");
        let mut t = Tailer::new(&p, None);
        lines(&mut t);
        append(&p, "one\ntwo\nthr");
        assert_eq!(lines(&mut t), ["one", "two"]);
        let saved = Position::decode(&t.position().unwrap().encode()).unwrap();
        assert_eq!(saved.offset, 8, "the unterminated 'thr' is not consumed");

        // The agent restarts while "thr" was half-written, and more arrives.
        drop(t);
        append(&p, "ee\nfour\n");
        let mut t = Tailer::new(&p, Some(saved));
        assert_eq!(lines(&mut t), ["three", "four"]);
    }

    #[test]
    fn copy_truncate_restarts_from_zero() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        append(&p, "");
        let mut t = Tailer::new(&p, None);
        lines(&mut t);
        append(&p, "aaaaaaaaaa\n");
        assert_eq!(lines(&mut t).len(), 1);
        fs::write(&p, "b\n").unwrap();
        let mut got = Vec::new();
        let out = t.poll(|l| got.push(l.to_owned())).unwrap();
        assert_eq!(got, ["b"]);
        assert_eq!(out.truncations, 1);
    }

    #[test]
    fn an_overlong_line_is_bounded_and_the_next_one_is_intact() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        append(&p, "");
        let mut t = Tailer::new(&p, None);
        lines(&mut t);
        append(&p, &format!("{}\nok\n", "x".repeat(MAX_LINE_BYTES * 5)));
        let got = lines(&mut t);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].len(), MAX_LINE_BYTES + 1, "kept just past the cap");
        assert_eq!(got[1], "ok");
        let (_, truncated) = crate::clamp(&got[0]);
        assert!(truncated, "the parsers' own cap flags it");
    }

    #[test]
    fn position_text_is_strict() {
        assert_eq!(Position::decode("v1 - - 12").unwrap().offset, 12);
        for bad in [
            "",
            "v2 - - 1",
            "v1 - - x",
            "v1 1 2",
            "v1 - - 1 extra",
            "v1 a b 3",
        ] {
            assert_eq!(Position::decode(bad), None, "{bad:?}");
        }
    }

    #[cfg(unix)]
    mod unix {
        use super::*;

        #[test]
        fn rename_and_recreate_drains_the_old_file_then_reads_the_new_one() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("a.log");
            append(&p, "");
            let mut t = Tailer::new(&p, None);
            lines(&mut t);
            append(&p, "before\n");
            assert_eq!(lines(&mut t), ["before"]);

            // Written to the old file, then logrotate renames it and the server
            // opens a new one: nothing between the last poll and the rename is lost.
            append(&p, "last-of-old\n");
            fs::rename(&p, dir.path().join("a.log.1")).unwrap();
            append(&p, "first-of-new\n");
            let mut got = Vec::new();
            let out = t.poll(|l| got.push(l.to_owned())).unwrap();
            assert_eq!(got, ["last-of-old", "first-of-new"]);
            assert_eq!(out.rotations, 1);
        }

        #[test]
        fn between_the_rename_and_the_recreate_nothing_is_lost_or_invented() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("a.log");
            append(&p, "");
            let mut t = Tailer::new(&p, None);
            lines(&mut t);
            fs::rename(&p, dir.path().join("a.log.1")).unwrap();
            assert!(lines(&mut t).is_empty());
            append(&p, "reborn\n");
            assert_eq!(lines(&mut t), ["reborn"]);
        }

        #[test]
        fn a_saved_position_on_another_file_starts_the_current_one_at_zero() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("a.log");
            append(&p, "x\n");
            let mut t = Tailer::new(&p, None);
            lines(&mut t);
            append(&p, "y\n");
            lines(&mut t);
            let saved = t.position().unwrap();
            drop(t);

            // Rotated while the agent was down.
            fs::rename(&p, dir.path().join("a.log.1")).unwrap();
            append(&p, "n1\nn2\n");
            let mut t = Tailer::new(&p, Some(saved));
            assert_eq!(lines(&mut t), ["n1", "n2"]);
        }
    }
}
