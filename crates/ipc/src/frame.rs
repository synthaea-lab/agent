//! JSON-lines framing over an async byte stream.
//!
//! Every message is one line: `<UTF-8 JSON>\n`. No length prefix, no
//! escaping beyond JSON's own — a `\n` inside a JSON string literal is
//! already `\\n`, so the delimiter is unambiguous by construction.
//!
//! Why JSON-lines and not length-prefixed framing:
//!
//! - **Debuggable.** `nc \\.\pipe\synthaea-agent | jq .` works. Any log
//!   line the agent emits from the wire is human-readable in a
//!   dashboard.
//! - **Aligns with the rest of the workspace.** `alerts.ndjson`,
//!   `events.jsonl`, model records, baseline captures — every long-lived
//!   textual artefact this project produces is already JSON-lines.
//! - **No manual byte-order-mark or endianness discipline.** Text on the
//!   wire is UTF-8, period.
//!
//! Limits: [`MAX_MESSAGE_BYTES`] caps a single message at 1 MiB.
//! Anything above that is a bug or an attack — the server closes the
//! connection when its line reader hits the cap.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Hard cap on one line's length in bytes, INCLUDING the trailing
/// newline. Chosen large enough for a `RecentDetectionsResponse` with a
/// generous `limit`, small enough that a runaway client cannot pin
/// unbounded memory. 1 MiB.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Read one JSON-lines message from `reader` and parse it as `T`.
///
/// Reads until the next `\n` (exclusive) or [`MAX_MESSAGE_BYTES`],
/// whichever comes first. Returns `Ok(None)` on a clean EOF at message
/// boundary (the peer closed the connection); returns
/// `Err(FrameError::TooLarge)` if the message exceeds the cap.
///
/// # Errors
///
/// - [`FrameError::Io`] — the underlying reader failed mid-line.
/// - [`FrameError::TooLarge`] — the line exceeds [`MAX_MESSAGE_BYTES`].
/// - [`FrameError::Parse`] — the line does not parse as JSON of type
///   `T`.
pub async fn read_message<T, R>(reader: &mut BufReader<R>) -> Result<Option<T>, FrameError>
where
    T: DeserializeOwned,
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = String::new();
    let n = read_line_bounded(reader, &mut buf).await?;
    if n == 0 {
        // Clean EOF at message boundary — peer closed the connection.
        return Ok(None);
    }
    // Strip trailing `\n` (and optional `\r` for the paranoid CRLF case,
    // though our own writer never emits it).
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    let parsed: T = serde_json::from_str(&buf).map_err(FrameError::Parse)?;
    Ok(Some(parsed))
}

/// Reads up to [`MAX_MESSAGE_BYTES`] into `out` from `reader`, stopping
/// at the first `\n` (kept in `out`). Returns the number of bytes read;
/// `0` means EOF at message boundary. `FrameError::TooLarge` if the cap
/// is hit before a `\n` appears.
///
/// Not exposed publicly — [`read_message`] is the only caller.
async fn read_line_bounded<R>(
    reader: &mut BufReader<R>,
    out: &mut String,
) -> Result<usize, FrameError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    // tokio's `read_line` doesn't take a byte cap, so we roll one here.
    // We read one buffered chunk at a time and stop as soon as we see a
    // `\n` OR pass the cap.
    let mut total = 0usize;
    loop {
        let (done, consumed) = {
            let available = reader.fill_buf().await.map_err(|source| FrameError::Io { source })?;
            if available.is_empty() {
                return Ok(total); // EOF; `total > 0` means partial line
            }
            // Look for `\n` in what's available.
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                let take = pos + 1; // include the newline
                if total + take > MAX_MESSAGE_BYTES {
                    return Err(FrameError::TooLarge);
                }
                let slice = &available[..take];
                out.push_str(std::str::from_utf8(slice).map_err(|_| FrameError::NotUtf8)?);
                (true, take)
            } else {
                // No newline yet — consume the whole buffer, subject to
                // the cap.
                let take = available.len();
                if total + take > MAX_MESSAGE_BYTES {
                    return Err(FrameError::TooLarge);
                }
                out.push_str(std::str::from_utf8(available).map_err(|_| FrameError::NotUtf8)?);
                (false, take)
            }
        };
        reader.consume(consumed);
        total += consumed;
        if done {
            return Ok(total);
        }
    }
}

/// Serialize `message` as JSON, append `\n`, write it all to `writer`
/// and flush. One call = one full message on the wire, no partial-write
/// interleaving with another writer (callers must serialize their
/// writes at a higher level — the framing itself does no locking).
///
/// # Errors
///
/// - [`FrameError::Io`] — the writer failed mid-write.
/// - [`FrameError::Serialize`] — `message` failed to serialize (a
///   `serde_json` bug in practice — for the concrete types in
///   [`crate::protocol`], unreachable).
pub async fn write_message<T, W>(writer: &mut W, message: &T) -> Result<(), FrameError>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let mut buf = serde_json::to_vec(message).map_err(FrameError::Serialize)?;
    if buf.len() + 1 > MAX_MESSAGE_BYTES {
        return Err(FrameError::TooLarge);
    }
    buf.push(b'\n');
    writer
        .write_all(&buf)
        .await
        .map_err(|source| FrameError::Io { source })?;
    writer
        .flush()
        .await
        .map_err(|source| FrameError::Io { source })?;
    Ok(())
}

/// Framing-layer failures.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// I/O failed reading or writing the frame.
    #[error("frame I/O failed: {source}")]
    Io {
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A single line exceeded [`MAX_MESSAGE_BYTES`].
    #[error(
        "framed message exceeds the {MAX_MESSAGE_BYTES}-byte per-line cap"
    )]
    TooLarge,
    /// A line contained non-UTF-8 bytes; the wire is strictly UTF-8 JSON.
    #[error("framed message is not valid UTF-8")]
    NotUtf8,
    /// The line's UTF-8 could not be parsed as JSON of the expected
    /// type.
    #[error("failed to parse framed JSON: {0}")]
    Parse(#[source] serde_json::Error),
    /// A message could not be serialized to JSON. Effectively unreachable
    /// for the concrete types in [`crate::protocol`]; kept in the enum
    /// so we don't `.unwrap()` a serde error at the wire boundary.
    #[error("failed to serialize framed JSON: {0}")]
    Serialize(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    // These tests hand `read_message` a `&[u8]` reader — tokio implements
    // `AsyncRead` for byte slices, which is a simpler and non-blocking
    // way to drive framed reads than a live duplex socket. Writing tests
    // build the framed bytes with `write_message` into a `Vec<u8>` and
    // then feed the bytes back through a `&[u8]` reader.

    #[tokio::test]
    async fn round_trip_through_bytes() {
        let msg = crate::protocol::Request::RecentDetections { limit: 3 };
        let mut buf: Vec<u8> = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();
        assert!(buf.ends_with(b"\n"), "framed message must end with newline");

        let mut reader = BufReader::new(&buf[..]);
        let got: Option<crate::protocol::Request> = read_message(&mut reader).await.unwrap();
        assert_eq!(got, Some(msg));

        // After the message, the underlying slice is exhausted — the next
        // read hits EOF at message boundary and returns `Ok(None)`.
        let eof: Option<crate::protocol::Request> = read_message(&mut reader).await.unwrap();
        assert_eq!(eof, None);
    }

    #[tokio::test]
    async fn oversized_line_is_rejected() {
        // A raw byte payload that exceeds the cap. `read_line_bounded`
        // walks its bounded buffer and returns TooLarge before consuming
        // the whole thing — no need for a duplex writer that could block.
        let junk = vec![b'x'; MAX_MESSAGE_BYTES + 100];
        let mut reader = BufReader::new(&junk[..]);
        let err = read_message::<crate::protocol::Request, _>(&mut reader)
            .await
            .expect_err("should reject oversized line");
        assert!(matches!(err, FrameError::TooLarge));
    }

    #[tokio::test]
    async fn parse_error_reports_json_position() {
        let bytes = b"{not json}\n";
        let mut reader = BufReader::new(&bytes[..]);
        let err = read_message::<crate::protocol::Request, _>(&mut reader)
            .await
            .expect_err("should fail to parse");
        assert!(matches!(err, FrameError::Parse(_)));
    }
}
