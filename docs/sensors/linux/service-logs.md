# Service logs

Some attacks are only visible in an application's own log: a web scan, an SQL injection attempt, a
webshell answering requests, a database password guess.
[`sensor-linux-logs`](../../../crates/sensors/linux/logs/src/lib.rs) parses the logs an operator
declares and turns the few lines that matter into events. It is pure: parsers, a tailer, budgets
and summaries, with no I/O beyond reading the file and no event delivery. The agent drives it
([`log_sources.rs`](../../../apps/agent/src/log_sources.rs)).

## Configuration

Sources are declared in the agent configuration, `[[logs.sources]]`, each with an absolute `path`
and a `kind` ([`LogSourceConfig`](../../../crates/config/src/schema.rs)). At most 16 sources
(`MAX_LOG_SOURCES`). There is no auto-detection and no free-form pattern: a custom `LogFormat` is
reported as a misparsing source rather than guessed at.

| `kind` | Format | Events |
| --- | --- | --- |
| `access_common` | Apache `common` (`%h %l %u %t "%r" %>s %b`) | `HttpRequest` on a signature match, `HttpSummary` per window |
| `access_combined` | Apache `combined`, nginx default `combined` | same |
| `mysql_error` | MySQL 8 / MariaDB error log | `Auth` (failed login), feeding the brute-force rule |

## Reading a file

[`Tailer`](../../../crates/sensors/linux/logs/src/tail.rs) follows one file. The agent polls every
source once a second on one thread.

- **First start** begins at the end of the file; replaying history would flood the case engine.
- **Restart** resumes at the saved [`Position`](../../../crates/sensors/linux/logs/src/tail.rs)
  (`v1 <dev> <ino> <offset>`, persisted next to the alerts file) if the file has the same device and
  inode and has not shrunk; otherwise the current file is read from 0.
- **Rename and recreate** (logrotate's default): the old file is drained through the handle still
  open on it, then the new one is read from 0.
- **Copy-truncate**: same file, shorter than the offset: restart from 0.
- **Position** is the start of the first unconsumed line, so a half-written line is read again
  after a restart instead of being lost.
- **Overlong lines** keep their first `MAX_LINE_BYTES + 1` bytes and drop the rest as it arrives,
  so memory per source is bounded whatever the file holds.

## Parsing

Every byte of a log line is chosen by whoever sent the request, so the parsers follow fixed rules:

- a quote- and escape-aware [tokenizer](../../../crates/sensors/linux/logs/src/tokenizer.rs), never
  `split(' ')`;
- lines over [`MAX_LINE_BYTES`](../../../crates/sensors/linux/logs/src/lib.rs) (8 KiB, above
  Apache's default 8190-byte request line) are cut on a character boundary and flagged `truncated`;
- a line that does not match its preset is an `Err` ([`ParseError`](../../../crates/sensors/linux/logs/src/lib.rs)),
  counted and sampled by the agent (cut and escaped), never skipped silently.

[`parse_mysql_error_line`](../../../crates/sensors/linux/logs/src/mysql.rs) accepts both the MySQL 8
(`[MY-010926]`, `[MY-010925]`) and MariaDB forms. MySQL 8 writes these lines only at
`log_error_verbosity = 3`; MariaDB at its default. The user name is attacker-chosen and unescaped,
so the identity is split on the last `'@'`.

## Signatures and events

[`match_request`](../../../crates/sensors/linux/logs/src/http.rs) runs on a normalized copy of the
request (percent-decoded twice, lower-cased, `/**/` read as a space), since the attacker chooses
the encoding. Signatures: path traversal, SQL injection markers, scanner user agents, and
webshell-like requests (known webshell names, command parameters, a new `.php` answering 200).
These are substring tests, not a WAF: an attacker who encodes three times or splits a marker evades
them. Their value is a case for the correlator when the same host then runs something it should not.

The event ([`to_http_request_event`](../../../crates/sensors/linux/logs/src/http.rs)) carries the
path without its query string, the query parameter names (never values, at most 32), and the one
value that matched, cut to [`EVIDENCE_MAX_CHARS`](../../../crates/sensors/linux/logs/src/http.rs)
(128). Credential redaction of that value is done once, at the agent's sink boundary
(`log_sources::deliver`), not here.

## Volume bounds

| Bound | Value | Effect |
| --- | --- | --- |
| [`PER_SIGNATURE_PER_WINDOW`](../../../crates/sensors/linux/logs/src/budget.rs) | 30 per signature per 60 s window | Further matches are counted, not emitted. Per signature, so a thousand SQLi probes cannot use up the allowance for a webshell hit |
| [`WINDOW_SECS`](../../../crates/sensors/linux/logs/src/summary.rs) | 60 | One `HttpSummary` per source per window: requests, 4xx, 5xx, distinct clients, top failing clients |
| `MAX_TRACKED_CLIENTS` | 4096 | Further clients count in `requests` but not in the ranking |
| `TOP_CLIENTS` | 5 | Ranking length |

No event is emitted for an ordinary request.

## Health

A source whose format changed is blind while looking healthy.
[`MisparseWatch`](../../../crates/sensors/linux/logs/src/health.rs) counts, per 60 s window, the
lines that claimed to be of the kind and how many failed; a window of at least
[`MIN_LINES`](../../../crates/sensors/linux/logs/src/health.rs) (10) in which at least half failed is
reported once per episode, and the agent raises a `LOG-SOURCE` alert. Lines a parser ignores on
purpose and lines cut at the length cap do not count.

There is no silence heartbeat for log sources: a quiet log is normal on a quiet site.

## Testing

Unit tests for every module, with log lines captured on real servers; the fuzz target
[`logs_parse`](../../../tests/fuzz/fuzz_targets/logs_parse.rs) runs both access formats and the MySQL
parser on arbitrary input.
