//! Content check for `rules/ioc/` (#934, ADR-0038): every `*.txt` there is one feed, and the
//! engine must take every line of it. A line it refuses is dropped silently on a device (the
//! loader counts it and goes on), so this is where a bad line in shipped content is caught. The
//! server's `tests/unit/ioc-content.test.ts` adds the public-suffix check the engine cannot make.
//! Vacuous while the directory is absent or empty.

use std::path::Path;

use intel::{DEFAULT_MEMORY_BUDGET_BYTES, FeedId, SetBuilder};

/// What is wrong with one feed file; empty when the engine loads all of it.
fn problems(name: &str, text: &str) -> Vec<String> {
    let mut builder = SetBuilder::new(DEFAULT_MEMORY_BUDGET_BYTES);
    let report = builder.add_lines(FeedId(1), text);
    let mut out = Vec::new();
    if report.rejected > 0 {
        out.push(format!(
            "{name}: {} lines the engine rejects",
            report.rejected
        ));
    }
    if report.over_budget > 0 {
        out.push(format!(
            "{name}: {} indicators over the memory budget",
            report.over_budget
        ));
    }
    if report.added == 0 {
        out.push(format!("{name}: no indicator"));
    }
    out
}

#[test]
fn the_check_flags_a_rejected_line_and_an_empty_file() {
    assert!(problems("ok.txt", "# c\nsha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nip:203.0.113.9\ndomain:evil.example\n").is_empty());
    assert_eq!(
        problems("bad.txt", "ip:203.0.113.9\nip:127.0.0.1\nnonsense\n").len(),
        1
    );
    assert_eq!(problems("empty.txt", "# nothing\n").len(), 1);
}

#[test]
fn every_shipped_ioc_feed_loads_whole() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/ioc");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut found = Vec::new();
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.extension().is_some_and(|e| e == "txt") {
            let text = std::fs::read_to_string(&path).expect("a UTF-8 feed file");
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            found.extend(problems(&name, &text));
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}
