//! Stage 1 acceptance test: requires the full native osquery build to have
//! succeeded (see osquery-sys/build.rs), so it's gated behind a feature
//! rather than run by a plain `cargo test`.
#![cfg(feature = "integration-tests")]

use std::path::Path;

use osquery::OsqueryInstance;

// A single test, not two: OsqueryInstance is a process-wide singleton (see
// osquery/src/instance.rs), and `cargo test` runs every #[test] fn in one
// process (on separate threads) by default -- two independent tests each
// calling `OsqueryInstance::start()` would race for that one slot instead
// of exercising it deterministically.
#[test]
fn select_1_end_to_end_with_no_socket_then_second_start_is_refused() {
    // osquery's shell-mode socket path defaults to `<home>/shell.em[.<rand>]`
    // (see osquery::osqueryHomeDirectory()/initShellSocket() upstream).
    // Snapshot any pre-existing *.em files so we only flag ones this test
    // run created.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let osquery_home = Path::new(&home).join(".osquery");
    let before = list_em_files(&osquery_home);

    let instance = OsqueryInstance::start().expect("failed to start embedded osquery");

    let result = instance
        .query("SELECT 1 AS one")
        .expect("SELECT 1 should succeed");

    assert_eq!(result.rows.len(), 1, "expected exactly one row: {result:?}");
    assert_eq!(result.rows[0].get("one").map(String::as_str), Some("1"));

    let after = list_em_files(&osquery_home);
    let new_sockets: Vec<_> = after.difference(&before).collect();
    assert!(
        new_sockets.is_empty(),
        "expected zero new extension socket files, found: {new_sockets:?}"
    );

    let second = OsqueryInstance::start();
    assert!(second.is_err(), "a second instance should be refused");
}

fn list_em_files(dir: &Path) -> std::collections::HashSet<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Default::default();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.contains(".em"))
        .collect()
}
