use std::path::Path;
use std::sync::OnceLock;

use osquery::{OsqueryError, OsqueryInstance};
use serde::Deserialize;

static INSTANCE: OnceLock<Result<OsqueryInstance, OsqueryError>> = OnceLock::new();

fn instance() -> &'static OsqueryInstance {
    match INSTANCE.get_or_init(OsqueryInstance::start) {
        Ok(instance) => instance,
        Err(e) => panic!("failed to get osquery instance: {}", e),
    }
}

#[test]
fn select_users_no_err() {
    #[derive(Deserialize, Debug)]
    struct UserRow {
        username: String,
        uid: String,
    }

    let instance = instance();
    let result = instance.query::<UserRow>("SELECT * FROM users").unwrap();
    assert!(result.rows.len() > 0);
    assert!(!result.rows[0].uid.is_empty());
    assert!(!result.rows[0].username.is_empty());
}

#[test]
fn singleton() {
    let _instance = instance();

    let second = OsqueryInstance::start();
    assert!(second.is_err(), "a second instance should be refused");
}

#[test]
fn select_1_end_to_end_with_no_socket() {
    // osquery's shell-mode socket path defaults to `<home>/shell.em[.<rand>]`
    // (see osquery::osqueryHomeDirectory()/initShellSocket() upstream).
    // Snapshot any pre-existing *.em files so we only flag ones this test
    // run created.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let osquery_home = Path::new(&home).join(".osquery");
    let before = list_em_files(&osquery_home);

    let instance = instance();

    let result = instance
        .query_row("SELECT 1 AS one")
        .expect("SELECT 1 should succeed");

    assert_eq!(result.rows.len(), 1, "expected exactly one row: {result:?}");
    assert_eq!(result.rows[0].get("one").map(String::as_str), Some("1"));

    let after = list_em_files(&osquery_home);
    let new_sockets: Vec<_> = after.difference(&before).collect();
    assert!(
        new_sockets.is_empty(),
        "expected zero new extension socket files, found: {new_sockets:?}"
    );
}

// Regression: 0.2.5's x86_64 Linux link (libc++ linked selectively, without
// cc's `-lc++`) crashed on these tables while users/SELECT 1 still worked.
#[test]
fn system_info_has_rows() {
    let result = instance()
        .query_row("SELECT * FROM system_info")
        .expect("system_info should succeed");
    assert!(!result.rows.is_empty(), "system_info returned no rows");
}

#[cfg(unix)]
#[test]
fn mounts_has_rows() {
    let result = instance()
        .query_row("SELECT * FROM mounts")
        .expect("mounts should succeed");
    assert!(!result.rows.is_empty(), "mounts returned no rows");
}

// Rows depend on the host/container (and root for disk_encryption), so only
// assert the queries complete.
#[cfg(unix)]
#[test]
fn block_devices_and_disk_encryption_no_crash() {
    for table in ["block_devices", "disk_encryption"] {
        instance()
            .query_row(&format!("SELECT * FROM {table}"))
            .unwrap_or_else(|e| panic!("{table} should succeed: {e}"));
    }
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
