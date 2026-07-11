//! Relays the raw osquery link arguments `osquery-sys`'s build script
//! discovered (via `DEP_OSQUERY_EMBED_SHIM_LINK_ARGS`, from its
//! `links = "osquery_embed_shim"` + `cargo:link_args=...` metadata) as this
//! crate's own `cargo:rustc-link-arg`.
//!
//! This step exists only because `cargo:rustc-link-arg` applies solely to
//! the emitting package's own binary/test/example targets, not to
//! downstream dependents (see osquery-sys/build.rs for the full
//! explanation) -- so the flags have to be re-declared at each crate
//! boundary that actually links a final binary. A future consumer building
//! an application on top of `osquery` (rather than just its test suite)
//! will need the same relay in their own build.rs, reading this same
//! env var; that's a known ergonomic gap to revisit in a later stage.

fn main() {
    if let Ok(joined) = std::env::var("DEP_OSQUERY_EMBED_SHIM_LINK_ARGS") {
        for arg in joined.split('\u{1f}').filter(|s| !s.is_empty()) {
            println!("cargo:rustc-link-arg={arg}");
        }
    }
}
