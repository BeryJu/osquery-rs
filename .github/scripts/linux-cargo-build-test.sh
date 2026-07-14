#!/usr/bin/env bash
# ci.yml's Linux build+test command, run via manylinux-entrypoint.sh inside
# the manylinux2014 container. Split out from ci.yml itself only so the
# `docker run` invocation there stays a single readable line.
set -eux
set -o pipefail

# Diagnostic: a prior Linux run went completely silent for 60+ minutes with
# no way to tell whether the runner itself froze or just the compiler
# process did. Comparing whether these heartbeat lines keep appearing
# (system alive, something else hung) against `free -h`'s own numbers
# (memory exhausted at the time it stopped) gives a real answer instead of
# another guess if it happens again.
( while true; do
    sleep 60
    echo "=== heartbeat $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    free -h
    echo "--- top memory consumers ---"
    ps -eo pid,ppid,%mem,%cpu,etime,cmd --sort=-%mem | head -15
  done ) &
HEARTBEAT_PID=$!
trap 'kill "$HEARTBEAT_PID" 2>/dev/null || true' EXIT


# `-vv` makes Cargo echo the full rustc invocation for every crate, which
# for this project (dozens of -L/-l flags per compile) produces single
# physical log lines tens of KB long -- past whatever length GitHub
# Actions' own log storage silently truncates at, which made a real
# aarch64 link failure impossible to fully diagnose from the captured
# log (the tail of the actual command, where the interesting -l flags
# live, was simply missing with no indication it had been cut). Fold
# long lines so nothing exceeds a few KB; `set -o pipefail` above keeps
# cargo's own real exit code (not `fold`'s) governing `set -e`.
#
# Confirmed via a folded (non-truncated) log on a real aarch64 run:
# osquery-sys's own build-script-emitted native link flags (-l
# static=c++, -l static=osquery_core, etc.) are completely absent from
# the *smoke*/osquery `--test` binaries' own rustc invocations here --
# not a logging artifact, the command genuinely ends right after the
# last -L flag. osquery-sys's own build script runs exactly once (single
# metadata hash, single OUT_DIR), and its emitted directives are correct
# -- the divergence is purely in whether Cargo attaches them to a given
# downstream Unit. Ruled out, each via a real CI round with the
# identical symptom persisting: a two-cargo-invocation caching
# interaction, disabling incremental compilation, and an older Rust
# toolchain (1.90.0 vs the repo's pinned 1.97.0 -- both show it). This
# only happens on this aarch64/AlmaLinux9 combination; every other
# platform works unmodified with this exact same script/build.rs.
#
# CARGO_LOG=cargo::core::compiler=trace (added for the previous round)
# ruled out the leading theory at the time: that osquery-sys appearing as
# two different Cargo Units (Host-kind, where its build script actually
# runs, vs Target-kind, referenced via the smoke/osquery dependency edge)
# meant native-lib flags never reached the Target-kind copy. A clean,
# fast local repro (a 2-crate links="" workspace, built for real on
# aarch64 hardware via Docker -- no CI round needed) disproved this: both
# a plain `cargo:rustc-link-lib` and the `+whole-archive` modifier this
# project actually uses propagate correctly through to a downstream
# --test binary's real link, even though (exactly as seen here) the
# intermediate compile's own rustc command line never shows the -l flag
# directly -- that's normal Cargo behavior (flags flow through rlib
# metadata into the final `cc` invocation the compiler spawns
# internally, not onto the outer rustc command line cargo -vv echoes).
#
# Cross-checking the actual failing link against osquery-sys's own full,
# correctly-ordered 151-entry -l list (reconstructed from CARGO_LOG's
# trace, carefully handling the quoted `-l 'static:+whole-archive=name'`
# form that a naive grep misses) shows the visible portion matches
# exactly, in the right order, and CMake's own build log confirms every
# relevant component archive (osquery_sql, osquery_core,
# thirdparty_sqlite -- providers of the specific missing symbols) links
# successfully with no errors anywhere in the CMake/make phase. So the
# native-lib propagation mechanism itself isn't the bug, and the
# libraries genuinely get built.
#
# RUSTFLAGS=--verbose (rustc's own flag, distinct from cargo's -vv) got
# rustc's error-message renderer to print the failing link command in
# full instead of self-truncating it ("<N object files omitted>"/"some
# arguments are omitted"). Result: the real command has exactly the 29
# `+whole-archive`-modified archives osquery-sys's build script emits,
# and *zero* of the ~120 plain (non-whole-archive) `-l static=NAME`
# entries -- not thirdparty_sqlite, not osquery_core, not even the final
# -lc++/-lc/-lpthread system libs. So propagation genuinely is dropping
# every plain entry on this build, contradicting the clean small-scale
# repro (2 crates, still exactly reproduces this project's real
# `links=`/`+whole-archive` mix, directive count of 151, and even
# per-library long/distinct -L search-path directories matching this
# project's real CMake build-tree layout) -- which links correctly every
# time, run inside the identical manylinux_2_34_aarch64 container with
# the identical pinned Rust 1.97.0 toolchain and gcc-toolset-14 linker.
#
# Ruled out since: real Cargo build parallelism (CARGO_BUILD_JOBS=1 on a
# real CI run made no difference -- identical failure, same missing
# plain libraries) and 80,000 lines of non-"cargo:"-prefixed stdout
# volume before the real directives in a local repro (simulating the
# real CMake build's own forwarded output -- also no difference).
#
# Root cause not identified, but +whole-archive propagation has a 100%
# success rate everywhere tested (repro and real CI alike) versus 100%
# failure for plain propagation on this one target -- build.rs's
# emit_link_items now forces every static lib to +whole-archive on
# aarch64-unknown-linux-gnu specifically as a documented workaround (see
# its own comment for the full reasoning and everything ruled out).
# RUSTFLAGS=--verbose stays on so a full, non-abbreviated link command
# is available immediately if this still doesn't fully resolve it.
if [ "$(uname -m)" = "aarch64" ]; then
  export RUSTFLAGS="--verbose"
fi

cargo test -p osquery --features integration-tests -vv -- --nocapture 2>&1 | fold -w 2000
