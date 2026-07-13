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
# last -L flag. This is a two-`cargo`-invocation setup (a separate
# `cargo build --workspace` first, then `cargo test -p osquery
# --features integration-tests` second, both operating on the same
# target/debug); "osquery-sys" shows as Fresh (not rebuilt) by the time
# `cargo test` runs, and its cached build-script output should still be
# replayed to any newly-compiled downstream unit (the --test binaries,
# which need integration-tests enabled and so are new compilations) --
# that replay is what appears to be failing here, only on this
# aarch64/AlmaLinux9 combination (every other platform runs this exact
# same two-invocation pattern successfully). Testing whether a single
# `cargo test` invocation (which builds everything it needs itself,
# rather than reusing state from a separate prior `cargo build`
# process) avoids whatever caching interaction is dropping the
# propagation here.
cargo test -p osquery --features integration-tests -vv -- --nocapture 2>&1 | fold -w 2000
