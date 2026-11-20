#!/usr/bin/env bash
# ci.yml's Linux build+test command, run via manylinux-entrypoint.sh inside
# the manylinux2014 container. Split out from ci.yml itself only so the
# `docker run` invocation there stays a single readable line.
set -eux
set -o pipefail

# Diagnostic: distinguishes a hung runner from a merely slow compiler by
# comparing heartbeat continuity against `free -h`'s memory numbers.
( while true; do
    sleep 60
    echo "=== heartbeat $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    free -h
    echo "--- top memory consumers ---"
    ps -eo pid,ppid,%mem,%cpu,etime,cmd --sort=-%mem | head -15
  done ) &
HEARTBEAT_PID=$!
trap 'kill "$HEARTBEAT_PID" 2>/dev/null || true' EXIT

# `-vv` echoes every rustc invocation, including all -L/-l flags -- tens of
# KB per line for this project, past what GitHub Actions' log storage keeps
# intact. `fold` keeps lines short; `set -o pipefail` above keeps cargo's
# own exit code (not fold's) governing `set -e`.
status=0
cargo test -p osquery -vv -- --nocapture 2>&1 | fold -w 2000 || status=$?

# A native crash kills the whole (parallel) test binary with no hint of which
# test or where; rerun each binary single-threaded under gdb for a backtrace.
if [ "$status" -ne 0 ]; then
  command -v gdb >/dev/null || yum install -y gdb
  for bin in $(cargo test -p osquery --no-run --message-format=json 2>/dev/null \
      | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p'); do
    gdb -q -batch -ex run -ex bt -ex 'x/4i $pc' \
      --args "$bin" --test-threads=1 --nocapture || true
  done
  exit "$status"
fi
