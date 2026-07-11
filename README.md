# osquery-sys / osquery

Embeds [osquery](https://github.com/osquery/osquery) directly into a Rust
process as a linked library -- no `osqueryd` subprocess, no Thrift
extensions Unix socket on disk. Exposes starting/stopping the embedded
runtime and running SQL queries against osquery's virtual tables
(`processes`, `users`, etc.) in-process.

**Status: Stage 1 complete and verified on Linux/aarch64** (built and
tested end-to-end in the Docker image this repo ships; `SELECT 1` runs
through the real embedded osquery engine with zero on-disk sockets
created -- see `osquery/tests/smoke.rs`). This was a substantial
systems-integration effort, not a quick FFI wrapper -- see "How this
works" below and the staged-delivery notes there.

**CI** (`.github/workflows/ci.yml`) runs the same build/test on Linux,
macOS, and Windows. Linux mirrors the verified Docker recipe directly on
the runner. macOS and Windows are **unverified as of this writing** --
Windows in particular is new: osquery's own build only documents/tests the
multi-config "Visual Studio" CMake generator, which doesn't produce the
`link.txt`/`flags.make` files this crate's `build.rs` parses to discover
the link line, so it forces the (untested-by-osquery-upstream) "NMake
Makefiles" generator instead. Expect both to need iteration against real
CI runs before they go green.

## Crates

- `osquery-sys` -- low-level, unsafe FFI bindings, generated over a small
  hand-written C++ shim (`osquery-sys/shim/`). No lifecycle safety
  guarantees of its own.
- `osquery` -- safe wrapper: `OsqueryInstance::start()` / `.query(sql)` /
  `.shutdown()`, `Drop`, typed errors. Depend on this crate, not
  `osquery-sys`, unless you have a specific reason not to.

## Build requirements

osquery is vendored as a pinned git submodule (`vendor/osquery`, currently
pinned to release `5.23.1`) and built from source the first time
`osquery-sys` is compiled. That build:

- requires CMake >= 3.21.4, Python 3, and (per osquery's own build docs)
  a supported compiler toolchain;
- fetches and compiles dozens of third-party dependencies (boost, thrift,
  rocksdb, sqlite, openssl, zstd, glog, gflags, ...) plus osquery's own
  large C++ codebase, and can take a long time on first build;
- is **only validated in this repo via Linux** (see `docker/build.Dockerfile`
  and below) -- osquery's own docs state its macOS build is broken on Xcode
  SDK >= 16.3, and this repo was bootstrapped on a host with only newer
  Xcode versions available, so the macOS path in `osquery-sys/build.rs` is
  written but unverified.

### Recommended: build/test via Docker

```sh
docker build -f docker/build.Dockerfile -t osquery-sys-build .
docker run --rm -v "$(pwd)":/work -w /work osquery-sys-build \
  cargo build
docker run --rm -v "$(pwd)":/work -w /work osquery-sys-build \
  cargo test -p osquery --features integration-tests
```

The native osquery build is persisted at `build/osquery` (not `OUT_DIR`) so
it survives across `cargo build` invocations instead of being redone from
scratch every time; override the location with `OSQUERY_SYS_BUILD_DIR`.

On Linux, `osquery-sys/build.rs` requires the
[osquery-toolchain](https://github.com/osquery/osquery-toolchain) (a
prebuilt LLVM/libc++ toolchain osquery's own docs specify) to be installed;
by default it looks at `/usr/local/osquery-toolchain`
(`docker/build.Dockerfile` installs it there), overridable via
`OSQUERY_TOOLCHAIN_SYSROOT`. `build.rs` also passes, on every platform:

- `-DOSQUERY_BUILD_EXPERIMENTS=OFF -DOSQUERY_BUILD_BPF=OFF`: both pull in an
  eBPF-based Linux-events component whose vendored LLVM collides with
  osquery's own top-level zlib import under the same CMake binary directory
  (a real upstream CMake fragility with this toolchain/LLVM combination);
  neither is needed for in-process SQL queries.
- `-DOSQUERY_BUILD_AWS=OFF`: aws-sdk-cpp (needed for the AWS Firehose/Kinesis
  logger plugins, not needed here) vendors aws-c-common, which in turn
  vendors CBMC formal-verification proof submodules with absurdly deep
  nested paths -- these overflow Windows' filesystem path-length limits
  regardless of when they're fetched, and broke Windows CI outright before
  this was added.

CI (see below) also does a **non-recursive** submodule fetch
(`git submodule update --init`, not `--recursive`): osquery's own CMake
configure step lazily fetches each nested third-party submodule on demand,
per-platform, so a blanket recursive fetch upfront needlessly pulls in
platform-irrelevant content too (this is also how local verification always
worked, without ever running a recursive fetch by hand).

**Known local patches / environment fixes** (all against `vendor/osquery`'s
checked-out working tree, or the `docker/build.Dockerfile` environment --
not against this crate's own code):

- `boost/mpl/aux_/integral_wrapper.hpp` carries an uncommitted
  `#pragma clang diagnostic ignored "-Wenum-constexpr-conversion"` guard.
  The osquery-toolchain's current release (1.3.0) bundles Clang 18, much
  newer than the Clang 9.0.1 osquery's own docs describe; Clang 18
  hard-errors on an out-of-range enum arithmetic trick the pinned Boost
  version relies on. If the submodule is ever reset, reapply this patch
  (see git history / diff on that file) before rebuilding.
- `docker/build.Dockerfile` (and CI) conditionally write a passthrough
  `xlocale.h` shim inside the toolchain's sysroot (`usr/include/xlocale.h`,
  *not* the container's own `/usr/local/include` -- `--sysroot` redirects
  default header search paths there), **only if the file doesn't already
  exist**: osquery vendors augeas, whose gnulib submodule ships a
  pregenerated header assuming `<xlocale.h>` exists, and real glibc removed
  it years ago -- but the `osquery-toolchain` 1.3.0 release ships a
  meaningfully *older* glibc header snapshot for x86_64 than for aarch64.
  aarch64's genuinely lacks `xlocale.h` (needs the shim); x86_64's already
  has a complete, real one (old enough to still need it directly) that a
  blind unconditional overwrite clobbers with a shim that's circular there.
  Check which case applies before assuming the fix generalizes to a new
  architecture.
- A nested git submodule (boost's `libs/regex`) can end up incompletely
  fetched if a transient network failure hits mid-clone and is never
  retried on a later reconfigure (the directory is left with just a `.git`
  file, no content). If a build fails with `boost/regex.hpp` file-not-found
  errors, `cd` into `vendor/osquery/libraries/cmake/source/boost/src` and
  run `git submodule update --init --recursive -- libs/regex` (or check
  other submodules for the same "empty except `.git`" symptom).
- `build.rs` defaults `NUM_JOBS`/its build parallelism to `min(cores, 4)`:
  osquery's own docs warn that a fully-parallel build can OOM with under
  ~8GB of memory, which is easy to hit even on many-core machines if
  available memory is constrained (e.g. a capped Docker Desktop VM).

## How this works

- **No on-disk socket**: the embedded runtime is started as
  `osquery::Initializer(argc, argv, ToolType::SHELL)` with
  `FLAGS_disable_extensions` forced `true` before `Initializer::start()` is
  called. Verified directly against osquery's source
  (`osquery/extensions/extensions.cpp`): both `startExtensionManager()` and
  `initShellSocket()` check this flag first and return/no-op *before* ever
  computing a socket path or binding one.
- **No separate `libosquery.a`**: osquery's CMake build produces ~30
  discrete static library targets that get linked into `osqueryd`, one of
  which (`osquery_main`) contains the translation unit that defines the
  process's real `main()`. `build.rs` builds real `osqueryd` from the
  vendored source, parses CMake's own generated link line for it, and
  reuses it verbatim for the final Rust binary -- minus that one archive,
  since linking it would collide with the Rust binary's own entry point.
  This also means the `-Wl,--whole-archive`/`-force_load` sequences osquery
  itself already applies (via its own `enableLinkWholeArchive()` CMake
  helper) to every table/plugin target that registers itself via C++
  static initializers come along for free, correctly ordered, without this
  crate needing to hand-maintain that list.
- **Query results cross the FFI boundary as JSON**: the shim calls
  osquery's own `serializeQueryDataJSON` and hands back a single
  allocated string, parsed with `serde_json` on the Rust side. osquery row
  data is fundamentally `map<string,string>` per row, so nothing richer is
  lost by this, and it keeps the entire FFI surface to four `extern "C"`
  functions (see `osquery-sys/shim/shim.h`).
- **Singleton lifecycle**: `osquery::Initializer` installs process-wide
  signal handlers and was not designed to be constructed/destroyed more
  than once, so `OsqueryInstance` enforces at most one instance ever, for
  the lifetime of the process (see `osquery/src/instance.rs`).
- **The final Rust binary links with the system's default linker driver,
  not the osquery-toolchain's clang++** -- forcing clang++ globally (via
  `.cargo/config.toml`) broke every unrelated build-script/proc-macro
  binary in the workspace, since the toolchain's sysroot lacks the host's
  own gcc runtime bits (e.g. `-lgcc_s`) those unrelated links still need.
  Instead, `build.rs`'s `adapt_tokens_for_default_linker` translates the
  handful of clang/toolchain-only pieces in osquery's own generated link
  line to ones the default linker understands (dropping `--sysroot=`,
  which would otherwise redirect `-lc`/`-lgcc_s` resolution into the
  toolchain's older, CentOS7-targeted glibc and produce real symbol-version
  mismatches; referencing `libc++`/`libc++abi`/compiler-rt's
  `libclang_rt.builtins.a` by absolute path, appended at the very end of
  the link line rather than left in their original early position, since
  GNU ld only pulls a static archive's members in if something already
  needs them at the point it's processed). A one-line `sysctl()` stub
  (`shim/compat_stubs.cpp`, its own tiny archive for the same
  end-of-link-line reason) papers over one specific table's use of a glibc
  function removed in 2.30+ that we don't exercise for SQL queries.
- **`cargo:rustc-link-arg` doesn't propagate to downstream crates**: it
  only applies to the *emitting* crate's own binary/test/example targets,
  so `osquery-sys`'s build script relays its discovered link arguments via
  the `links`-metadata mechanism (`cargo:link_args=...` ->
  `DEP_OSQUERY_EMBED_SHIM_LINK_ARGS` env var) to a small `osquery/build.rs`
  that re-emits them as its own `cargo:rustc-link-arg`. A real application
  built on top of the `osquery` crate (as opposed to just its test suite)
  will need the same relay in its own `build.rs`; that's a known ergonomic
  gap for a later stage.

### Staged delivery

1. **Stage 1 (done)**: prove the link -- `build.rs` builds real osquery,
   discovers its link line, and produces a working binary that runs a
   hardcoded query end-to-end with zero socket files created, exercised by
   `osquery/tests/smoke.rs` (passing on Linux/aarch64 as of this writing).
2. **Stage 2**: generalize the query API further (e.g. typed columns),
   verify on Linux/x86_64 and (once a supported Xcode/SDK is available)
   macOS, resolve the cross-crate link-arg relay ergonomics noted above.
3. **Stage 3**: expose more `Initializer`/config knobs as real usage
   demands.

## License

This crate is Apache-2.0. osquery itself is dual-licensed
`Apache-2.0 OR GPL-2.0-only`; this project links against it under the
Apache-2.0 option, which does not impose copyleft obligations on downstream
users of this crate.
