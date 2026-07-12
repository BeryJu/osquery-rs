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

**Distribution model: prebuilt by default, from-source as an explicit
fallback.** `cargo add osquery` doesn't build osquery from source on your
machine -- `osquery-sys/build.rs` downloads a prebuilt archive bundle from
this repo's GitHub Releases for your target triple, verifies it against a
checksum baked into the crate's own source, and links against that. The
from-source path (clone + full native CMake build, which can take hours)
still exists and is used automatically for any target without a published
prebuilt bundle, or forced for any target via
`OSQUERY_SYS_FORCE_SOURCE_BUILD=1`. See "Build requirements" below for the
full fallback behavior and what's still required even on the prebuilt
path.

**CI** (`.github/workflows/ci.yml`) exercises the from-source build/test on
Linux, macOS, and Windows on every push (`OSQUERY_SYS_FORCE_SOURCE_BUILD=1`
is set there specifically so it keeps testing that path even once real
prebuilt releases exist). A separate workflow
(`.github/workflows/release.yml`) builds, packages, and publishes prebuilt
bundles whenever a version tag is pushed -- see "Release process" below.
All of this is new and, as of this writing, **unverified against real CI
runs for large parts of it** -- Windows in particular has needed multiple
rounds of iteration (osquery's own build only documents/tests the
multi-config "Visual Studio" CMake generator, which doesn't produce the
`link.txt` this crate's `build.rs` parses on other generators, and even the
"NMake Makefiles" generator forced instead turned out to skip `link.txt`
entirely in favor of an inline response-file block embedded in
`build.make` -- see `find_link_line`/`extract_link_line_from_build_make`
in `osquery-sys/build.rs`), and the release workflow / manylinux2014
containerization have not yet been exercised by a real tag push at all.
Expect iteration.

## Crates

- `osquery-sys` -- low-level, unsafe FFI bindings, generated over a small
  hand-written C++ shim (`osquery-sys/shim/`). No lifecycle safety
  guarantees of its own.
- `osquery` -- safe wrapper: `OsqueryInstance::start()` / `.query(sql)` /
  `.shutdown()`, `Drop`, typed errors. Depend on this crate, not
  `osquery-sys`, unless you have a specific reason not to.

## Build requirements

This crate has no vendored submodule and no special repo layout
requirement -- `cargo add osquery` (or a plain path/git dependency) works
from any project.

### Default path: prebuilt download

For the three published target triples (`x86_64-unknown-linux-gnu`,
`aarch64-apple-darwin`, `x86_64-pc-windows-msvc`), `osquery-sys/build.rs`
downloads a prebuilt archive bundle from this repo's GitHub Releases
(`osquery-sys-<version>-<target>.tar.zst`, one per tagged release -- see
"Release process" below), verifies its SHA-256 against a hash baked into
the crate's own committed source (`prebuilt-checksums.v1`, via
`include_str!` -- the expected hash never comes from the network, so
compromising only the release asset can't forge a matching one), and links
against the archives inside it directly. This still requires, even on the
prebuilt path:

- **network access** at build time (one download, not a multi-hour clone +
  full native build);
- **a working C++ compiler** locally (via the `cc` crate) -- the shim
  (`osquery-sys/shim/`, a few hundred lines) always compiles fresh, locally,
  every time, rather than being bundled prebuilt itself, both because it's
  fast and to avoid an ABI mismatch against whatever compiler `cc`
  auto-detects on your machine;
- **`git`**, briefly -- the shim's own `#include <osquery/...>` headers
  still need a real source checkout to resolve against, so build.rs does a
  lightweight, shallow top-level clone of osquery's pinned tag even on the
  prebuilt path (seconds, not the hours a full CMake configure+build would
  take -- that's the actual cost this path exists to skip).

A checksum **mismatch** on a downloaded bundle is a hard build failure with
no fallback (it can mean tampering or corruption, not just release-infra
flakiness); a **missing** prebuilt (network/HTTP failure, or no bundle
published yet for your target) instead prints a loud `cargo:warning` and
falls back to building from source below. Set
`OSQUERY_SYS_FORCE_SOURCE_BUILD=1` to skip the prebuilt download attempt
entirely and always build from source.

### Fallback / opt-out: build from source

Used automatically for any target with no published prebuilt bundle, or
forced via `OSQUERY_SYS_FORCE_SOURCE_BUILD=1`. `osquery-sys/build.rs`
shallow-clones osquery's pinned release tag (`OSQUERY_TAG` in
`osquery-sys/build.rs`, currently `5.23.1`) itself the first time it runs,
then builds it from source. That build:

- requires `git` and network access at build time (to clone osquery's tag,
  and for osquery's own CMake configure step to lazily fetch whichever of
  its ~150 nested third-party submodules the current platform actually
  needs -- boost, thrift, rocksdb, sqlite, openssl, zstd, glog, gflags,
  ...). This is not expected to work in a network-sandboxed build
  environment (e.g. docs.rs); see "Known limitations" below.
- requires CMake >= 3.21.4, Python 3, and (per osquery's own build docs) a
  supported compiler toolchain;
- compiles dozens of third-party dependencies plus osquery's own large C++
  codebase, and can take a long time (potentially hours) on first build;
- is **only validated end-to-end in this repo via Linux** (see
  `docker/build.Dockerfile` and below) -- osquery's own docs state its
  macOS build is broken on Xcode SDK >= 16.3, and this repo was
  bootstrapped on a host with only newer Xcode versions available, so the
  macOS path in `osquery-sys/build.rs` is written but unverified locally
  (it *is* exercised by CI -- see `.github/workflows/ci.yml`, which always
  forces this path via `OSQUERY_SYS_FORCE_SOURCE_BUILD=1` specifically so
  it keeps testing it once real prebuilt releases exist).

Both the cloned source and the native build are cached under
`<cargo target dir>/osquery-sys/{src,build}-<OSQUERY_TAG>/` -- inside the
*consuming project's* own `target/` directory (derived from `OUT_DIR`, see
`cargo_target_dir()` in `osquery-sys/build.rs`), so it survives normal
incremental rebuilds and is cleaned up by `cargo clean` like any other
build artifact. Override either location with `OSQUERY_SYS_SRC_DIR`/
`OSQUERY_SYS_BUILD_DIR` if needed (e.g. to point at an existing local
checkout for offline/air-gapped builds).

### Recommended: build/test via Docker

```sh
docker build -f docker/build.Dockerfile -t osquery-sys-build .
docker run --rm -v "$(pwd)":/work -w /work osquery-sys-build \
  cargo build
docker run --rm -v "$(pwd)":/work -w /work osquery-sys-build \
  cargo test -p osquery --features integration-tests
```

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

**Known local patches / environment fixes:**

- `boost/mpl/aux_/integral_wrapper.hpp`, inside the cloned osquery source,
  gets a `#pragma clang diagnostic ignored "-Wenum-constexpr-conversion"`
  guard applied automatically and idempotently by
  `apply_local_patches`/`patch_boost_mpl_enum_constexpr_conversion` in
  `osquery-sys/build.rs` (no manual step needed -- it runs on every fresh
  clone). The osquery-toolchain's current release (1.3.0) bundles Clang 18,
  much newer than the Clang 9.0.1 osquery's own docs describe; Clang 18
  hard-errors on an out-of-range enum arithmetic trick the pinned Boost
  version relies on.
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
- A nested git submodule (boost's `libs/regex`, fetched lazily by osquery's
  own CMake configure step) can end up incompletely fetched if a transient
  network failure hits mid-clone and is never retried on a later
  reconfigure (the directory is left with just a `.git` file, no content).
  If a build fails with `boost/regex.hpp` file-not-found errors, `cd` into
  `<cache dir>/src-<tag>/libraries/cmake/source/boost/src` (see "Build
  requirements" above for the cache path) and run
  `git submodule update --init --recursive -- libs/regex` (or check other
  submodules for the same "empty except `.git`" symptom).
- `build.rs` defaults `NUM_JOBS`/its build parallelism to
  `min(cores, 4) + 1` unless overridden (e.g. CI sets it explicitly):
  osquery's own docs warn that a fully-parallel build can OOM with under
  ~8GB of memory, which is easy to hit even on many-core machines if
  available memory is constrained (e.g. a capped Docker Desktop VM).

### Known limitations

- **docs.rs**: builds crates in a network-sandboxed container, so even the
  prebuilt path's download (and the from-source path's `git clone`/CMake-
  triggered submodule fetches) would fail there, same as many heavy `-sys`
  crates. Not yet addressed (a `DOCS_RS` env var check to skip both and
  emit stub bindings would be the standard fix, if this becomes a problem).
- **Prebuilt bundles only cover 3 target triples** (see "Default path:
  prebuilt download" above) -- anything else falls back to a from-source
  build automatically, with an informational `cargo:warning`.

## Release process (maintainers)

1. Bump `workspace.package.version` **and** the version pinned in
   `workspace.dependencies.osquery-sys` (both in the root `Cargo.toml` --
   the latter exists because `cargo publish` needs a real version
   requirement on that path dependency, not just a path; see the comment
   there) to the same new value. Commit.
2. Tag that commit `v<version>` (e.g. `v0.2.0`) and push the tag.
3. `.github/workflows/release.yml` takes over automatically: builds
   osquery from source on all 3 platforms, packages each into a prebuilt
   bundle, uploads them as a **draft** GitHub Release, commits the
   computed checksums to `osquery-sys/prebuilt-checksums.v1` on `main`,
   re-downloads and re-verifies every uploaded asset against those same
   checksums, publishes the release, and finally runs `cargo publish` for
   both crates -- requires a `CARGO_REGISTRY_TOKEN` repo secret (a
   crates.io API token with publish rights for both crates) to be
   configured once, manually, ahead of time.
4. If anything in step 3 fails partway, fix the issue and re-push the same
   tag (`git tag -f v<version> && git push -f origin v<version>`) to retry
   -- the workflow re-derives everything from the current source tree each
   time and overwrites its own prior draft/checksum entries for that exact
   version.

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
  cloned source, parses CMake's own generated link line for it, and
  classifies every surviving token into a `LinkItem` for the final Rust
  binary -- minus that one archive, since linking it would collide with the
  Rust binary's own entry point. This also means the
  `-Wl,--whole-archive`/`-force_load`/`/WHOLEARCHIVE:` sequences osquery
  itself already applies (via its own `enableLinkWholeArchive()` CMake
  helper) to every table/plugin target that registers itself via C++
  static initializers come along for free, correctly ordered (translated to
  Rust's own cross-platform `+whole-archive` link-lib modifier), without
  this crate needing to hand-maintain that list.
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
  Instead, `build.rs`'s `append_linux_default_linker_items` (Linux only)
  swaps in what the default linker actually needs in place of what
  `collect_link_items` already dropped (`-stdlib=libc++`, `-lc++abi`,
  `--sysroot=...`, `--no-undefined`): dropping `--sysroot=`, which would
  otherwise redirect `-lc`/`-lgcc_s` resolution into the toolchain's older,
  CentOS7-targeted glibc and produce real symbol-version mismatches;
  referencing `libc++`/`libc++abi`/compiler-rt's `libclang_rt.builtins.a`
  by absolute path, appended at the very end of the link item list rather
  than left in their original early position, since GNU ld only pulls a
  static archive's members in if something already needs them at the
  point it's processed. A one-line `sysctl()` stub (`shim/compat_stubs.cpp`,
  its own tiny archive for the same end-of-list reason) papers over one
  specific table's use of a glibc function removed in 2.30+ that we don't
  exercise for SQL queries.
- **Link info is emitted as native, transitively-propagating Cargo
  directives, not raw passthrough flags**: `cargo:rustc-link-lib`/
  `cargo:rustc-link-search` (unlike `cargo:rustc-link-arg`, which only
  applies to the *emitting* crate's own binary/test/example targets) are
  documented to propagate through the *entire* dependency graph to any
  depth. `build.rs` classifies every surviving link.txt token into a
  `LinkItem` (a real static archive with a resolvable directory, a bare
  system/dynamic library name, or a macOS framework) and emits each one
  directly -- including whole-archive semantics, via Rust's own
  cross-platform `+whole-archive` link-lib modifier instead of manually
  handled `-Wl,--whole-archive`/`-force_load`/`/WHOLEARCHIVE:` sequences.
  A real end-user application several crates downstream of `osquery-sys`
  links correctly with zero extra `build.rs` code of its own. Order is
  preserved for the (majority) plain, non-whole-archive static libraries
  that need it: Cargo places one crate's own `rustc-link-lib`/`-search`
  directives on the linker command line in the order the build script
  printed them, and every item here comes from this one crate's build
  script. A small residual set of flags with no lib/search equivalent that
  don't affect functional correctness (compile-flag echoes, cosmetic
  hardening flags) are dropped; anything else unrecognized is dropped too
  but with a `cargo:warning`, in case a future osquery version introduces
  something new.
- **Prebuilt bundles are a frozen snapshot of exactly one from-source
  build's outputs, not a separate code path**: `OSQUERY_SYS_PACKAGE_DIR`
  (set only by `release.yml`) copies each `LinkItem::StaticLib`'s real
  archive into a flat `lib/` directory and writes `manifest.v1` -- a
  hand-rolled, tab-separated format (deliberately not JSON/serde, to avoid
  a proc-macro compile-time cost landing on every consumer's first build
  for a format with no external interop requirement) listing every item in
  the exact order `emit_link_items` would emit them, plus a header
  recording the exact compiler/sysroot/defines/includes that build used.
  Downloading and parsing that manifest (`try_prebuilt`/`parse_manifest`)
  replays those same `cargo:rustc-link-lib`/`-search` directives and
  recompiles the shim locally against the recorded flags -- the prebuilt
  path is not a different mechanism from the from-source one, just a
  cached, pre-computed answer to "what did `collect_link_items` figure
  out" for a specific release.

### Staged delivery

1. **Stage 1 (done)**: prove the link -- `build.rs` builds real osquery,
   discovers its link line, and produces a working binary that runs a
   hardcoded query end-to-end with zero socket files created, exercised by
   `osquery/tests/smoke.rs` (passing on Linux/aarch64 as of this writing).
2. **Stage 2 (in progress)**: prebuilt-artifact distribution (this
   document's "Default path: prebuilt download" and "Release process"
   sections) -- implemented, but unverified against a real tag push/release
   as of this writing. Also: generalize the query API further (e.g. typed
   columns), get a fully green CI run on all 3 platforms.
3. **Stage 3**: expose more `Initializer`/config knobs as real usage
   demands.

## License

This crate is Apache-2.0. osquery itself is dual-licensed
`Apache-2.0 OR GPL-2.0-only`; this project links against it under the
Apache-2.0 option, which does not impose copyleft obligations on downstream
users of this crate.
