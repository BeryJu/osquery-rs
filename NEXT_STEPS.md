# Next steps for osquery-sys / osquery

Handoff notes as of 2026-07-11, for whoever (human or agent) picks this up next.
Full design detail for the big pending item lives in a plan file outside this
repo (see "Prebuilt-artifact distribution" below) — this doc summarizes it and
tracks the smaller, concrete task list.

## Where things stand right now

**Done and merged to `main`:**
- Core in-process osquery embedding works (`osquery-sys` unsafe FFI + `osquery`
  safe wrapper), verified on Linux/aarch64 locally early in this project.
- Reworked for crates.io reusability: `build.rs` git-clones osquery's pinned
  tag itself (no git submodule), caches source+build under
  `<cargo target dir>/osquery-sys/{src,build}-<tag>/`, and emits link info via
  `cargo:rustc-link-lib`/`-link-search` (propagate transitively — no more
  manual relay crate).
- Windows Boost-patch CRLF bug fixed for real (commit `caf8d5d`): normalizes
  `\r\n`→`\n` in `patch_boost_mpl_enum_constexpr_conversion` before the
  anchor-text match, instead of fighting git's checkout behavior via
  `core.autocrlf` env vars (that first attempt did NOT work — Boost's own
  repo(s) likely carry a path-specific `.gitattributes` override).
- `-vv` added to CI's `cargo build`/`cargo test` so build-script child-process
  (cmake/git) output actually streams to the Actions log live, instead of
  silent multi-hour gaps that look identical to a hang.

**NOT yet confirmed: a fully green 3-platform CI run.** The `-vv` + CRLF-fix
push (`caf8d5d`) showed real progress on all 3 platforms (Windows cleared the
Boost-patch step and was genuinely compiling OpenSSL; macOS passed; Linux was
28 min into its build with no errors) — but before that run finished, `main`
moved again (see below), superseding it. **The very next thing to do is get
one clean, fully-green 3-platform run against current `main`** before touching
anything else — none of the prebuilt-artifact work below can be usefully
tested against a build that doesn't complete.

**Repo changed since the CRLF fix landed** (not done by this agent — either
the user directly or Dependabot automation):
- `dependabot.yml` added (commit `dc6d349` "add dependabot and toolchain").
- A "bump jobs" commit (`0d64ce5`) removed the `env: NUM_JOBS: "3"` block from
  `ci.yml`. Not a regression — `build.rs`'s `num_jobs()` already falls back to
  `min(available_parallelism, 4)` when `NUM_JOBS` is unset — just noting the
  diff since a prior session added that env var deliberately.
- `dtolnay/rust-toolchain@stable` replaced with
  `actions-rust-lang/setup-rust-toolchain@v1` in all 3 CI jobs (commit
  `3184c43` "use correct setup rust action" — presumably fixing something a
  Dependabot PR got wrong).
- `actions/checkout` bumped 4→7, `actions/cache` bumped 4→6 (Dependabot PRs
  #1 and #2, already merged to `main`).
- **Three Dependabot PRs still open, unreviewed**:
  - #5 `thiserror` 1→2 (used by the `osquery` crate) — check for breaking
    changes in the `#[error(...)]`/`From` derive behavior before merging.
  - #4 `shlex` 1→2 (build-dependency of `osquery-sys`, used in
    `build.rs`'s `expand_response_files`/CMake `flags.make` parsing) — check
    `shlex::split`'s signature/behavior didn't change across the major bump.
  - #3 Docker base image `ubuntu:24.04` → `26.04` in `docker/build.Dockerfile`
    (local dev convenience image only, not CI-critical).
- None of these have been verified against a real native build yet.

## Immediate next step

1. Get one fully green (`cargo build` + `cargo test` passing) run on all
   3 platforms against current `main`.
   Use `gh run list --repo BeryJu/osquery-rs` / `gh run view` / `gh api
   repos/BeryJu/osquery-rs/actions/jobs/<id>/logs` to check status (note: the
   logs API only serves periodic snapshots for in-progress jobs, not a true
   live tail — don't over-interpret two fetches a few seconds apart as "no
   progress").
2. Review and merge (or fix) the 3 open Dependabot PRs — probably safe, but
   verify against a real build first given how build-dep-sensitive this crate
   is (shlex especially, since it's used for correctness-critical shell-word
   parsing of CMake's generated files).
3. Only then move on to the prebuilt-artifact work below.

## Big pending item: prebuilt-artifact distribution

The user asked to stop building osquery from source on every consumer's
machine (multi-hour native build) and instead: build once in this repo's own
CI, host the compiled result, and have `build.rs` download+link a prebuilt
bundle by default (keeping from-source as an explicit opt-in fallback via
`OSQUERY_SYS_FORCE_SOURCE_BUILD=1`). Also requires the Linux artifact's final
link to target an old glibc floor (build inside a `manylinux2014` container),
since prebuilding changes who performs the final link (was: the consumer;
becomes: this repo's CI).

**Full design is written up in a plan file** (not part of this repo, lives in
the planning agent's workspace):
`/Users/jens/.config/claude/work/plans/hidden-noodling-quill.md`

That file has the complete, reviewed design: bundle contents/layout (flat
`lib/` dir of static archives + a hand-rolled tab-separated `manifest.v1`, no
serde), hosting (GitHub Release assets under tag `v<CARGO_PKG_VERSION>`),
download mechanism (`ureq` build-dep), integrity verification (`sha2` +
git-committed `prebuilt-checksums.v1`, `include_str!`'d so the expected hash
never comes from the network), the fallback decision tree (loud warning +
auto-fallback on network failure, hard error on checksum mismatch), and the
new `release.yml` CI workflow shape (draft release → build+package+checksum
per platform → commit checksums → self-verify → publish → `cargo publish`).
If that file is no longer available, this task list plus the corresponding
project-memory entries (see below) should still convey enough to reconstruct
the design; ask the user to confirm before re-deriving it from scratch.

### Remaining sub-tasks (in dependency order)

1. **Implement `manifest.v1` + `prebuilt-checksums.v1` format and parsing** in
   `osquery-sys/build.rs` — tab-separated, `KIND \t PATH_OR_DASH \t NAME \t
   WHOLE_ARCHIVE_OR_DASH` per line for the manifest (plus a `#`-prefixed
   header carrying `osquery_tag`/`crate_version`/`target`/
   `cxx_compiler`/`sysroot`/`cxx_defines`/`cxx_includes`), one `target \t
   sha256` line per platform for the checksums file.
2. **Implement `OSQUERY_SYS_PACKAGE_DIR`-gated staging** in `build.rs`: reuse
   the existing `items`/`cxx_compiler`/`sysroot`/`defines`/`includes` that
   `main()` already computes to copy each `StaticLib`'s archive into a flat
   `lib/` dir and write `manifest.v1` — this function's only job is staging
   files, NOT invoking `tar` (that stays in the CI workflow, visible/
   auditable in YAML rather than hidden in a build script).
3. **Implement the prebuilt download/verify/extract/fallback path** in
   `build.rs::main()`: add `ureq` + `sha2` as build-dependencies; implement
   the decision tree (force-source env var → unsupported target → cached
   bundle → download → checksum check → extract → parse manifest → emit
   LinkItems + compile shim locally against the manifest's recorded
   compiler/sysroot/defines/includes). See the plan file's "Fallback decision
   tree" section for the exact branching and error-message wording.
4. **Write `.github/workflows/release.yml`**: triggered on `push: tags:
   ['v*']`, one job per platform (Linux containerized under manylinux2014),
   each running `cargo build --release` with `OSQUERY_SYS_PACKAGE_DIR` set,
   then a workflow step that tars+zstds the staged dir, computes its SHA-256,
   commits the updated checksum entry, uploads to a draft release, and a
   final job that re-verifies all uploaded assets before publishing the
   release and running `cargo publish` for both crates.
5. **Containerize the Linux CI job under `manylinux2014`** (in both `ci.yml`
   and `release.yml`, for consistency) — `container:
   quay.io/pypa/manylinux2014_x86_64` instead of bare `ubuntu-latest`; install
   `cmake`/`bison`/`flex`/`perl`/`python3`/`git`/`ccache` via `yum` (verify
   CentOS 7's stock `cmake` is new enough for osquery — likely needs `pip
   install cmake` or a manual binary instead). The existing
   `OSQUERY_TOOLCHAIN_SYSROOT`-based CMake configure logic doesn't need to
   change; only the final link's dynamic `-lc`/`-lresolv` resolution
   (`append_linux_default_linker_items`) is affected by the container choice.
6. **Update `README.md` and project memory** once the above is implemented
   and CI-verified: document the new default (prebuilt download) vs.
   `OSQUERY_SYS_FORCE_SOURCE_BUILD=1`, the still-required local C++ compiler
   and lightweight source clone even on the prebuilt path, and the maintainer
   release process. Project memory lives at
   `/Users/jens/.config/claude/work/projects/-Users-jens-dev-t-osquery-sys/`
   (`osquery_sys_project_status.md`, `osquery_sys_build_findings.md`) — a
   fresh agent session in this same working directory should have access to
   it automatically.

## Known constraints worth remembering

- No local Linux/macOS/Windows native-build environment available on the dev
  machine this was built on (Xcode incompatibility on that Mac) — all
  verification of anything touching the native build or CI containers has to
  go through real GitHub Actions runs.
- Native osquery builds take 1–3+ hours per platform even when working
  correctly — budget for slow iteration cycles, and don't mistake "slow" for
  "stuck" (that's exactly what the `-vv` change above was for).
- The native-build CI cache (`target/osquery-sys` in `ci.yml`'s cache steps)
  is keyed on `hashFiles('osquery-sys/build.rs')` — every `build.rs` edit
  forces a full rebuild on all 3 platforms on the next run.
