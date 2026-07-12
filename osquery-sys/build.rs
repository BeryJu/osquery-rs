//! Fetches osquery's pinned release tag (shallow git clone, no vendored
//! submodule required -- this crate is meant to be usable as a normal
//! `cargo add`ed dependency, not just from inside this workspace), builds
//! it (as its own top-level CMake project, exactly as osquery's own docs
//! describe -- NOT wrapped via `add_subdirectory()`, since osquery's
//! CMakeLists.txt assumes it IS the top-level project via
//! `CMAKE_SOURCE_DIR`-relative includes), then harvests the real,
//! fully-resolved link line CMake generated for the `osqueryd` executable
//! target.
//!
//! That link line already contains, in the correct order, every third-party
//! and osquery-internal static library `osqueryd` needs -- including the
//! `-Wl,--whole-archive`/`-force_load`/`/WHOLEARCHIVE:` sequences osquery's
//! own `enableLinkWholeArchive()` CMake helper already applies to every
//! table/plugin target that registers itself via static initializers. We
//! classify each surviving token into a `LinkItem` and emit it via
//! `cargo:rustc-link-lib`/`cargo:rustc-link-search` (see `emit_link_items`
//! for why, as opposed to raw `cargo:rustc-link-arg` passthrough), with one
//! exception: the single archive built from `osquery/main/{main,posix/main}.cpp`
//! (the `osquery_main` target) is dropped, because that's the one
//! translation unit that defines the process's real `main()`/`wmain()` --
//! linking it would collide with the Rust binary's own entry point.
//! Everything else in `osquery_main`'s dependency graph is a leaf library
//! with no competing `main`, so dropping only that one archive is safe.
//!
//! This is deliberately mechanical (parse CMake's own output) rather than a
//! hand-maintained list of ~30 target names: the leaf-library set here was
//! previously enumerated by hand from `osquery/main/CMakeLists.txt`, but
//! that requires re-deriving on every osquery version bump and re-deriving
//! third-party dependencies empirically anyway. Parsing the real link line
//! keeps this file correct across osquery version bumps automatically,
//! provided the general shape (one archive = one main()) doesn't change.
//!
//! On Windows, osquery's own docs only document the multi-config "Visual
//! Studio" CMake generator, whose MSBuild `.vcxproj` project files don't
//! have anything resembling `link.txt`/`flags.make`. We instead force the
//! "NMake Makefiles" generator (single-config, part of the same CMake
//! Makefile-generator family as "Unix Makefiles" -- same
//! `CMakeFiles/<target>.dir/{flags.make,link.txt}` layout), which is NOT
//! osquery's own tested/documented path upstream. This is unverified
//! against a real Windows build as of this writing; see
//! `.github/workflows/ci.yml` and iterate there.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Pinned osquery release. Bump deliberately -- this is the single source
/// of truth for which version gets built (there is no vendored submodule
/// pin to keep in sync with anymore). Changing it changes the default
/// source/build cache paths too (see `main`), so a version bump naturally
/// gets a fresh build rather than reusing a stale cache.
const OSQUERY_TAG: &str = "5.23.1";
const OSQUERY_REPO_URL: &str = "https://github.com/osquery/osquery.git";

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let shim_dir = manifest_dir.join("shim");

    // osquery's own build takes a very long time (fetches and compiles
    // dozens of third-party dependencies plus its own large codebase) and
    // is NOT something we want to redo inside a fresh OUT_DIR on every
    // cargo invocation (OUT_DIR's hash can change across rebuilds). Cache
    // both the cloned source and the native build in a stable location
    // inside the *consuming project's* target/ directory -- shared within
    // that project across incremental rebuilds, respects `cargo clean`,
    // and doesn't require a shared cross-project cache or any special
    // repo layout (no sibling `vendor/` directory, no git submodule).
    let cache_root = cargo_target_dir().join("osquery-sys");

    let src_dir = env::var_os("OSQUERY_SYS_SRC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| cache_root.join(format!("src-{OSQUERY_TAG}")));
    let build_dir = env::var_os("OSQUERY_SYS_BUILD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| cache_root.join(format!("build-{OSQUERY_TAG}")));

    let freshly_cloned = ensure_osquery_source(&src_dir);

    // A build_dir left over from a *different* source checkout would still
    // have a real osqueryd + link.txt sitting in it, but its flags.make/
    // link.txt reference paths into src_dir's third-party submodules (e.g.
    // boost) that a fresh clone hasn't fetched yet (those are only pulled
    // lazily by CMake's own configure step below) -- discovering that
    // stale osqueryd would skip configure_and_build entirely and only fail
    // much later, confusingly, when the shim's own compile step can't find
    // headers that were never fetched this run. Force a clean rebuild
    // whenever the source itself was just freshly cloned.
    if freshly_cloned && build_dir.exists() {
        fs::remove_dir_all(&build_dir)
            .unwrap_or_else(|e| panic!("failed to remove stale {}: {e}", build_dir.display()));
    }

    let osqueryd_path = find_osqueryd(&build_dir);
    if osqueryd_path.is_none() {
        configure_and_build(&src_dir, &build_dir);
    }
    let osqueryd_path =
        find_osqueryd(&build_dir).expect("osqueryd was not produced by the configured build");
    let (link_line, link_cwd) = find_link_line(&build_dir, "osqueryd").unwrap_or_else(|| {
        panic!(
            "could not find osqueryd's CMake-generated link command under {} \
             -- directories matching \"osqueryd\":{}",
            build_dir.display(),
            describe_missing_link_txt(&build_dir, "osqueryd")
        )
    });

    let (cxx_compiler, sysroot) = read_cmake_cache_compiler(&build_dir);

    let mut items = collect_link_items(&link_line, &osqueryd_path, &link_cwd);
    if cfg!(target_os = "linux") {
        append_linux_default_linker_items(&mut items, sysroot.as_deref());
    }
    // Must come after append_linux_default_linker_items (which itself
    // appends libc++/libc++abi/compiler-rt) so this is truly last -- see
    // compat_stubs.cpp for why it needs to be.
    items.push(link_item_for_archive(
        &compile_compat_stubs(&shim_dir, &cxx_compiler),
        false,
    ));

    emit_link_items(&items);

    // shim.cpp includes osquery/core/flags.h, sql.h, etc., which transitively
    // pull in third-party headers (boost, rapidjson, ...) via the same
    // per-target -I/-isystem/-D flags CMake generated for its own C++
    // sources -- there is no single include path that covers this, so reuse
    // a representative real target's flags.make verbatim rather than
    // guessing. osquery_core is a safe pick: it directly compiles
    // translation units that include flags.h/system.h, the same headers the
    // shim needs.
    let (defines, includes) = read_target_compile_flags(&build_dir, "osquery_core")
        .expect("could not find osquery_core's CMake-generated flags.make");

    compile_shim(
        &shim_dir,
        &src_dir,
        &cxx_compiler,
        sysroot.as_deref(),
        &defines,
        &includes,
    );

    println!("cargo:rerun-if-changed={}", shim_dir.join("shim.h").display());
    println!("cargo:rerun-if-changed={}", shim_dir.join("shim.cpp").display());
    println!(
        "cargo:rerun-if-changed={}",
        shim_dir.join("compat_stubs.cpp").display()
    );
}

/// Cargo doesn't expose the workspace/project target directory to build
/// scripts directly. Derive it from `OUT_DIR`
/// (`<target>/<profile>/build/<pkg>-<hash>/out`) by walking up 4 ancestors
/// -- a standard technique other large `-sys` crates use to find a stable,
/// `cargo clean`-respecting cache location outside the volatile
/// per-invocation `OUT_DIR` (whose hash can change across rebuilds).
fn cargo_target_dir() -> PathBuf {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    out_dir
        .ancestors()
        .nth(4)
        .unwrap_or_else(|| {
            panic!(
                "OUT_DIR ({}) has an unexpectedly shallow path",
                out_dir.display()
            )
        })
        .to_path_buf()
}

/// Sets a single, lightweight git tracing env var on a git (or
/// git-spawning) child process, so a stalled/slow network fetch produces
/// some continuous diagnostic output instead of potential total silence.
/// Deliberately just `GIT_TRACE` (one line per git subcommand dispatched) --
/// `GIT_CURL_VERBOSE` (full HTTP request/response headers) and
/// `GIT_TRACE_PERFORMANCE` (per-internal-operation timing) were tried too,
/// but across ~30 nested submodule fetches during `cmake configure` they
/// multiplied CI log volume enough to be its own problem (log fetches were
/// getting truncated well before reaching the actual error). Applied both
/// to our own explicit clone and to `cmake configure` (whose nested `git
/// submodule` fetches for boost/thrift/rocksdb/... inherit this env too).
fn apply_git_diagnostics(cmd: &mut Command) {
    cmd.env("GIT_TRACE", "1");
}

/// Clones osquery's pinned tag into `dest` if it isn't already there.
/// Shallow (`--depth 1`): we only need this exact tag's tree, not history.
/// Nested third-party submodules (boost, thrift, rocksdb, ...) are NOT
/// fetched here -- osquery's own CMake configure step fetches each one
/// lazily, per-platform, as it's actually needed (see
/// `configure_and_build`; this is also what makes disabling
/// OSQUERY_BUILD_AWS/BPF/EXPERIMENTS below actually skip their heavy
/// nested dependencies instead of just skipping the *build* of code
/// that's already been fetched).
/// Returns `true` if a fresh clone was actually performed (as opposed to
/// `dest` already existing from a prior run) -- callers use this to decide
/// whether any pre-existing `build_dir` output can still be trusted. A fresh
/// source clone has none of osquery's third-party submodules fetched yet
/// (those are pulled lazily by CMake's own configure step -- see below), so
/// a `build_dir` left over from a *different* source checkout would have
/// generated `flags.make`/`link.txt` referencing paths (e.g. into boost)
/// that this fresh `dest` doesn't have content at yet. Silently reusing
/// such a build_dir causes a working `osqueryd`/`link.txt` to be discovered
/// while the shim's own compile step fails with cryptic missing-header
/// errors from third-party include paths that were never actually fetched
/// this run.
fn ensure_osquery_source(dest: &Path) -> bool {
    if dest.join("CMakeLists.txt").exists() {
        return false;
    }
    let parent = dest
        .parent()
        .expect("osquery source destination has no parent directory");
    fs::create_dir_all(parent)
        .unwrap_or_else(|e| panic!("failed to create {}: {e}", parent.display()));

    let mut clone = Command::new("git");
    clone
        .arg("clone")
        .arg("--progress")
        .arg("--branch")
        .arg(OSQUERY_TAG)
        .arg("--depth")
        .arg("1")
        .arg(OSQUERY_REPO_URL)
        .arg(dest);
    apply_git_diagnostics(&mut clone);
    run(&mut clone, "git clone osquery");
    true
}

/// Applies known local patches to the freshly cloned osquery tree, each
/// idempotent (checks for a marker before touching the file) so re-running
/// build.rs never double-patches.
fn apply_local_patches(src_dir: &Path) {
    patch_boost_mpl_enum_constexpr_conversion(src_dir);
}

/// Boost.MPL's integral_wrapper.hpp computes value+1/value-1 for every
/// integral wrapper type it's instantiated for, including internal
/// Boost.TypeTraits enums whose valid range doesn't include the resulting
/// out-of-range value. Older Clang tolerated this as UB; Clang >= ~17
/// makes it a hard error under `-Wenum-constexpr-conversion`. osquery pins
/// a Boost version that predates this diagnostic, and the osquery-toolchain
/// (Linux) / a modern Xcode (macOS) can both bundle a Clang new enough to
/// hit it. Silence the diagnostic around the two spots that trigger it,
/// rather than patching the generic arithmetic (this header is shared by
/// many wrapper types).
fn patch_boost_mpl_enum_constexpr_conversion(src_dir: &Path) {
    let path = src_dir.join(
        "libraries/cmake/source/boost/src/libs/mpl/include/boost/mpl/aux_/integral_wrapper.hpp",
    );
    // Normalize to LF before matching: Windows checkouts of this file can
    // come back CRLF (git-for-Windows' core.autocrlf default, and/or a
    // path-specific .gitattributes rule inside Boost's own repo that
    // overrides a global autocrlf=false override -- tried that override
    // first, on both the top-level clone and the cmake-configure step that
    // triggers this nested submodule's checkout, and it did not change the
    // result) -- neither Clang nor MSVC care about a source file's
    // line-ending style, so rewriting the whole file to LF-only here has no
    // effect on compilation and makes the byte-exact anchor match below
    // robust regardless of which checkout path produced CRLF.
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let contents = contents.replace("\r\n", "\n");

    if contents.contains("-Wenum-constexpr-conversion") {
        return; // already patched
    }

    let open_marker = "BOOST_MPL_AUX_ADL_BARRIER_NAMESPACE_OPEN\n\ntemplate< AUX_WRAPPER_PARAMS(N) >\nstruct AUX_WRAPPER_NAME";
    let open_replacement = "BOOST_MPL_AUX_ADL_BARRIER_NAMESPACE_OPEN\n\n#if defined(__clang__)\n#pragma clang diagnostic push\n#pragma clang diagnostic ignored \"-Wenum-constexpr-conversion\"\n#endif\n\ntemplate< AUX_WRAPPER_PARAMS(N) >\nstruct AUX_WRAPPER_NAME";
    let close_marker = "BOOST_MPL_AUX_ADL_BARRIER_NAMESPACE_CLOSE";
    let close_replacement = "#if defined(__clang__)\n#pragma clang diagnostic pop\n#endif\n\nBOOST_MPL_AUX_ADL_BARRIER_NAMESPACE_CLOSE";

    if !contents.contains(open_marker) || !contents.contains(close_marker) {
        panic!(
            "expected anchor text not found in {} -- osquery's vendored Boost \
             version may have changed; update patch_boost_mpl_enum_constexpr_conversion",
            path.display()
        );
    }

    let patched = contents
        .replacen(open_marker, open_replacement, 1)
        .replacen(close_marker, close_replacement, 1);
    fs::write(&path, patched)
        .unwrap_or_else(|e| panic!("failed to write patched {}: {e}", path.display()));
}

fn osqueryd_name() -> &'static str {
    if cfg!(windows) {
        "osqueryd.exe"
    } else {
        "osqueryd"
    }
}

fn find_osqueryd(build_dir: &Path) -> Option<PathBuf> {
    let candidate = build_dir.join("osquery").join(osqueryd_name());
    if candidate.exists() {
        return Some(candidate);
    }
    find_file_named(build_dir, osqueryd_name())
}

/// Returns the full link command line for `target`, plus the directory it
/// must be resolved relative to (CMake runs link.txt/build.make's link rule
/// with its CWD set to the target's own source-relative build directory --
/// e.g. `build_dir/osquery/` for a target defined in
/// `osquery/CMakeLists.txt` -- not the `CMakeFiles/<target>.dir/` folder
/// the command itself lives in, which is two levels deeper).
///
/// On Linux/macOS ("Unix Makefiles"), this is literally the contents of
/// `link.txt`. On Windows ("NMake Makefiles" + MSVC), CMake doesn't write a
/// standalone link.txt for the final executable at all -- see
/// `extract_link_line_from_build_make` for why -- so that's tried as a
/// fallback.
fn find_link_line(build_dir: &Path, target: &str) -> Option<(String, PathBuf)> {
    let dir = find_target_dir(build_dir, target)?;
    let link_cwd = dir.parent().and_then(Path::parent)?.to_path_buf();

    if let Ok(line) = fs::read_to_string(dir.join("link.txt")) {
        return Some((line, link_cwd));
    }
    let line = extract_link_line_from_build_make(&dir.join("build.make"))?;
    Some((line, link_cwd))
}

/// On Windows, CMake's "NMake Makefiles" generator (forced because the
/// "Visual Studio" generator's MSBuild `.vcxproj` files have nothing
/// resembling `link.txt`/`flags.make` -- see the module doc comment)
/// doesn't write a standalone `link.txt` for the final executable either.
/// Instead it wraps the real link invocation in `cmake -E vs_link_exe` (a
/// CMake-internal helper that emulates Visual Studio's manifest/
/// incremental-link handling for non-VS generators targeting MSVC) and
/// expresses the actual linker command as an inline NMake response-file
/// block directly inside `build.make`: the wrapper's own command line ends
/// in `@<<`, and one or more following lines (terminated by a line
/// containing only `<<`) are the real flags/libraries, exactly as if
/// they'd been written to an external response file CMake then referenced.
/// Reconstruct that block as a single line so it can be tokenized the same
/// way `link.txt`'s content is on Linux/macOS.
fn extract_link_line_from_build_make(build_make: &Path) -> Option<String> {
    let contents = fs::read_to_string(build_make).ok()?;
    let lines: Vec<&str> = contents.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if !line.to_ascii_lowercase().contains("link.exe") {
            continue;
        }
        // CMake's own wrapper args (`-E vs_link_exe --msvc-ver=... --rc=...
        // --mt=... --manifests ...`) precede a ` -- ` separator, after
        // which the real, wrapped command begins.
        let after_wrapper = line.rsplit_once(" -- ").map_or(*line, |(_, tail)| tail).trim();
        let Some(header) = after_wrapper.strip_suffix("@<<") else {
            continue;
        };

        let mut full = header.trim_end().to_string();
        let mut found_terminator = false;
        for cont in lines.iter().skip(i + 1).take(64) {
            if cont.trim() == "<<" {
                found_terminator = true;
                break;
            }
            full.push(' ');
            full.push_str(cont.trim());
        }
        if !found_terminator {
            // Didn't find the closing marker within a sane distance --
            // this isn't the block we think it is (or the format changed
            // in a way this parsing doesn't understand). Don't guess with
            // however much unrelated build.make content we scooped up;
            // let the caller's diagnostic panic fire instead.
            continue;
        }
        return Some(full);
    }
    None
}

/// Every CMake target we look for by name (`osqueryd`, `osquery_core`) is
/// defined directly in (or included from) `osquery/CMakeLists.txt`, so its
/// generated `CMakeFiles/<target>.dir/` always lands at this one consistent
/// location -- checking it directly (one `is_dir()` stat) avoids the
/// unbounded recursive walk `find_dir_named` falls back to below. That walk
/// visits every directory in `build_dir` with no pruning at all, and once
/// every vendored third-party dependency (boost, thrift, rocksdb,
/// sleuthkit, openssl, sqlite, ...) is actually compiled, that tree can
/// have hundreds of thousands of files -- on Linux CI specifically (whose
/// build produces meaningfully more such files than the macOS/Windows
/// builds do) this walk alone was slow enough to be indistinguishable from
/// a genuine hang. The slow path is kept as a fallback purely so this still
/// works if a future osquery version changes the layout.
fn find_target_dir(build_dir: &Path, target: &str) -> Option<PathBuf> {
    let dir_name = format!("{target}.dir");
    let fast_path = build_dir.join("osquery").join("CMakeFiles").join(&dir_name);
    if fast_path.is_dir() {
        return Some(fast_path);
    }
    find_dir_named(build_dir, &dir_name)
}

fn find_dir_named(root: &Path, dir_name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let is_match = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(dir_name));
        if is_match {
            return Some(path);
        }
        if let Some(found) = find_dir_named(&path, dir_name) {
            return Some(found);
        }
    }
    None
}

/// Called only when `find_link_line` comes back empty, to turn an otherwise
/// silent "not found" into an actionable panic message. Walks `build_dir`
/// collecting every directory whose name contains `needle` (case-insensitive
/// substring, not an exact `.dir`-suffixed match -- deliberately looser than
/// `find_dir_named`'s own matching, so this still reports something
/// useful even if the real directory is named subtly differently than
/// expected), listing each one's immediate contents.
fn describe_missing_link_txt(build_dir: &Path, needle: &str) -> String {
    let mut hits = Vec::new();
    collect_dirs_containing(build_dir, &needle.to_ascii_lowercase(), &mut hits);
    if hits.is_empty() {
        return format!(
            "no directory anywhere under {} has a name containing {needle:?} at all",
            build_dir.display()
        );
    }
    let mut report = String::new();
    for dir in hits {
        report.push_str(&format!("\n  {}:\n", dir.display()));
        match fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    report.push_str(&format!("    {}\n", entry.file_name().to_string_lossy()));
                }
            }
            Err(e) => report.push_str(&format!("    <failed to list: {e}>\n")),
        }

        // No standalone link.txt on at least some CMake/generator
        // combinations (observed on Windows/NMake) -- the actual link
        // invocation may be embedded directly in build.make instead. Dump
        // only lines that look linker-related (filtered to keep this from
        // becoming its own log-volume problem) so a fix can be designed
        // from the real format instead of guessed at blindly.
        let build_make = dir.join("build.make");
        if let Ok(contents) = fs::read_to_string(&build_make) {
            report.push_str(&format!("\n  relevant lines from {}:\n", build_make.display()));
            for line in contents.lines() {
                let lower = line.to_ascii_lowercase();
                if lower.contains("link")
                    || lower.contains(".exe")
                    || lower.contains("cmake_link_script")
                {
                    report.push_str(&format!("    {line}\n"));
                }
            }
        }
    }
    report
}

fn collect_dirs_containing(root: &Path, needle_lower: &str, hits: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.to_ascii_lowercase().contains(needle_lower) {
                hits.push(path.clone());
            }
        }
        collect_dirs_containing(&path, needle_lower, hits);
    }
}

fn configure_and_build(src_dir: &Path, build_dir: &Path) {
    fs::create_dir_all(build_dir).expect("failed to create osquery build directory");

    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(src_dir)
        .arg("-B")
        .arg(build_dir)
        .arg("-DCMAKE_BUILD_TYPE=RelWithDebInfo")
        // The "experiments" subtree (as opposed to the always-built
        // events_stream registry we do need) pulls in an eBPF-based Linux
        // events component that vendors its own LLVM; that LLVM's zlib
        // import collides with osquery's own top-level zlib import under
        // the same CMake binary directory (an upstream CMake bug in that
        // combination). We don't need eBPF Linux event tables for
        // in-process SQL queries, so skip it entirely.
        .arg("-DOSQUERY_BUILD_EXPERIMENTS=OFF")
        // OSQUERY_BUILD_BPF pulls in ebpfpub -> its own vendored LLVM,
        // whose find_package(ZLIB) collides with osquery's own top-level
        // zlib import under the same CMake binary directory (a real
        // upstream CMake fragility with this toolchain/LLVM combination:
        // FindZLIB.cmake's importSourceSubmodule() has no guard against
        // being invoked twice). We don't need BPF-based Linux process/file
        // event tables for in-process SQL queries.
        .arg("-DOSQUERY_BUILD_BPF=OFF")
        // OSQUERY_BUILD_AWS defaults ON on every platform except
        // Windows-arm64, pulling in aws-sdk-cpp/aws-crt-cpp/aws-c-*/s2n.
        // aws-c-common alone vendors CBMC formal-verification proof
        // submodules (litani, aws-verification-model-for-libcrypto, ...)
        // with absurdly deep nested paths that blow past Windows'
        // filesystem path-length limits (`fatal: cannot write keep file
        // '...pack-<sha>.keep': Filename too long`) regardless of whether
        // they're fetched upfront or lazily during configure. We don't
        // need AWS Firehose/Kinesis logger plugins for in-process SQL
        // queries, so disable it everywhere rather than special-casing
        // Windows -- it also trims a substantial dependency from every
        // platform's build.
        .arg("-DOSQUERY_BUILD_AWS=OFF")
        // NOTE: CMAKE_VERBOSE_MAKEFILE=ON was tried here to get per-file
        // compiler invocations instead of terse "[ x%] Building ..." lines,
        // but for a codebase this large (osquery + ~30 vendored
        // dependencies) it multiplied CI log volume enough to make log
        // fetches truncate before reaching the actual error -- removed.
        // `cargo build -vv` already surfaces enough for our own crate's
        // build; a genuinely stuck native build is better diagnosed by
        // checking for CI runner contention first (see git history/PR
        // discussion) than by maximizing this log's verbosity further.
        .arg("-G")
        .arg(if cfg!(windows) {
            "NMake Makefiles"
        } else {
            "Unix Makefiles"
        });

    if cfg!(target_os = "linux") {
        let sysroot = env::var("OSQUERY_TOOLCHAIN_SYSROOT")
            .unwrap_or_else(|_| "/usr/local/osquery-toolchain".to_string());
        if Path::new(&sysroot).exists() {
            configure.arg(format!("-DOSQUERY_TOOLCHAIN_SYSROOT={sysroot}"));
        } else {
            panic!(
                "OSQUERY_TOOLCHAIN_SYSROOT not set and /usr/local/osquery-toolchain does not \
                 exist. See docker/build.Dockerfile / README.md for how to install the \
                 osquery-toolchain (LLVM/libc++) osquery's own build requires on Linux."
            );
        }
    } else if cfg!(target_os = "macos") {
        // Requires a supported Xcode/SDK to be selected (osquery's docs say
        // its macOS build is broken on Xcode SDK >= 16.3 -- pin the active
        // developer directory to a compatible Xcode before invoking cargo;
        // see .github/workflows/ci.yml, which uses an explicit Xcode
        // version rather than whatever "latest" the runner defaults to).
        // The "Unix Makefiles" generator forced above works identically to
        // Linux here (same CMake Makefile-generator family -> same
        // CMakeFiles/<target>.dir/{flags.make,link.txt} layout our parsing
        // relies on), so no macOS-specific link-line handling is needed:
        // rustc's own default linker driver on macOS already IS the same
        // clang (via the active Xcode) that built osquery, unlike Linux's
        // mismatched custom toolchain-vs-system-gcc situation.
        let sdk_path = Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string());
        if let Some(sdk_path) = sdk_path {
            configure.arg(format!("-DCMAKE_OSX_SYSROOT={sdk_path}"));
        }
        configure
            .arg("-DCMAKE_C_COMPILER=clang")
            .arg("-DCMAKE_CXX_COMPILER=clang++")
            // Matches osquery's own build docs recommendation; affects the
            // minimum macOS version the produced code targets, not build
            // success, but keeps us aligned with what upstream tests.
            .arg("-DCMAKE_OSX_DEPLOYMENT_TARGET=10.15");
    } else if cfg!(windows) {
        // NMake Makefiles needs the MSVC toolchain (cl.exe/link.exe/nmake)
        // already on PATH -- i.e. run from a Developer Command Prompt, or
        // (as CI does) via the ilammy/msvc-dev-cmd action before invoking
        // cargo. CMake auto-detects cl.exe from the environment for this
        // generator the same way it auto-detects gcc/clang for "Unix
        // Makefiles"; we don't set CMAKE_C(XX)_COMPILER explicitly here.
        //
        // Strawberry Perl is required (per osquery's own Windows build
        // docs) for the OpenSSL formula's build; also must be on PATH.
    }

    apply_git_diagnostics(&mut configure);
    run(&mut configure, "cmake configure");

    // The patched file (a vendored Boost header) lives inside a nested
    // submodule that only gets fetched by the CMake configure step's own
    // lazy submodule mechanism -- must run after configure, before build
    // (which is what actually compiles it).
    apply_local_patches(src_dir);

    let mut build = Command::new("cmake");
    build
        .arg("--build")
        .arg(build_dir)
        .arg("--target")
        .arg("osqueryd")
        .arg("-j")
        .arg(num_jobs());
    run(&mut build, "cmake build osqueryd");
}

fn num_jobs() -> String {
    // osquery's own docs warn that Clang can crash/OOM compiling
    // third-party dependencies (boost, thrift, rocksdb, ...) with under
    // ~8GB of memory; a full-parallelism build (one heavy clang++ process
    // per core) can exceed that even on machines with plenty of cores but
    // constrained memory (e.g. a capped Docker Desktop VM). Default to a
    // conservative cap and let callers with more memory raise it.
    env::var("NUM_JOBS").unwrap_or_else(|_| {
        std::thread::available_parallelism()
            .map(|n| n.get().min(4))
            .unwrap_or(4)
            .add(1)
            .to_string()
    })
}

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {description}: {e}"));
    if !status.success() {
        panic!("{description} failed with {status}");
    }
}

/// Reads CMAKE_CXX_COMPILER (and, on Linux via the osquery-toolchain,
/// CMAKE_SYSROOT) out of the configured build's CMakeCache.txt, so shim.cpp
/// is compiled with the exact same compiler/stdlib osquery itself used --
/// mixing libc++ (what the osquery-toolchain forces on Linux) with the
/// system's default libstdc++ would be an ABI mismatch.
fn read_cmake_cache_compiler(build_dir: &Path) -> (PathBuf, Option<PathBuf>) {
    let cache_path = build_dir.join("CMakeCache.txt");
    let contents = fs::read_to_string(&cache_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", cache_path.display()));

    let mut compiler = None;
    let mut sysroot = None;
    for line in contents.lines() {
        if let Some(v) = line.strip_prefix("CMAKE_CXX_COMPILER:STRING=") {
            compiler = Some(PathBuf::from(v));
        } else if let Some(v) = line.strip_prefix("CMAKE_CXX_COMPILER:FILEPATH=") {
            compiler = Some(PathBuf::from(v));
        } else if let Some(v) = line.strip_prefix("CMAKE_SYSROOT:PATH=") {
            if !v.is_empty() {
                sysroot = Some(PathBuf::from(v));
            }
        }
    }

    (compiler.unwrap_or_else(|| PathBuf::from("c++")), sysroot)
}

/// A single library reference destined for `cargo:rustc-link-lib`/
/// `cargo:rustc-link-search`. Unlike `cargo:rustc-link-arg`, both of those
/// propagate transitively through the *entire* dependency graph regardless
/// of depth -- see `emit_link_items` -- which is what makes an arbitrary
/// downstream application depending on the `osquery` crate link correctly
/// with zero build.rs code of its own.
enum LinkItem {
    /// A real static archive with a resolvable directory (osquery's own
    /// build output, or a file we compiled/located ourselves).
    StaticLib {
        dir: PathBuf,
        name: String,
        whole_archive: bool,
    },
    /// A system/dynamic library referenced by bare name (Unix `-lNAME`, or
    /// a Windows import library with no directory component).
    Dylib(String),
    /// macOS `-framework NAME` (`-weak_framework NAME` is folded into this
    /// too, losing its "weak"/optional-at-runtime semantics -- there's no
    /// stable Cargo modifier for that yet; an acceptable behavior change
    /// for the one framework reference (OSLog) that used it, since it
    /// isn't something SQL queries call into).
    Framework(String),
}

/// Emits every collected `LinkItem` as `cargo:rustc-link-lib`/
/// `cargo:rustc-link-search`. These (unlike `cargo:rustc-link-arg`, which
/// only applies to the *emitting* crate's own binary/test/example targets)
/// are documented to propagate through the whole dependency graph to any
/// depth: a final application several crates downstream of `osquery-sys`
/// picks these up automatically. Order matters for plain (non-whole-archive)
/// static libraries under GNU ld's single-pass symbol resolution; Cargo
/// places one crate's own rustc-link-lib/-search directives on the linker
/// command line in the order the build script printed them, and every item
/// here comes from this one crate's build script, so the order we computed
/// while parsing osquery's own link.txt is preserved exactly.
fn emit_link_items(items: &[LinkItem]) {
    for item in items {
        match item {
            LinkItem::StaticLib {
                dir,
                name,
                whole_archive,
            } => {
                println!("cargo:rustc-link-search=native={}", dir.display());
                if *whole_archive {
                    println!("cargo:rustc-link-lib=static:+whole-archive={name}");
                } else {
                    println!("cargo:rustc-link-lib=static={name}");
                }
            }
            LinkItem::Dylib(name) => {
                println!("cargo:rustc-link-lib=dylib={name}");
            }
            LinkItem::Framework(name) => {
                println!("cargo:rustc-link-lib=framework={name}");
            }
        }
    }
}

fn link_item_for_archive(path: &Path, whole_archive: bool) -> LinkItem {
    let dir = path
        .parent()
        .unwrap_or_else(|| panic!("archive path has no parent directory: {}", path.display()))
        .to_path_buf();
    let name = archive_bare_name(path);
    LinkItem::StaticLib {
        dir,
        name,
        whole_archive,
    }
}

/// Strips the platform-conventional archive decoration from a path's file
/// name: `lib<name>.a` -> `<name>` on Unix, `<name>.lib` -> `<name>` on
/// Windows (MSVC doesn't use a `lib` prefix) -- the bare form
/// `cargo:rustc-link-lib` expects.
fn archive_bare_name(path: &Path) -> String {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_else(|| panic!("archive path has no file name: {}", path.display()));
    if cfg!(windows) {
        file_name.trim_end_matches(".lib").to_string()
    } else {
        file_name
            .strip_prefix("lib")
            .unwrap_or(file_name)
            .trim_end_matches(".a")
            .to_string()
    }
}

/// Walks osquery's own CMake-generated link line for the `osqueryd` target
/// and classifies every surviving token into a `LinkItem`. Strips the
/// compiler/linker invocation itself, the output-file flag, all object
/// files, and the one archive containing osquery_main's competing
/// `main()`/`wmain()` (see module doc comment for why). A small set of
/// flags with no lib/search equivalent that don't affect functional
/// correctness (compile-flag echoes like `-O2`/`-DNDEBUG`, meaningless at
/// the link step; cosmetic/hardening-only linker flags) are silently
/// dropped; anything else unrecognized is dropped too but with a
/// `cargo:warning`, in case a future osquery version introduces a new kind
/// of reference we haven't seen and this crate needs updating for.
///
/// Handles both GNU-style (Unix Makefiles: `-o <path>`, `.o`, `.a`,
/// `-Wl,--whole-archive`/`--no-whole-archive` as a start/end pair) and
/// MSVC-style (NMake Makefiles: `/OUT:<path>`, `.obj`, `.lib`,
/// `/WHOLEARCHIVE:<path>` as a single self-contained token) link-line
/// syntax. MSVC link commands can also reference a `@<file>.rsp` response
/// file instead of listing everything inline (a real possibility for a
/// dependency graph this large, given Windows' command-line length
/// limits) -- expanded transparently before the main token walk.
fn collect_link_items(link_line: &str, osqueryd_path: &Path, link_cwd: &Path) -> Vec<LinkItem> {
    let tokens = expand_response_files(
        link_line.split_whitespace().map(str::to_string).collect(),
        link_cwd,
    );
    let mut items = Vec::new();
    let mut i = if tokens.is_empty() { 0 } else { 1 }; // token 0 is the driver itself
    let mut whole_archive = false;

    while i < tokens.len() {
        let tok = tokens[i].as_str();

        if cfg!(windows) {
            // CMake's `cmake -E vs_link_exe` wrapper (used for the NMake
            // Makefiles generator, see find_link_line/
            // extract_link_line_from_build_make) emits this flag lowercase
            // (`/out:...`), unlike a hand-written link.txt which might use
            // `/OUT:` -- match case-insensitively rather than assuming one.
            if tok.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("/OUT:")) {
                i += 1;
                continue;
            }
            if tok.ends_with(".obj") {
                i += 1;
                continue;
            }
            if tok.ends_with(".lib") && is_osquery_main_archive(tok) {
                i += 1;
                continue;
            }
            if let Some(rest) = tok.strip_prefix("/WHOLEARCHIVE:") {
                let resolved = resolve_token_path(rest, link_cwd);
                items.push(link_item_for_archive(Path::new(&resolved), true));
                i += 1;
                continue;
            }
            if tok.ends_with(".lib") {
                let resolved = resolve_token_path(tok, link_cwd);
                items.push(classify_archive_or_dylib(Path::new(&resolved)));
                i += 1;
                continue;
            }
        } else {
            if tok == "-o" {
                i += 2; // skip flag + its output path argument
                continue;
            }
            if tok.ends_with(".o") {
                i += 1;
                continue;
            }
            if tok == "-Wl,--whole-archive" {
                whole_archive = true;
                i += 1;
                continue;
            }
            if tok == "-Wl,--no-whole-archive" {
                whole_archive = false;
                i += 1;
                continue;
            }
            if tok.ends_with(".a") && is_osquery_main_archive(tok) {
                i += 1;
                continue;
            }
            if tok.ends_with(".a") {
                let resolved = resolve_token_path(tok, link_cwd);
                items.push(link_item_for_archive(Path::new(&resolved), whole_archive));
                i += 1;
                continue;
            }
            // `-stdlib=libc++` is always redundant: on macOS, rustc's own
            // default link already includes a plain `-lc++` that covers
            // it; on Linux it's replaced below by an explicit path to the
            // osquery-toolchain's own libc++.a (see
            // append_linux_default_linker_items for why a plain `-lc++`
            // doesn't work there).
            if tok == "-stdlib=libc++" {
                i += 1;
                continue;
            }
            // `-lc++abi` similarly needs Linux-specific handling (no
            // system libc++abi there, replaced by an explicit archive
            // path) but resolves fine via the default dynamic linker
            // search on macOS, where it's left as a normal Dylib item
            // below (proven working during local/CI verification).
            if tok == "-lc++abi" && cfg!(target_os = "linux") {
                i += 1;
                continue;
            }
            if let Some(name) = tok.strip_prefix("-l") {
                items.push(LinkItem::Dylib(name.to_string()));
                i += 1;
                continue;
            }
            // Two-token flags whose second token is a bare name (framework
            // name, arch name, ...), not a path.
            if matches!(tok, "-framework" | "-weak_framework") && i + 1 < tokens.len() {
                items.push(LinkItem::Framework(tokens[i + 1].clone()));
                i += 2;
                continue;
            }
            if tok == "-arch" && i + 1 < tokens.len() {
                // Dropped, not converted: rustc's own default link
                // invocation already passes the correct `-arch
                // <target-arch>` for the Cargo target being built. There's
                // no Cargo-native equivalent for a bare compiler flag like
                // this, and none is needed since it would just repeat what
                // rustc already supplies.
                i += 2;
                continue;
            }
        }

        let _ = osqueryd_path; // reserved for future path-based filtering
        if !is_known_droppable_flag(tok) {
            println!(
                "cargo:warning=osquery-sys: dropping unrecognized link token `{tok}` \
                 (no rustc-link-lib/-search equivalent; if the final binary fails to \
                 link or crashes at runtime, this token may need explicit handling)"
            );
        }
        i += 1;
    }
    items
}

/// Classifies a resolved `.lib`/`.a` path: a directory-qualified path is a
/// real static archive; a bare file name with no directory (as Windows
/// system import libraries like `kernel32.lib`/`ws2_32.lib` can appear)
/// is a dynamic/system library reference instead.
fn classify_archive_or_dylib(path: &Path) -> LinkItem {
    let has_dir = path
        .parent()
        .map(|p| !p.as_os_str().is_empty())
        .unwrap_or(false);
    if has_dir {
        link_item_for_archive(path, false)
    } else {
        LinkItem::Dylib(archive_bare_name(path))
    }
}

/// Flags known to have no `cargo:rustc-link-lib`/`-search` equivalent and
/// to not affect the final binary's functional correctness: compile-flag
/// echoes (meaningless at the link step, since nothing is being compiled
/// there) and cosmetic/hardening-only linker flags. Each entry here was
/// directly observed in a real captured link line during development;
/// this is deliberately conservative (only flags we have evidence are
/// safe) rather than an attempt to allowlist every conceivable flag --
/// anything not listed here falls through to a `cargo:warning` instead of
/// being silently assumed safe.
fn is_known_droppable_flag(tok: &str) -> bool {
    matches!(
        tok,
        "-DNDEBUG"
            | "-pthread"
            | "-Wl,-z,relro,-z,now"
            | "-Wl,--build-id=sha1"
            | "-fPIE"
            | "-pie"
    ) || tok.starts_with("-O")
        || tok.starts_with("-g")
        || tok.starts_with("-mmacosx-version-min=")
        || tok.starts_with("--sysroot=")
        || tok == "--no-undefined"
}

/// Expands any `@<file>` response-file reference tokens by reading the
/// file and shell-word-splitting its content in place of the `@file`
/// token. MSVC response files don't use exactly POSIX shell quoting, but
/// `shlex` is a reasonable first approximation for the simple
/// path/flag-only content these contain.
fn expand_response_files(tokens: Vec<String>, link_cwd: &Path) -> Vec<String> {
    let mut out = Vec::with_capacity(tokens.len());
    for tok in tokens {
        if let Some(rsp_path) = tok.strip_prefix('@') {
            let resolved = if Path::new(rsp_path).is_absolute() {
                PathBuf::from(rsp_path)
            } else {
                link_cwd.join(rsp_path)
            };
            let contents = fs::read_to_string(&resolved).unwrap_or_else(|e| {
                panic!("failed to read response file {}: {e}", resolved.display())
            });
            let expanded = shlex::split(&contents)
                .unwrap_or_else(|| panic!("failed to parse response file {}", resolved.display()));
            out.extend(expand_response_files(expanded, link_cwd));
        } else {
            out.push(tok);
        }
    }
    out
}

/// Resolves a single non-flag token as an absolute path if it looks like a
/// relative filesystem path (not already absolute, doesn't start with a
/// flag-introducing `-`/`/`). Flags are passed through unchanged.
fn resolve_token_path(tok: &str, link_cwd: &Path) -> String {
    let looks_like_flag = tok.starts_with('-') || (cfg!(windows) && tok.starts_with('/'));
    if !looks_like_flag && !Path::new(tok).is_absolute() {
        link_cwd.join(tok).to_string_lossy().into_owned()
    } else {
        tok.to_string()
    }
}

/// osquery's own link.txt is written for the osquery-toolchain's clang++
/// driver. We deliberately do NOT force rustc to use that clang++ as its
/// own linker driver globally (via .cargo/config.toml) -- that broke
/// linking for every unrelated build-script/proc-macro binary in the
/// workspace, since the osquery-toolchain sysroot lacks the system's own
/// gcc runtime bits (e.g. `-lgcc_s`) that all those other, unrelated links
/// still need. Instead, keep the default system linker driver for
/// everything and append what it actually needs in place of what
/// `collect_link_items` already dropped (`-stdlib=libc++`, `-lc++abi`,
/// `--sysroot=...`, `--no-undefined`):
///
/// - libc++/libc++abi are referenced by exact path to the osquery-toolchain's
///   own archives -- NOT via a `-lc++`/`-lc++abi` dylib reference plus an
///   added `-L` to the toolchain's lib dir, because that directory also
///   contains the toolchain's own (CentOS7-targeted, per
///   `OSQUERY_BUILD_DISTRO="centos7"` in its CXX_DEFINES) `libpthread`
///   stub, whose linker script hard-codes `/lib64/...` paths that don't
///   exist on this (Ubuntu, non-multilib) system. Adding that directory to
///   the search path let `-lpthread` resolve to that broken stub instead of
///   the system's real libpthread. Referencing libc++/libc++abi by exact
///   path sidesteps the whole-directory search entirely. They're appended
///   at the very END of the item list (not left in whatever position they'd
///   have had) -- GNU ld processes static archives in one left-to-right
///   pass, only pulling in members that resolve an outstanding undefined
///   symbol at that point; with libc++/libc++abi positioned before the
///   hundreds of osquery/third-party archives that actually reference
///   `operator new`/`operator delete`/`vtable for __cxxabiv1::...`/etc.,
///   nothing had asked for those symbols yet and they were silently
///   dropped, surfacing as undefined references much later.
/// - `-lc`/`-lresolv`: rustc's own default link args put `-lc` (libc.so)
///   early, before any of the whole-archive osquery objects that reference
///   versioned glibc symbols (e.g. `__stack_chk_guard@@GLIBC_2.17`, from
///   the osquery toolchain targeting an older glibc ABI baseline).
///   Ensuring `-lc` is (re-)emitted at the very end fixed an otherwise-
///   inexplicable "undefined reference ... DSO missing from command line"
///   -- a known GNU ld quirk with versioned-symbol resolution and link-line
///   ordering. `-lresolv` (needed for `__res_close`, used by the
///   dns_resolvers table) has the same problem on Linux specifically: with
///   `-Wl,--as-needed` in effect, a shared library processed before
///   anything references its symbols can get dropped from the NEEDED list
///   entirely. (macOS's own link line also references `-lresolv`, but in
///   a position that's verified working there already, so it's left
///   untouched by `collect_link_items` and not touched here.)
fn append_linux_default_linker_items(items: &mut Vec<LinkItem>, sysroot: Option<&Path>) {
    let sysroot = sysroot.expect("OSQUERY_TOOLCHAIN_SYSROOT must be known to adapt link flags");

    move_dylib_to_end(items, "c");
    move_dylib_to_end(items, "resolv");

    items.push(link_item_for_archive(
        &sysroot.join("usr/lib/libc++.a"),
        false,
    ));
    items.push(link_item_for_archive(
        &sysroot.join("usr/lib/libc++abi.a"),
        false,
    ));

    // Several osquery/third-party objects (OpenSSL's threads_pthread.c,
    // librdkafka, boost, libc++ itself, ...) were compiled by the
    // toolchain's clang targeting aarch64/x86_64 "outline atomics" -- calls
    // to helper functions like `__aarch64_ldadd4_acq_rel`/`__cas4_rel` that
    // dispatch to either LL/SC or LSE instructions at runtime based on
    // detected CPU support. These aren't GNU libatomic symbols (wrong
    // naming convention entirely); they're LLVM compiler-rt builtins,
    // which clang normally links in automatically but GCC's driver has no
    // knowledge of. Reference the toolchain's own compiler-rt archive by
    // path, again at the very end for archive-ordering reasons.
    let builtins = find_file_named(sysroot, "libclang_rt.builtins.a").unwrap_or_else(|| {
        panic!(
            "could not find libclang_rt.builtins.a under {}",
            sysroot.display()
        )
    });
    items.push(link_item_for_archive(&builtins, false));
}

/// Removes the first `Dylib(name)` item found (wherever it currently is)
/// and re-appends it at the end; if no such item exists yet, just appends
/// it. See `append_linux_default_linker_items` for why late positioning
/// matters here.
fn move_dylib_to_end(items: &mut Vec<LinkItem>, name: &str) {
    if let Some(pos) = items
        .iter()
        .position(|item| matches!(item, LinkItem::Dylib(n) if n == name))
    {
        let item = items.remove(pos);
        items.push(item);
    } else {
        items.push(LinkItem::Dylib(name.to_string()));
    }
}

fn is_osquery_main_archive(token: &str) -> bool {
    // MSVC static libraries use the bare target name + `.lib` (no `lib`
    // prefix, unlike Unix's `lib<name>.a` convention).
    let expected = if cfg!(windows) {
        "osquery_main.lib"
    } else {
        "libosquery_main.a"
    };
    Path::new(token)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == expected)
        .unwrap_or(false)
}

fn compile_shim(
    shim_dir: &Path,
    src_dir: &Path,
    cxx_compiler: &Path,
    sysroot: Option<&Path>,
    defines: &[String],
    includes: &[String],
) {
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .compiler(cxx_compiler)
        .file(shim_dir.join("shim.cpp"))
        .include(src_dir)
        .std("c++17");

    for define in defines {
        build.flag(define);
    }
    for include in includes {
        build.flag(include);
    }

    if cfg!(target_os = "linux") {
        build.flag("-stdlib=libc++");
        if let Some(sysroot) = sysroot {
            build.flag(format!("--sysroot={}", sysroot.display()));
        }
    }

    build.compile("osquery_embed_shim");
}

/// Compiles compat_stubs.cpp into its own tiny static archive, separate
/// from libosquery_embed_shim.a (see that file's doc comment for why),
/// returning the resulting archive's path so it can be appended to the end
/// of the link item list explicitly rather than left to Cargo's own (early)
/// placement.
fn compile_compat_stubs(shim_dir: &Path, cxx_compiler: &Path) -> PathBuf {
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file(shim_dir.join("compat_stubs.cpp"))
        .std("c++17");
    if !cfg!(windows) {
        // On non-Windows we already resolved the exact compiler CMake used
        // (matters for ABI consistency, see compile_shim); on Windows,
        // let `cc` use its own MSVC (cl.exe) auto-detection rather than
        // pointing at the path harvested from CMakeCache.txt, since that
        // detection also sets up the MSVC-flavored argument style `cc`
        // needs internally.
        build.compiler(cxx_compiler);
    }
    build.compile("osquery_embed_compat_stubs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    if cfg!(windows) {
        out_dir.join("osquery_embed_compat_stubs.lib")
    } else {
        out_dir.join("libosquery_embed_compat_stubs.a")
    }
}

/// Parses `CXX_DEFINES`/`CXX_INCLUDES` out of a target's CMake-generated
/// `flags.make` (Makefiles generator), returning each as a standalone
/// pre-formed compiler flag (e.g. `-DFOO=1`, `-I<path>`, `-isystem`,
/// `<path>`) in original order, ready to hand to `cc::Build::flag()`.
///
/// These lines are written for consumption by `/bin/sh -c "..."` (that's
/// how `make` invokes the compiler), so they use shell quoting -- e.g.
/// `-DGFLAGS_DLL_DECLARE_FLAG=""` means "define to the empty string" (the
/// shell strips the quotes) and `-DOSQUERY_BUILD_DISTRO=\"centos7\"` means
/// "define to the 8-character string `"centos7"`" (the backslash-escaped
/// quotes become literal quote characters once the shell unescapes them).
/// We invoke the compiler directly via `Command`/`cc::Build`, bypassing the
/// shell entirely, so naive whitespace-splitting would pass those quote
/// characters through literally and corrupt the values -- must do the same
/// shell-word unescaping a real shell would.
fn read_target_compile_flags(build_dir: &Path, target: &str) -> Option<(Vec<String>, Vec<String>)> {
    let dir = find_target_dir(build_dir, target)?;
    let flags_make = dir.join("flags.make");
    let contents = fs::read_to_string(&flags_make).ok()?;

    let mut defines = Vec::new();
    let mut includes = Vec::new();
    for line in contents.lines() {
        if let Some(v) = line.strip_prefix("CXX_DEFINES = ") {
            defines = shlex::split(v).unwrap_or_else(|| panic!("failed to parse CXX_DEFINES: {v}"));
        } else if let Some(v) = line.strip_prefix("CXX_INCLUDES = ") {
            includes =
                shlex::split(v).unwrap_or_else(|| panic!("failed to parse CXX_INCLUDES: {v}"));
        }
    }
    Some((defines, includes))
}

fn find_file_named(root: &Path, name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_named(&path, name) {
                return Some(found);
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some(name) {
            return Some(path);
        }
    }
    None
}

