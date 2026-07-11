//! Builds the vendored osquery tree (as its own top-level CMake project,
//! exactly as osquery's own docs describe -- NOT wrapped via
//! `add_subdirectory()`, since osquery's CMakeLists.txt assumes it IS the
//! top-level project via `CMAKE_SOURCE_DIR`-relative includes), then
//! harvests the real, fully-resolved link line CMake generated for the
//! `osqueryd` executable target.
//!
//! That link line already contains, in the correct order, every third-party
//! and osquery-internal static library `osqueryd` needs -- including the
//! `-Wl,--whole-archive`/`-force_load` sequences osquery's own
//! `enableLinkWholeArchive()` CMake helper already applies to every
//! table/plugin target that registers itself via static initializers. We
//! reuse it verbatim, with one exception: the single archive built from
//! `osquery/main/{main,posix/main}.cpp` (the `osquery_main` target) is
//! dropped, because that's the one translation unit that defines the
//! process's real `main()`/`wmain()` -- linking it would collide with the
//! Rust binary's own entry point. Everything else in `osquery_main`'s
//! dependency graph is a leaf library with no competing `main`, so dropping
//! only that one archive is safe.
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

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .expect("osquery-sys manifest dir has no parent")
        .to_path_buf();
    let vendor_dir = workspace_root.join("vendor/osquery");
    let shim_dir = manifest_dir.join("shim");

    if !vendor_dir.join("CMakeLists.txt").exists() {
        panic!(
            "vendor/osquery is missing or empty at {}. Run \
             `git submodule update --init --recursive` in the workspace root first.",
            vendor_dir.display()
        );
    }

    // vendor/osquery is a git submodule (of a submodule, several levels
    // deep for its own vendored third-party sources) -- submodules only
    // record a pinned commit, not working-tree edits, so a local patch
    // applied by hand to a file under vendor/ does NOT survive a fresh
    // clone/checkout (including CI). Apply it here instead, idempotently,
    // so a plain `cargo build` is reproducible from scratch.
    apply_local_patches(&vendor_dir);

    // osquery's own build takes a very long time (fetches and compiles
    // dozens of third-party dependencies plus its own large codebase) and is
    // NOT something we want to redo inside a fresh OUT_DIR on every cargo
    // invocation. Persist it in a stable location, overridable for CI.
    let build_dir = env::var_os("OSQUERY_SYS_BUILD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("build/osquery"));

    let osqueryd_path = find_osqueryd(&build_dir);
    if osqueryd_path.is_none() {
        configure_and_build(&vendor_dir, &build_dir);
    }
    let osqueryd_path =
        find_osqueryd(&build_dir).expect("osqueryd was not produced by the configured build");
    let link_txt_path = find_link_txt(&build_dir, "osqueryd")
        .expect("could not find osqueryd's CMake-generated link.txt");

    let link_line = fs::read_to_string(&link_txt_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", link_txt_path.display()));

    let (cxx_compiler, sysroot) = read_cmake_cache_compiler(&build_dir);

    // CMake's Makefile generator runs link.txt with its CWD set to the
    // target's own build directory (three levels above link.txt: strip
    // `CMakeFiles/<target>.dir/link.txt`) -- most of the archive paths in
    // it are relative to THAT, not to whatever directory cargo eventually
    // invokes the linker from. Resolve them to absolute paths now.
    let link_cwd = link_txt_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("{} has an unexpectedly shallow path", link_txt_path.display()))
        .to_path_buf();

    let mut filtered = filter_link_tokens(&link_line, &osqueryd_path, &link_cwd);
    if cfg!(target_os = "linux") {
        filtered = adapt_tokens_for_default_linker(filtered, sysroot.as_deref());
    }
    // Must come after adapt_tokens_for_default_linker (which itself appends
    // libc++/libc++abi/compiler-rt at the end) so this is truly last --
    // see compat_stubs.cpp for why it needs to be.
    filtered.push(
        compile_compat_stubs(&shim_dir, &cxx_compiler)
            .to_string_lossy()
            .into_owned(),
    );

    // NOTE: this crate's own targets don't need this list linked (osquery-sys
    // has no binaries/tests of its own that call into osquery), so we don't
    // emit it via `cargo:rustc-link-arg` here -- that instruction only
    // applies to the CURRENT package's own binary/test/example targets, not
    // to downstream crates that merely depend on this one (see
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-arg).
    // Since the `osquery` crate's test binary (and eventually any
    // application embedding it) is what actually needs these on its link
    // line, relay them via the `links`-metadata mechanism instead: emit as
    // plain `cargo:KEY=VALUE` (not `cargo:rustc-...`), which Cargo exposes to
    // *direct* dependents' build scripts as `DEP_OSQUERY_EMBED_SHIM_KEY` env
    // vars (derived from this crate's `links = "osquery_embed_shim"`). The
    // `osquery` crate's build.rs reads that and re-emits it as its own
    // `cargo:rustc-link-arg`, which DOES apply to its test/lib consumers.
    println!("cargo:link_args={}", filtered.join("\u{1f}"));

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
        &vendor_dir,
        &cxx_compiler,
        sysroot.as_deref(),
        &defines,
        &includes,
    );

    println!("cargo:rerun-if-changed={}", shim_dir.join("shim.h").display());
    println!("cargo:rerun-if-changed={}", shim_dir.join("shim.cpp").display());
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join(".gitmodules").display()
    );
}

/// Applies known local patches to the vendored osquery tree, each
/// idempotent (checks for a marker before touching the file) so re-running
/// build.rs never double-patches. Patch the file content directly in Rust
/// rather than shelling out to `git apply`/`patch`: it's one small, known
/// change, and avoids depending on an external tool being present/behaving
/// identically across Linux/macOS/Windows.
fn apply_local_patches(vendor_dir: &Path) {
    patch_boost_mpl_enum_constexpr_conversion(vendor_dir);
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
fn patch_boost_mpl_enum_constexpr_conversion(vendor_dir: &Path) {
    let path = vendor_dir.join(
        "libraries/cmake/source/boost/src/libs/mpl/include/boost/mpl/aux_/integral_wrapper.hpp",
    );
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

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

fn find_link_txt(build_dir: &Path, target: &str) -> Option<PathBuf> {
    let dir_name = format!("{target}.dir");
    find_file_in_dir_named(build_dir, &dir_name, "link.txt")
}

fn configure_and_build(vendor_dir: &Path, build_dir: &Path) {
    fs::create_dir_all(build_dir).expect("failed to create osquery build directory");

    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(vendor_dir)
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

    run(&mut configure, "cmake configure");

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

    (
        compiler.unwrap_or_else(|| PathBuf::from("c++")),
        sysroot,
    )
}

/// Strips the compiler/linker invocation, the output-file flag, all object
/// files, and the one archive containing osquery_main's competing
/// `main()`/`wmain()`, keeping every other token (library archives, `-l`,
/// `-L`, `-framework`, `-Wl,--whole-archive`/`--no-whole-archive`/
/// `-force_load`/`/WHOLEARCHIVE:`, etc.) in the original order. Non-flag
/// tokens (archive paths) that are relative are resolved against
/// `link_cwd` -- CMake generates most of them relative to the directory it
/// originally ran the link command from, which is not where cargo will
/// eventually invoke the linker from.
///
/// Handles both GNU-style (Unix Makefiles: `-o <path>`, `.o`, `.a`) and
/// MSVC-style (NMake Makefiles: `/OUT:<path>`, `.obj`, `.lib`,
/// `/WHOLEARCHIVE:<path>` as a single combined token) link-line syntax.
/// MSVC link commands can also reference a `@<file>.rsp` response file
/// instead of listing everything inline (a real possibility for a
/// dependency graph this large, given Windows' command-line length
/// limits) -- expanded transparently before the main token walk.
fn filter_link_tokens(link_line: &str, osqueryd_path: &Path, link_cwd: &Path) -> Vec<String> {
    let tokens = expand_response_files(
        link_line.split_whitespace().map(str::to_string).collect(),
        link_cwd,
    );
    let mut out = Vec::new();
    let mut i = 0;
    // token 0 is the compiler/linker driver itself.
    if !tokens.is_empty() {
        i = 1;
    }
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if cfg!(windows) {
            if tok.starts_with("/OUT:") {
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
                out.push(format!("/WHOLEARCHIVE:{resolved}"));
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
            if tok.ends_with(".a") && is_osquery_main_archive(tok) {
                i += 1;
                continue;
            }
            // Two-token flags whose second token is a bare name (arch,
            // framework name, ...), NOT a path -- must be passed through
            // unresolved. Missing this for `-arch` caused
            // `resolve_token_path` to "helpfully" treat a bare `arm64` as
            // a relative path and mangle it into
            // `<link_cwd>/arm64`, which clang then rejected as an invalid
            // arch name. ld64 (macOS) uses many of these; Linux's ld
            // doesn't take `-arch`/`-framework` at all, so this is a
            // no-op there regardless of the OS check being unconditional.
            if matches!(tok, "-arch" | "-framework" | "-weak_framework") && i + 1 < tokens.len() {
                out.push(tok.to_string());
                out.push(tokens[i + 1].clone());
                i += 2;
                continue;
            }
        }
        let _ = osqueryd_path; // reserved for future path-based filtering
        out.push(resolve_token_path(tok, link_cwd));
        i += 1;
    }
    out
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
            let contents = fs::read_to_string(&resolved)
                .unwrap_or_else(|e| panic!("failed to read response file {}: {e}", resolved.display()));
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
/// driver (e.g. `-stdlib=libc++`, bare `--no-undefined`, `--sysroot=...`).
/// We deliberately do NOT force rustc to use that clang++ as its own linker
/// driver globally (via .cargo/config.toml) -- that broke linking for every
/// unrelated build-script/proc-macro binary in the workspace, since the
/// osquery-toolchain sysroot lacks the system's own gcc runtime bits (e.g.
/// `-lgcc_s`) that all those other, unrelated links still need. Instead,
/// keep the default system linker driver for everything and translate the
/// handful of clang/toolchain-only pieces to ones that work with the
/// system's real glibc/gcc:
/// - `-stdlib=libc++` (a driver convenience flag with no GCC equivalent) and
///   the plain `-lc++abi` token become explicit absolute paths to the
///   toolchain's libc++/libc++abi archives -- NOT `-lc++`/`-lc++abi` plus an
///   added `-L` to the toolchain's lib dir, because that directory also
///   contains the toolchain's own (CentOS7-targeted, per
///   `OSQUERY_BUILD_DISTRO="centos7"` in its CXX_DEFINES) `libpthread`
///   stub, whose linker script hard-codes `/lib64/...` paths that don't
///   exist on this (Ubuntu, non-multilib) system. Adding that directory to
///   the search path let `-lpthread` resolve to that broken stub instead of
///   the system's real libpthread. Referencing libc++/libc++abi by exact
///   path sidesteps the whole-directory search entirely. They're also
///   moved to the very END of the link line (not left in their original,
///   early position) -- GNU ld processes static archives in one left-to-
///   right pass, only pulling in members that resolve an outstanding
///   undefined symbol at that point; with libc++/libc++abi listed before
///   the hundreds of osquery/third-party archives that actually reference
///   `operator new`/`operator delete`/`vtable for __cxxabiv1::...`/etc.,
///   nothing had asked for those symbols yet and they were silently
///   dropped, surfacing as undefined references much later.
/// - bare `--no-undefined` is dropped entirely rather than translated to
///   `-Wl,--no-undefined`: osquery's own build uses it because everything
///   in *that* link consistently comes from the same toolchain/sysroot, so
///   strict undefined-symbol checking at link time is meaningful there. In
///   our mixed link (toolchain-compiled osquery objects against the host's
///   real system glibc), strict checking surfaced glibc symbol-versioning
///   noise (`__stack_chk_guard@@GLIBC_2.17`) that resolves fine at runtime
///   through the system's actual dynamic linker/libc -- this is exactly
///   the kind of forward-compatible resolution symbol versioning exists
///   for, and it isn't something we need link-time strictness to police
///   for a final executable (as opposed to a shared library).
/// - `--sysroot=<toolchain>` is dropped entirely: it would redirect `-lc`/
///   `-lgcc_s`/etc. resolution into the toolchain's bundled (older) glibc
///   instead of the system glibc that Rust's own std library was actually
///   linked against, which produced real symbol-version mismatches
///   (`undefined reference to '__stack_chk_guard@@GLIBC_2.17'`) when tried.
fn adapt_tokens_for_default_linker(tokens: Vec<String>, sysroot: Option<&Path>) -> Vec<String> {
    let sysroot = sysroot.expect("OSQUERY_TOOLCHAIN_SYSROOT must be known to adapt link flags");
    let libcxx = sysroot.join("usr/lib/libc++.a").to_string_lossy().into_owned();
    let libcxxabi = sysroot
        .join("usr/lib/libc++abi.a")
        .to_string_lossy()
        .into_owned();

    let mut out = Vec::with_capacity(tokens.len());
    for tok in tokens {
        if tok == "-stdlib=libc++" || tok == "-lc++abi" {
            // dropped here; re-added at the end, see doc comment above
        } else if tok == "--no-undefined" {
            // dropped, see doc comment above
        } else if tok.starts_with("--sysroot=") {
            // dropped, see doc comment above
        } else if tok == "-lresolv" {
            // dropped here; re-added at the end, see doc comment below --
            // same `--as-needed` + early-position problem as `-lc`.
        } else {
            out.push(tok);
        }
    }
    // rustc's own default link args put `-lc` (libc.so) early, before any
    // of the whole-archive osquery objects that reference versioned glibc
    // symbols (e.g. `__stack_chk_guard@@GLIBC_2.17`, from the osquery
    // toolchain targeting an older glibc ABI baseline). Re-listing `-lc`
    // at the very end fixed an otherwise-inexplicable "undefined reference
    // ... DSO missing from command line" -- a known GNU ld quirk with
    // versioned-symbol resolution and link-line ordering. `-lresolv`
    // (needed for `__res_close`, used by the dns_resolvers table) has the
    // same problem: with `-Wl,--as-needed` in effect, a shared library
    // processed before anything references its symbols can get dropped
    // from the NEEDED list entirely, so it's re-listed at the end too.
    out.push("-lc".to_string());
    out.push("-lresolv".to_string());
    // libc++/libc++abi belong at the very end too, for the same
    // archive-ordering reason (see doc comment above).
    out.push(libcxx);
    out.push(libcxxabi);
    // Several osquery/third-party objects (OpenSSL's threads_pthread.c,
    // librdkafka, boost, libc++ itself, ...) were compiled by the
    // toolchain's clang targeting aarch64 "outline atomics" -- calls to
    // helper functions like `__aarch64_ldadd4_acq_rel`/`__aarch64_cas4_rel`
    // that dispatch to either LL/SC or LSE instructions at runtime based on
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
    out.push(builtins.to_string_lossy().into_owned());
    out
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
    vendor_dir: &Path,
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
        .include(vendor_dir)
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
/// of the link line explicitly rather than left to Cargo's own (early)
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
    let dir_name = format!("{target}.dir");
    let flags_make = find_file_in_dir_named(build_dir, &dir_name, "flags.make")?;
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

fn find_file_in_dir_named(root: &Path, dir_name: &str, file_name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some(dir_name) {
                let candidate = path.join(file_name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
            if let Some(found) = find_file_in_dir_named(&path, dir_name, file_name) {
                return Some(found);
            }
        }
    }
    None
}
