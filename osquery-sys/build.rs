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

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::ops::Add;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Pinned osquery release. Bump deliberately -- this is the single source
/// of truth for which version gets built (there is no vendored submodule
/// pin to keep in sync with anymore). Changing it changes the default
/// source/build cache paths too (see `main`), so a version bump naturally
/// gets a fresh build rather than reusing a stale cache.
const OSQUERY_TAG: &str = "5.23.1";
const OSQUERY_REPO_URL: &str = "https://github.com/osquery/osquery.git";

/// Target triples this crate ships a prebuilt bundle for -- exactly the
/// four target triples `.github/workflows/release.yml` builds. Anything
/// else (e.g. `x86_64-apple-darwin`, `aarch64-unknown-linux-musl`)
/// automatically routes to the from-source path in `main`, extended by
/// adding a new CI job and appending its target triple here, nothing else.
const PREBUILT_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

/// This crate's own repo -- where `release.yml` uploads prebuilt bundles as
/// GitHub Release assets under tag `v<CARGO_PKG_VERSION>`. Deliberately not
/// an env-var override: an attacker able to redirect this could serve a
/// malicious artifact *and* a matching hash together, defeating the whole
/// point of `PREBUILT_CHECKSUMS` living in the crate's own committed source
/// instead of being fetched over the network.
const RELEASE_REPO: &str = "https://github.com/BeryJu/osquery-rs";

/// Expected SHA-256 of each target's prebuilt bundle, baked into the
/// compiled build script at compile time via `include_str!` -- meaning the
/// expected hash ships inside the exact same crates.io-published source
/// tree as the verification code itself, with zero network round-trips to
/// fetch it. An attacker who compromises only the GitHub Release asset
/// can't forge a matching entry here. See `prebuilt-checksums.v1` and
/// `.github/workflows/release.yml` for how this file gets populated.
const PREBUILT_CHECKSUMS: &str = include_str!("prebuilt-checksums.v1");

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

    // Default path: download a prebuilt bundle from this repo's GitHub
    // Releases instead of building osquery from source, which can take
    // multiple hours. See `try_prebuilt` for the full fallback decision
    // tree -- this only returns `FallBack` (rather than exiting) when
    // there's a real reason to fall through to the from-source path below,
    // logging a `cargo:warning` explaining why in every such case.
    if env::var_os("OSQUERY_SYS_FORCE_SOURCE_BUILD").is_none() {
        match try_prebuilt(&cache_root, &src_dir, &shim_dir) {
            PrebuiltAttempt::Used => return,
            PrebuiltAttempt::FallBack(reason) => {
                println!(
                    "cargo:warning=osquery-sys: {reason} -- falling back to a from-source \
                     build, which can take multiple hours. Set \
                     OSQUERY_SYS_FORCE_SOURCE_BUILD=1 to skip the prebuilt download attempt \
                     entirely on future builds."
                );
            }
        }
    }

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

    // If OSQUERY_SYS_PACKAGE_DIR is set (only ever done by the release CI
    // workflow), stage a prebuilt bundle from exactly this build's outputs
    // *before* compat_stubs gets appended below -- a consumer's build.rs
    // recompiles compat_stubs (and the rest of the shim) fresh locally
    // every time regardless of whether it took the prebuilt path, so the
    // packaged manifest shouldn't include it.
    if let Some(package_dir) = env::var_os("OSQUERY_SYS_PACKAGE_DIR") {
        stage_prebuilt_package(
            Path::new(&package_dir),
            &items,
            &cxx_compiler,
            sysroot.as_deref(),
            &defines,
            &includes,
            &src_dir,
            &build_dir,
        );
    }

    // Must come after append_linux_default_linker_items (which itself
    // appends libc++/libc++abi/compiler-rt) so this is truly last -- see
    // compat_stubs.cpp for why it needs to be.
    items.push(link_item_for_archive(
        &compile_compat_stubs(&shim_dir, &cxx_compiler),
        false,
    ));
    // Applied after compat_stubs is pushed (not before, as an earlier
    // version of this workaround did) -- see force_whole_archive_workaround's
    // own doc comment for why compat_stubs specifically needs
    // .cargo_metadata(false) on its cc::Build for this to be safe.
    force_whole_archive_workaround(&mut items);

    emit_link_items(&items);

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

enum PrebuiltAttempt {
    Used,
    FallBack(String),
}

/// Attempts the default, fast path: download a prebuilt bundle for the
/// current target from this repo's GitHub Releases instead of building
/// osquery from source (which can take multiple hours). Every `FallBack`
/// case is a deliberate, named condition -- see the summary table:
///
/// | Condition                                    | Action                          |
/// |-----------------------------------------------|--------------------------------|
/// | `OSQUERY_SYS_FORCE_SOURCE_BUILD` set          | never calls this function at all |
/// | `TARGET` not in `PREBUILT_TARGETS`            | `FallBack`, informational       |
/// | No checksum entry for this target yet         | `FallBack`, informational (not a hard error -- see below) |
/// | Download network/HTTP failure                 | `FallBack`, loud warning         |
/// | Checksum mismatch                              | hard `panic!`, no fallback       |
/// | Extraction (`tar`) failure                     | `FallBack`, loud warning         |
/// | Success                                        | `Used`                          |
///
/// The "no checksum entry yet" case deliberately falls back rather than
/// hard-erroring (unlike a genuine mismatch): `prebuilt-checksums.v1` starts
/// out with no real entries at all until the first tagged release's CI run
/// populates it, and hard-erroring every build until then would make the
/// crate unusable during that bootstrap window -- "no prebuilt published
/// yet for this version" isn't a release-process bug the way a checksum
/// mismatch against a *recorded* hash would be.
fn try_prebuilt(cache_root: &Path, src_dir: &Path, shim_dir: &Path) -> PrebuiltAttempt {
    let target = env::var("TARGET").expect("TARGET not set by cargo");
    if !PREBUILT_TARGETS.contains(&target.as_str()) {
        return PrebuiltAttempt::FallBack(format!("no prebuilt bundle exists for target {target}"));
    }

    let version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set by cargo");
    let bundle_dir = cache_root.join(format!("prebuilt-{version}-{target}"));

    if !bundle_dir.join("manifest.v1").exists() {
        if let Err(reason) = download_and_verify_bundle(&target, &version, &bundle_dir) {
            return PrebuiltAttempt::FallBack(reason);
        }
    }

    // The shim's own `#include <osquery/...>` headers still need a real
    // source checkout to resolve against -- just the lightweight top-level
    // clone (seconds), not the CMake configure+build of it (hours), which
    // is the actual cost this path exists to skip.
    ensure_osquery_source(src_dir);

    let manifest_path = bundle_dir.join("manifest.v1");
    let manifest_text = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("failed to read cached {}: {e}", manifest_path.display()));
    let manifest = parse_manifest(&manifest_text, &bundle_dir);

    // See append_linux_default_linker_items's comment for why this must be
    // printed before anything that -L's the toolchain's own sysroot.
    if env::var("TARGET").as_deref() == Ok("aarch64-unknown-linux-gnu") {
        println!("cargo:rustc-link-search=native=/usr/lib64");
    }

    let mut items = manifest.items;
    // Recompiled fresh locally every time, prebuilt path or not -- see
    // stage_prebuilt_package's own doc comment for why this (and the rest
    // of the shim) is never itself part of the bundle.
    items.push(link_item_for_archive(
        &compile_compat_stubs(shim_dir, &manifest.cxx_compiler),
        false,
    ));
    force_whole_archive_workaround(&mut items);
    emit_link_items(&items);

    compile_shim(
        shim_dir,
        src_dir,
        &manifest.cxx_compiler,
        manifest.sysroot.as_deref(),
        &manifest.cxx_defines,
        &manifest.cxx_includes,
    );

    println!("cargo:rerun-if-changed={}", shim_dir.join("shim.h").display());
    println!("cargo:rerun-if-changed={}", shim_dir.join("shim.cpp").display());
    println!(
        "cargo:rerun-if-changed={}",
        shim_dir.join("compat_stubs.cpp").display()
    );

    PrebuiltAttempt::Used
}

/// Downloads, verifies, and extracts the prebuilt bundle for `target` into
/// `bundle_dir`. Returns `Err(reason)` for anything that should fall back
/// to a from-source build (network/HTTP failure, extraction failure) --
/// panics directly instead (no fallback) for a checksum mismatch, which is
/// a real integrity concern rather than an environment condition. See
/// `try_prebuilt`'s doc comment for the full reasoning on why these two
/// failure classes are treated differently.
fn download_and_verify_bundle(target: &str, version: &str, bundle_dir: &Path) -> Result<(), String> {
    let checksums = parse_prebuilt_checksums();
    let Some(expected_hash) = checksums.get(target) else {
        return Err(format!(
            "no prebuilt bundle has been published yet for target {target} at version {version}"
        ));
    };

    let url = format!(
        "{RELEASE_REPO}/releases/download/v{version}/osquery-sys-{version}-{target}.tar.zst"
    );
    let response = ureq::get(&url)
        .call()
        .map_err(|e| format!("failed to download prebuilt bundle from {url}: {e}"))?;

    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read downloaded bundle from {url}: {e}"))?;

    let actual_hash = sha256_hex(&bytes);
    if &actual_hash != expected_hash {
        panic!(
            "osquery-sys: downloaded prebuilt bundle for {target} does not match its recorded \
             checksum (expected {expected_hash}, got {actual_hash}) -- refusing to use it. This \
             could mean a corrupted download, or (much less likely) a compromised release \
             asset; either way, verify {url} manually before proceeding. Set \
             OSQUERY_SYS_FORCE_SOURCE_BUILD=1 to build from source instead."
        );
    }

    fs::create_dir_all(bundle_dir)
        .map_err(|e| format!("failed to create {}: {e}", bundle_dir.display()))?;

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let archive_path = out_dir.join(format!("osquery-sys-{version}-{target}.tar.zst"));
    fs::write(&archive_path, &bytes)
        .map_err(|e| format!("failed to write downloaded bundle to {}: {e}", archive_path.display()))?;

    let mut tar = Command::new("tar");
    tar.arg("--zstd")
        .arg("-xf")
        .arg(&archive_path)
        .arg("-C")
        .arg(bundle_dir);
    let status = tar
        .status()
        .map_err(|e| format!("failed to spawn tar to extract prebuilt bundle: {e}"))?;
    let _ = fs::remove_file(&archive_path);
    if !status.success() {
        return Err(format!("tar extraction of prebuilt bundle failed with {status}"));
    }

    Ok(())
}

/// Parses the embedded `PREBUILT_CHECKSUMS` (`prebuilt-checksums.v1`) into a
/// `target -> expected sha256 hex` map. Tab-separated, `#`-prefixed comment
/// lines ignored -- see that file's own header for the full format
/// rationale and how it gets populated.
fn parse_prebuilt_checksums() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in PREBUILT_CHECKSUMS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('\t');
        if let (Some(target), Some(hash)) = (fields.next(), fields.next()) {
            map.insert(target.to_string(), hash.to_string());
        }
    }
    map
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The parsed contents of a prebuilt bundle's `manifest.v1` -- see
/// `stage_prebuilt_package` for the exact format this reads, written by the
/// same build.rs (under `OSQUERY_SYS_PACKAGE_DIR`) that produced the bundle
/// in the first place.
struct PrebuiltManifest {
    cxx_compiler: PathBuf,
    sysroot: Option<PathBuf>,
    cxx_defines: Vec<String>,
    cxx_includes: Vec<String>,
    items: Vec<LinkItem>,
}

fn parse_manifest(contents: &str, bundle_dir: &Path) -> PrebuiltManifest {
    let lib_dir = bundle_dir.join("lib");
    let mut cxx_compiler = None;
    let mut sysroot = None;
    let mut cxx_defines = Vec::new();
    let mut cxx_includes = Vec::new();
    let mut items = Vec::new();

    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("# cxx_compiler=") {
            cxx_compiler = Some(PathBuf::from(rest));
        } else if let Some(rest) = line.strip_prefix("# sysroot=") {
            if !rest.is_empty() {
                sysroot = Some(PathBuf::from(rest));
            }
        } else if let Some(rest) = line.strip_prefix("# cxx_defines=") {
            cxx_defines = rest
                .split('\t')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
        } else if let Some(rest) = line.strip_prefix("# cxx_includes=") {
            cxx_includes = rest
                .split('\t')
                .filter(|s| !s.is_empty())
                .map(|s| rejoin_bundle_include_token(s, bundle_dir))
                .collect();
        } else if line.starts_with('#') || line.trim().is_empty() {
            continue;
        } else {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 3 {
                panic!("malformed manifest.v1 line (expected 3 tab-separated fields): {line:?}");
            }
            let (kind, name, whole_archive_or_dash) = (fields[0], fields[1], fields[2]);
            let item = match kind {
                "STATICLIB" => LinkItem::StaticLib {
                    dir: lib_dir.clone(),
                    name: name.to_string(),
                    whole_archive: whole_archive_or_dash == "whole_archive",
                },
                "DYLIB" => LinkItem::Dylib(name.to_string()),
                "FRAMEWORK" => LinkItem::Framework(name.to_string()),
                other => panic!("unknown manifest.v1 item kind {other:?} in line: {line:?}"),
            };
            items.push(item);
        }
    }

    PrebuiltManifest {
        cxx_compiler: cxx_compiler
            .unwrap_or_else(|| panic!("manifest.v1 missing cxx_compiler header")),
        sysroot,
        cxx_defines,
        cxx_includes,
        items,
    }
}

/// Stages a prebuilt bundle from this build's own already-computed outputs
/// into `package_dir`, when `OSQUERY_SYS_PACKAGE_DIR` is set (only ever
/// done by `.github/workflows/release.yml`, never by a normal consumer
/// build). Copies each `StaticLib` item's real archive file into a flat
/// `package_dir/lib/` directory and writes `manifest.v1` describing every
/// item in the exact order `emit_link_items` would emit them (order is
/// load-bearing -- see that function's own doc comment).
///
/// Deliberately does NOT invoke `tar`/compute a checksum/upload anything --
/// that stays entirely in `release.yml`'s own steps, visible and auditable
/// there rather than hidden inside a build script side effect. This
/// function's only job is "materialize a plain directory of files + a
/// manifest describing them."
///
/// Also deliberately does NOT bundle the shim's own compiled archives
/// (`libosquery_embed_shim.a`, `libosquery_embed_compat_stubs.a`/.lib) --
/// those get recompiled fresh, locally, on every consumer build regardless
/// of whether the prebuilt path was used, both because it's fast (a
/// handful of small files via the ordinary `cc` crate) and because a
/// prebuilt shim archive could have an ABI mismatch against whatever
/// compiler the consumer's own `cc` crate auto-detects.
fn stage_prebuilt_package(
    package_dir: &Path,
    items: &[LinkItem],
    cxx_compiler: &Path,
    sysroot: Option<&Path>,
    defines: &[String],
    includes: &[String],
    src_dir: &Path,
    build_dir: &Path,
) {
    let lib_dir = package_dir.join("lib");
    fs::create_dir_all(&lib_dir).unwrap_or_else(|e| panic!("failed to create {}: {e}", lib_dir.display()));
    let bundle_include_dir = package_dir.join("include");

    // `includes` alternates "-Ipath" single tokens with "-isystem"/"path"
    // token *pairs* (confirmed directly from real manifest.v1 content) --
    // walk with an explicit cursor rather than `.map()` so a pair's two
    // tokens are classified/dropped together. Every path gets bundled
    // (see bundle_include_path) rather than staying a raw absolute path
    // from this machine, which a consumer could never resolve.
    let mut copied_include_dirs: HashSet<PathBuf> = HashSet::new();
    let mut rewritten_includes: Vec<String> = Vec::new();
    let mut i = 0;
    while i < includes.len() {
        let tok = includes[i].as_str();
        if tok == "-isystem" {
            let path_str = includes
                .get(i + 1)
                .unwrap_or_else(|| panic!("dangling -isystem with no following path in cxx_includes"));
            if let Some(rewritten) = bundle_include_path(
                path_str,
                src_dir,
                build_dir,
                &bundle_include_dir,
                &mut copied_include_dirs,
            ) {
                rewritten_includes.push("-isystem".to_string());
                rewritten_includes.push(rewritten);
            }
            i += 2;
        } else if let Some(path_str) = tok.strip_prefix("-I") {
            if let Some(rewritten) = bundle_include_path(
                path_str,
                src_dir,
                build_dir,
                &bundle_include_dir,
                &mut copied_include_dirs,
            ) {
                rewritten_includes.push(format!("-I{rewritten}"));
            }
            i += 1;
        } else {
            // Unrecognized token shape -- keep as-is defensively.
            rewritten_includes.push(tok.to_string());
            i += 1;
        }
    }

    let mut manifest = String::new();
    manifest.push_str("# osquery-sys prebuilt bundle manifest, schema v1\n");
    manifest.push_str(&format!("# osquery_tag={OSQUERY_TAG}\n"));
    manifest.push_str(&format!("# cxx_compiler={}\n", cxx_compiler.display()));
    manifest.push_str(&format!(
        "# sysroot={}\n",
        sysroot.map(|p| p.display().to_string()).unwrap_or_default()
    ));
    // cxx_defines are all `-DNAME[=value]` flags (audited directly against
    // real manifest content) -- never filesystem paths, so unlike
    // cxx_includes below, these need no rewriting.
    manifest.push_str(&format!("# cxx_defines={}\n", defines.join("\t")));
    manifest.push_str(&format!("# cxx_includes={}\n", rewritten_includes.join("\t")));

    let mut used_names: HashSet<String> = HashSet::new();
    for item in items {
        match item {
            LinkItem::StaticLib {
                dir,
                name,
                whole_archive,
            } => {
                let src_file = dir.join(archive_file_name(name));
                let final_name = if used_names.insert(name.clone()) {
                    name.clone()
                } else {
                    // A genuine name collision across different source
                    // directories (low-probability in practice, but the
                    // format accounts for it rather than silently
                    // clobbering one file with another) -- disambiguate
                    // with a short hash of the original absolute source
                    // dir, applied identically to both the copied file's
                    // name and the manifest's own NAME field, since
                    // `cargo:rustc-link-lib=static=NAME` expects a file
                    // matching NAME exactly and these must never diverge.
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    dir.hash(&mut hasher);
                    let disambiguated = format!("{name}_{:08x}", hasher.finish() & 0xffff_ffff);
                    used_names.insert(disambiguated.clone());
                    disambiguated
                };
                let dest_file = lib_dir.join(archive_file_name(&final_name));
                fs::copy(&src_file, &dest_file).unwrap_or_else(|e| {
                    panic!(
                        "failed to copy {} to {}: {e}",
                        src_file.display(),
                        dest_file.display()
                    )
                });
                let whole_archive_field = if *whole_archive { "whole_archive" } else { "plain" };
                manifest.push_str(&format!("STATICLIB\t{final_name}\t{whole_archive_field}\n"));
            }
            LinkItem::Dylib(name) => {
                manifest.push_str(&format!("DYLIB\t{name}\t-\n"));
            }
            LinkItem::Framework(name) => {
                manifest.push_str(&format!("FRAMEWORK\t{name}\t-\n"));
            }
        }
    }

    let manifest_path = package_dir.join("manifest.v1");
    fs::write(&manifest_path, manifest)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", manifest_path.display()));
}

/// The inverse of `archive_bare_name`: the platform-conventional archive
/// filename Cargo's `cargo:rustc-link-lib=static=NAME` directive expects to
/// find for a given bare `NAME` (`libNAME.a` on Unix, `NAME.lib` on
/// Windows).
fn archive_file_name(bare_name: &str) -> String {
    if cfg!(windows) {
        format!("{bare_name}.lib")
    } else {
        format!("lib{bare_name}.a")
    }
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
    run(&mut clone, "git clone osquery");
    true
}

/// Applies known local patches to the freshly cloned osquery tree, each
/// idempotent (checks for a marker before touching the file) so re-running
/// build.rs never double-patches.
fn apply_local_patches(src_dir: &Path) {
    patch_boost_mpl_enum_constexpr_conversion(src_dir);
    patch_boost_numeric_conversion_mixture_enums(src_dir);
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

/// Boost.MPL's `integral_c<EnumType, N>::prior` unconditionally computes
/// `static_cast<EnumType>(N - 1)`, including at `N == 0`. For an unscoped
/// enum without a fixed underlying type, casting an out-of-range int to it
/// in a constant expression is ill-formed per the standard; some Clang
/// versions only warn (`-Wenum-constexpr-conversion`, suppressible), but at
/// least one (a bleeding-edge Xcode beta, Apple clang 21) rejects it
/// unconditionally and doesn't even recognize that diagnostic's name, so no
/// amount of `-Wno-...`/pragma suppression helps there (this is the same
/// underlying issue `patch_boost_mpl_enum_constexpr_conversion` targets, but
/// that patch is a no-op on toolchains where the diagnostic can't be named).
/// Giving the two specific enums shim.cpp's include graph instantiates
/// through this path a fixed underlying type sidesteps the rule entirely --
/// with a fixed underlying type, the enum's valid range is the underlying
/// type's full range, so the cast is always well-formed, on every Clang.
fn patch_boost_numeric_conversion_mixture_enums(src_dir: &Path) {
    let base = src_dir.join(
        "libraries/cmake/source/boost/src/libs/numeric/conversion/include/boost/numeric/conversion",
    );
    for (file, enum_name) in [
        ("udt_builtin_mixture_enum.hpp", "udt_builtin_mixture_enum"),
        ("int_float_mixture_enum.hpp", "int_float_mixture_enum"),
    ] {
        let path = base.join(file);
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let contents = contents.replace("\r\n", "\n");

        let fixed_marker = format!("enum {enum_name} : int");
        if contents.contains(&fixed_marker) {
            continue; // already patched
        }

        let marker = format!("enum {enum_name}\n  {{");
        let replacement = format!("enum {enum_name} : int\n  {{");
        if !contents.contains(&marker) {
            panic!(
                "expected anchor text not found in {} -- osquery's vendored Boost \
                 version may have changed; update patch_boost_numeric_conversion_mixture_enums",
                path.display()
            );
        }

        let patched = contents.replacen(&marker, &replacement, 1);
        fs::write(&path, patched)
            .unwrap_or_else(|e| panic!("failed to write patched {}: {e}", path.display()));
    }
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
/// defined somewhere under the top-level `osquery/` source directory (never
/// under `libs/`, `plugins/`, or `specs/`, which hold third-party
/// dependencies and generated codegen targets instead) -- but NOT
/// necessarily directly in `osquery/CMakeLists.txt` itself. `osqueryd` is
/// (`build_dir/osquery/CMakeFiles/osqueryd.dir/`, checked as a fast path
/// below), but `osquery_core` is actually defined one level deeper, in
/// `osquery/core/CMakeLists.txt` (`build_dir/osquery/core/CMakeFiles/
/// osquery_core.dir/`) -- confirmed against osquery 5.23.1's real source
/// tree after a from-scratch `find_dir_named` fallback search (see below)
/// silently ate 3+ hours on Linux CI doing an unbounded, unpruned walk
/// across every vendored third-party dependency (boost, thrift, rocksdb,
/// sleuthkit, ...) before ever reaching the actual `osquery/core/`
/// directory it needed. Confirmed via a CI heartbeat: the build.rs process
/// itself was using ~0% CPU the whole time (i/o-bound directory walking,
/// not a stuck compiler or OOM) with 14GiB RAM still free.
///
/// Fixed two ways: the one hardcoded fast path remains (covers `osqueryd`,
/// costs one `is_dir()` stat when it doesn't apply), and the fallback walk
/// is now scoped to `build_dir/osquery/` instead of the entire `build_dir`
/// -- since every target we ever look up by name lives somewhere in that
/// subtree, this prunes out every third-party dependency's directory tree
/// entirely regardless of how deeply a future osquery version nests a
/// target we search for.
fn find_target_dir(build_dir: &Path, target: &str) -> Option<PathBuf> {
    let dir_name = format!("{target}.dir");
    let osquery_dir = build_dir.join("osquery");
    let fast_path = osquery_dir.join("CMakeFiles").join(&dir_name);
    if fast_path.is_dir() {
        return Some(fast_path);
    }
    find_dir_named(&osquery_dir, &dir_name)
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
    // Clang can OOM compiling third-party deps (boost, thrift, rocksdb) with
    // under ~8GB per core; cap parallelism conservatively by default and let
    // callers raise it. OSQUERY_SYS_CMAKE_JOBS overrides NUM_JOBS just for
    // this build, since Cargo always overwrites NUM_JOBS to match its own
    // `--jobs`/CARGO_BUILD_JOBS for every build script invocation.
    env::var("OSQUERY_SYS_CMAKE_JOBS")
        .or_else(|_| env::var("NUM_JOBS"))
        .unwrap_or_else(|_| {
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

/// WORKAROUND, not a root-cause fix: on aarch64-unknown-linux-gnu, plain
/// (non-whole-archive) `cargo:rustc-link-lib` directives never reach the
/// downstream `smoke`/`osquery` test binary's real link -- an unidentified
/// Cargo/rustc propagation gap. `+whole-archive` propagates reliably and is
/// a strictly stronger request (superset of what plain would link), so
/// forcing every static lib to it here sidesteps the bug.
///
/// Must run after compat_stubs is pushed onto `items`: see
/// `compile_compat_stubs`'s comment for why it needs a single emission path.
fn force_whole_archive_workaround(items: &mut [LinkItem]) {
    if env::var("TARGET").as_deref() != Ok("aarch64-unknown-linux-gnu") {
        return;
    }
    for item in items {
        if let LinkItem::StaticLib { whole_archive, .. } = item {
            *whole_archive = true;
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
            // `/implib:osqueryd.lib` tells link.exe to also emit an import
            // library for osqueryd.exe (so dynamically loaded extension
            // modules can link against symbols it exports) -- it's a
            // linker flag, not a library reference, but ends in `.lib` and
            // starts with `/`, so without this check it would fall through
            // to the generic `.lib` handling below. Because
            // resolve_token_path treats any `/`-prefixed token as "looks
            // like a flag" and returns it unresolved, archive_bare_name
            // would then compute a bare name from the literal string
            // `/implib:osqueryd.lib` itself (there's no real path
            // separator before `osqueryd.lib` in this bare, cwd-relative
            // token), yielding the nonsensical library name
            // `implib:osqueryd` -- which rustc then rejects with
            // "renaming of the library `implib` was specified" (the
            // trailing `:NAME` in a `-l` flag has its own, unrelated
            // meaning to rustc). Must be checked before the generic
            // `.lib` suffix check.
            if tok.get(..8).is_some_and(|p| p.eq_ignore_ascii_case("/IMPLIB:")) {
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
    dedupe_static_libs(items)
}

/// The same static archive can legitimately appear more than once in a
/// real GNU ld link line (e.g. once whole-archive-wrapped for its static
/// initializers' registration side effects, once again plainly for normal
/// symbol resolution) -- harmless for `ld` itself, since re-listing an
/// archive is a no-op once its members are already pulled in, but rustc
/// hard-errors ("overriding linking modifiers from command line is not
/// supported") if the *same* library name is passed to `-l` more than once
/// with different modifiers (`static` vs `static:+whole-archive`) in one
/// invocation. Collapse duplicates by name into a single entry, keeping
/// the *first* occurrence's position (matches the order CMake's own
/// dependency graph already resolved) and upgrading it to whole_archive if
/// *any* occurrence requested it -- whole-archive is a strictly stronger
/// request (pulls in every member instead of only ones satisfying an
/// already-undefined symbol), so OR-ing across duplicates can only ever
/// pull in a superset of what plain resolution would have.
fn dedupe_static_libs(items: Vec<LinkItem>) -> Vec<LinkItem> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<LinkItem> = Vec::with_capacity(items.len());
    for item in items {
        match item {
            LinkItem::StaticLib {
                dir,
                name,
                whole_archive,
            } => {
                if let Some(&idx) = seen.get(&name) {
                    if let LinkItem::StaticLib {
                        whole_archive: existing,
                        ..
                    } = &mut out[idx]
                    {
                        *existing |= whole_archive;
                    }
                } else {
                    seen.insert(name.clone(), out.len());
                    out.push(LinkItem::StaticLib {
                        dir,
                        name,
                        whole_archive,
                    });
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// Classifies a resolved `.lib`/`.a` path: a directory-qualified path is a
/// real static archive; a bare file name with no directory (as Windows
/// system import libraries like `kernel32.lib`/`ws2_32.lib` can appear)
/// is a dynamic/system library reference instead.
fn classify_archive_or_dylib(path: &Path) -> LinkItem {
    // Windows SDK import libraries (ntdll.lib, ole32.lib, kernel32.lib, and
    // ~30 others osquery's own link line references this way) are always
    // written as a bare `name.lib` token with no directory component,
    // relying on link.exe's own default LIB-environment-variable search
    // path -- the exact Windows equivalent of Unix's bare `-lname`, which
    // this file already treats unconditionally as a Dylib with zero path
    // resolution. But resolve_token_path (needed so *real* build-tree
    // archives like osquery_core.lib, which really are referenced by a
    // bare name relative to the link working directory, resolve
    // correctly) joins ANY non-absolute, non-flag-looking token to
    // link_cwd -- which fabricates a directory for system import libs too,
    // making the `has_dir` check below always true and misclassifying
    // them as StaticLib pointed at a directory that never actually
    // contains them. The two cases are indistinguishable from the token
    // text alone; check whether the resolved path actually exists on disk
    // instead -- a real build-tree archive does, a system import library
    // never does (link_cwd is never where the Windows SDK's own libs
    // live).
    if cfg!(windows) && !path.exists() {
        return LinkItem::Dylib(archive_bare_name(path));
    }
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
/// file and word-splitting its content (see `split_generated_flags`) in
/// place of the `@file` token.
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
            let expanded = split_generated_flags(&contents);
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

    // The toolchain's own sysroot bundles glibc-2.27-era compat shims
    // (libdl.so, librt.so, ...) in the same usr/lib dir libc++.a needs
    // `-L`'d below. GNU ld resolves `-lNAME` against whichever `-L`
    // directory lists it first, so print the host's own lib dir here,
    // before the toolchain's, or `-ldl` resolves to the toolchain's
    // ABI-mismatched copy instead (undefined @GLIBC_PRIVATE references).
    if env::var("TARGET").as_deref() == Ok("aarch64-unknown-linux-gnu") {
        println!("cargo:rustc-link-search=native=/usr/lib64");
    }

    move_dylib_to_end(items, "c");
    move_dylib_to_end(items, "resolv");

    let libcxx = sysroot.join("usr/lib/libc++.a");
    let libcxxabi = sysroot.join("usr/lib/libc++abi.a");

    // libc++.a and libc++abi.a both bundle a full copy of LLVM's libunwind,
    // normally invisible under selective linking but a "multiple
    // definition" error once force_whole_archive_workaround whole-archives
    // both on aarch64. Both copies are identical upstream source, so
    // stripping them from libc++.a (leaving libc++abi.a's) is safe.
    const LIBUNWIND_OBJECTS_DUPLICATED_IN_LIBCXX: &[&str] = &[
        "libunwind.cpp.o",
        "Unwind-EHABI.cpp.o",
        "UnwindLevel1.c.o",
        "UnwindLevel1-gcc-ext.c.o",
        "UnwindRegistersRestore.S.o",
        "UnwindRegistersSave.S.o",
        "Unwind-seh.cpp.o",
        "Unwind-sjlj.c.o",
        "Unwind-wasm.c.o",
    ];
    if env::var("TARGET").as_deref() == Ok("aarch64-unknown-linux-gnu") {
        for member in LIBUNWIND_OBJECTS_DUPLICATED_IN_LIBCXX {
            strip_archive_member_if_present(&libcxx, member);
        }
    }

    items.push(link_item_for_archive(&libcxx, false));
    items.push(link_item_for_archive(&libcxxabi, false));

    // Several objects reference "outline atomics" helpers
    // (`__aarch64_ldadd4_acq_rel` etc.) -- LLVM compiler-rt builtins that
    // clang links in automatically but GCC's driver doesn't know about.
    // Reference the toolchain's own compiler-rt archive directly.
    let builtins = find_file_named(sysroot, "libclang_rt.builtins.a").unwrap_or_else(|| {
        panic!(
            "could not find libclang_rt.builtins.a under {}",
            sysroot.display()
        )
    });
    items.push(link_item_for_archive(&builtins, false));
}

/// Deletes `member` from the archive at `archive_path` via `ar d`, checking
/// with `ar t` first since `ar d` exits non-zero for an absent member.
fn strip_archive_member_if_present(archive_path: &Path, member: &str) {
    let listing = Command::new("ar")
        .arg("t")
        .arg(archive_path)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn ar t on {}: {e}", archive_path.display()));
    if !listing.status.success() {
        panic!(
            "ar t on {} failed: {}",
            archive_path.display(),
            listing.status
        );
    }
    let present = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .any(|line| line == member);
    if !present {
        return;
    }

    let status = Command::new("ar")
        .arg("d")
        .arg(archive_path)
        .arg(member)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn ar d to strip {member} from {}: {e}",
                archive_path.display()
            )
        });
    if !status.success() {
        panic!(
            "ar d failed to strip {member} from {}: {status}",
            archive_path.display()
        );
    }
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

    if cfg!(target_os = "macos") {
        // shim.cpp transitively includes boost/mpl (via osquery/utils/expected/
        // expected.h -> boost::variant) the same way osquery_core itself does --
        // osquery's own libraries/cmake/source/boost/CMakeLists.txt already
        // works around this exact issue ("silence enum constexpr conversion for
        // MPL on Xcode 26") via a `target_compile_options(thirdparty_boost_mpl
        // INTERFACE -Wno-enum-constexpr-conversion)`, an INTERFACE flag that
        // only propagates to CMake targets linking against thirdparty_boost_mpl
        // -- osquery_core's own flags.make (what `defines`/`includes` above are
        // harvested from) only ever captures `-D`/`-I`/`-isystem` tokens, so
        // this `-W...` flag never reaches shim.cpp's own compile even when
        // present there. Boost.MPL/NumericConversion's `integral_c::prior`
        // computes `value - 1` as an always-instantiated (never actually used)
        // intermediate type at the enum's first value, producing an
        // out-of-range enum cast; newer Clang (this diagnostic's name dates it
        // to roughly Xcode 15+) treats that as ill-formed in a constant
        // expression. Mirror osquery's own fix directly here rather than
        // generalizing flag extraction to capture arbitrary `-W...` tokens
        // from flags.make, which risks pulling in other, unrelated flags too.
        build.flag("-Wno-enum-constexpr-conversion");
    }

    build.compile("osquery_embed_shim");
}

/// Compiles compat_stubs.cpp into its own tiny static archive, separate
/// from libosquery_embed_shim.a (see that file's doc comment for why),
/// returning its path so the caller can append it to the link item list
/// explicitly rather than leave it to Cargo's own (early) placement.
///
/// `.cargo_metadata(false)` suppresses `cc::Build`'s own automatic (always
/// plain) link-lib emission, so this archive has exactly one emission path
/// (the caller's explicit one) and can safely be forced to `+whole-archive`
/// -- two emissions with conflicting modifiers is a rustc hard error.
fn compile_compat_stubs(shim_dir: &Path, cxx_compiler: &Path) -> PathBuf {
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file(shim_dir.join("compat_stubs.cpp"))
        .std("c++17")
        .cargo_metadata(false);
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
/// `<path>`) in original order, ready to hand to `cc::Build::flag()`. See
/// `split_generated_flags` for how the actual tokenizing differs between
/// Unix (real `/bin/sh -c` shell-word unescaping, since that's how `make`
/// invokes the compiler there) and Windows (no shell involved at all --
/// must NOT unescape backslashes, since those are literal path separators
/// MSVC's own command-line parser expects unmodified).
fn read_target_compile_flags(build_dir: &Path, target: &str) -> Option<(Vec<String>, Vec<String>)> {
    let dir = find_target_dir(build_dir, target)?;
    let flags_make = dir.join("flags.make");
    let contents = fs::read_to_string(&flags_make).ok()?;

    let mut defines = Vec::new();
    let mut includes = Vec::new();
    for line in contents.lines() {
        if let Some(v) = line.strip_prefix("CXX_DEFINES = ") {
            defines = split_generated_flags(v);
        } else if let Some(v) = line.strip_prefix("CXX_INCLUDES = ") {
            includes = split_generated_flags(v);
        }
    }
    Some((defines, includes))
}

/// Splits CMake-generated flag/path content (a `flags.make` `CXX_DEFINES`/
/// `CXX_INCLUDES` line, or a response-file's contents) into tokens.
///
/// On non-Windows, these files are written for `/bin/sh -c` consumption
/// (e.g. `-DGFLAGS_DLL_DECLARE_FLAG=""` meaning "define to the empty
/// string"), so real POSIX shell-word-splitting via `shlex` is necessary --
/// naive whitespace-splitting would pass raw quote characters through
/// literally and corrupt the values.
///
/// On Windows, CMake's NMake generator instead writes content for MSVC's
/// own command-line argument parser (`cl.exe`/`link.exe` invoked directly
/// via `CreateProcess`, with no intermediate shell involved at all) --
/// running that through `shlex`'s POSIX rules silently eats every
/// backslash in every path (`\` is shlex's own escape character), mangling
/// e.g. `-ID:\a\osquery-rs\...\ns_osquery_core` into a single
/// run-together `-ID:aosquery-rs...ns_osquery_core` token with no
/// separators left at all -- this broke every Windows shim compile until
/// found via a real CI failure. Use a much simpler tokenizer instead: split
/// on whitespace, respecting double-quoted regions so a token with an
/// embedded space stays one token, without interpreting backslashes or
/// stripping quote characters -- MSVC's own parser does that itself once
/// handed the token unmodified, exactly as CMake intended.
fn split_generated_flags(s: &str) -> Vec<String> {
    if !cfg!(windows) {
        return shlex::split(s)
            .unwrap_or_else(|| panic!("failed to shell-split generated flags: {s}"));
    }
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    // CMake's flags.make uses a bare, unescaped `-DNAME=""` idiom to mean
    // "define to the empty string" -- on Unix that relies on a real shell
    // to strip the quotes (see split_generated_flags's own non-Windows
    // branch above), but no shell is involved here, and MSVC's own
    // command-line parser does NOT collapse this on its own: confirmed by
    // a real build failure where GFLAGS_DLL_DECLARE_FLAG (defined exactly
    // this way) survived as a literal `""` token all the way into
    // `extern "" bool FLAGS_disable_extensions;` -- `error C2537: '':
    // illegal linkage specification`, since `extern ""` isn't a valid
    // language-linkage string. Collapse this one specific, unambiguous
    // shape ourselves. Deliberately narrow: a *backslash-escaped* quoted
    // define (`-DNAME=\"value\"`, meaning "the literal quoted string
    // should survive into the macro value", e.g.
    // `-DOSQUERY_BUILD_DISTRO=\"10\"`) is a different token shape entirely
    // and must not be touched here.
    tokens
        .into_iter()
        .map(|tok| match tok.strip_prefix("-D").and_then(|rest| rest.strip_suffix("=\"\"")) {
            Some(name) => format!("-D{name}="),
            None => tok,
        })
        .collect()
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

/// Recursively copies every file under `src` into `dst`, creating
/// directories as needed. Used by `bundle_include_path` to stage a
/// still-needed include directory into a prebuilt package.
fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap_or_else(|e| panic!("failed to create {}: {e}", dst.display()));
    let entries =
        fs::read_dir(src).unwrap_or_else(|e| panic!("failed to read dir {}: {e}", src.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        let dest_path = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_all(&path, &dest_path);
        } else {
            fs::copy(&path, &dest_path).unwrap_or_else(|e| {
                panic!("failed to copy {} to {}: {e}", path.display(), dest_path.display())
            });
        }
    }
}

/// Classifies a `cxx_includes` path token (already stripped of any leading
/// `-I`/`-isystem`) against `build_dir`/`src_dir` and either bundles it into
/// `package_dir/include/...` (returning the bundle-relative `include/...`
/// replacement, copying it at most once per unique source directory via
/// `copied`) or drops it entirely (returning `None`).
///
/// Dropped: CMake's own `ns_*`-prefixed virtual-namespace directories
/// (`cmake/utilities.cmake`'s include-namespace helper -- symlink farms
/// that just re-expose `src_dir`'s own real headers under a per-target
/// path, for CMake's own build organization) and `installed_formulas`
/// (osquery's own CMake-built OpenSSL headers). Both are build-tree-only
/// and confirmed, via a real compile of shim.cpp/compat_stubs.cpp with
/// neither present, to be unneeded: `compile_shim`'s own `.include(src_dir)`
/// call already covers everything the `ns_*` dirs would have symlinked
/// back to, and neither file includes anything from OpenSSL directly.
///
/// Everything else gets bundled, whether it points into the CMake build
/// tree (e.g. glog's own `log_severity.h`, placed by a real
/// `configure_file(... COPYONLY)` at CMake configure time -- genuinely
/// can't be reconstructed without running CMake) or the plain git-cloned
/// source tree (third-party headers living in a git submodule --
/// `ensure_osquery_source`'s lightweight clone never runs `git submodule
/// update`, so a consumer's own local checkout won't have this content
/// either). Bundling is the only option that's independent of both.
fn bundle_include_path(
    path_str: &str,
    src_dir: &Path,
    build_dir: &Path,
    bundle_include_dir: &Path,
    copied: &mut HashSet<PathBuf>,
) -> Option<String> {
    let path = Path::new(path_str);

    let relative = if let Ok(rel) = path.strip_prefix(build_dir) {
        let first = rel.components().next().and_then(|c| c.as_os_str().to_str());
        if matches!(first, Some(name) if name.starts_with("ns_") || name == "installed_formulas") {
            return None;
        }
        rel
    } else if let Ok(rel) = path.strip_prefix(src_dir) {
        rel
    } else {
        // Defensive fallback: every include token seen in a real manifest
        // falls under build_dir or src_dir. Pass an unrecognized one
        // through unchanged rather than panicking a release build over a
        // genuinely novel case -- no worse than the pre-bundling behavior.
        return Some(path_str.to_string());
    };

    if copied.insert(path.to_path_buf()) {
        copy_dir_all(path, &bundle_include_dir.join(relative));
    }

    // Always `/`-joined, never OS-native-separator-joined: this string is
    // written into manifest.v1 and may be read back on a different OS than
    // the one that staged it (e.g. built on Linux, consumed on Windows).
    let portable_relative = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    Some(format!("include/{portable_relative}"))
}

/// Rejoins a manifest-recorded `cxx_includes` token against `bundle_dir` if
/// it uses `bundle_include_path`'s `include/...` convention; passes
/// anything else (the bare `-isystem` flag word, or an unrecognized-token
/// absolute-path fallback) through unchanged.
fn rejoin_bundle_include_token(token: &str, bundle_dir: &Path) -> String {
    if let Some(rel) = token.strip_prefix("-Iinclude/") {
        return format!("-I{}", bundle_dir.join("include").join(rel).display());
    }
    if let Some(rel) = token.strip_prefix("include/") {
        return bundle_dir.join("include").join(rel).display().to_string();
    }
    token.to_string()
}

