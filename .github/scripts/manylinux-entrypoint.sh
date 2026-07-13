#!/usr/bin/env bash
# Runs inside `docker run ... quay.io/pypa/manylinux2014_<arch>` (x86_64,
# CentOS 7) or `quay.io/pypa/manylinux_2_34_<arch>` (aarch64, AlmaLinux 9 --
# see the aarch64 Linux job's own comment in ci.yml for why a newer
# manylinux tier is needed there) -- see the Linux jobs in ci.yml/
# release.yml for why this is invoked via a manual `docker run` rather than
# the job-level `container:` key. Sets up everything osquery's from-source
# build needs on whichever of these old(-ish)-glibc bases is in use -- yum
# prerequisites, a modern CMake, a plain `python3`, osquery-toolchain, and
# Rust itself (neither container has any of these) -- then execs whatever
# command was passed as this script's own arguments. Works unmodified
# across both image families/architectures (see ARCH/PKGCONFIG_PKG below).
set -eux

case "$(uname -m)" in
  aarch64) ARCH=aarch64 ;;
  x86_64) ARCH=x86_64 ;;
  *)
    echo "unsupported arch $(uname -m)" >&2
    exit 1
    ;;
esac

# manylinux2014 (CentOS 7) names the pkg-config package `pkgconfig`;
# manylinux_2_34 (AlmaLinux 9) renamed it to `pkgconf-pkg-config` (and
# actually ships it preinstalled already, but naming it explicitly here is
# harmless either way). Sourcing /etc/os-release's $ID is the actual
# distinguishing factor, not the architecture -- this project's own CI
# usage happens to pair x86_64 with manylinux2014 and aarch64 with
# manylinux_2_34, but that pairing isn't something to bake an assumption
# on here.
. /etc/os-release
case "$ID" in
  centos) PKGCONFIG_PKG=pkgconfig ;;
  *) PKGCONFIG_PKG=pkgconf-pkg-config ;;
esac

# perl-FindBin: unlike perl-IPC-Cmd/perl-Data-Dumper/perl-Time-Piece
# (split out on BOTH images below), FindBin.pm ships bundled directly in
# CentOS 7's base perl package already -- confirmed directly:
# /usr/share/perl5/FindBin.pm exists there with nothing extra installed,
# and "perl-FindBin" doesn't even exist as a package name on that image
# (yum would abort the *entire* install trying to resolve it, same
# "Not tolerating missing names" failure mode as ccache below). AlmaLinux
# 9 does split it out separately, so it's only needed there.
EXTRA_PERL_PKGS=(perl-IPC-Cmd perl-Data-Dumper perl-Time-Piece)
if [ "$ID" != "centos" ]; then
  EXTRA_PERL_PKGS+=(perl-FindBin)
fi

# No-ops on manylinux_2_34/AlmaLinux 9 (its repo files don't contain
# "mirror.centos.org" at all) -- only actually matters for manylinux2014/
# CentOS 7, which is EOL upstream (mirrorlist.centos.org 404s), so repoint
# yum at the community-maintained vault mirror first.
sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo
# The perl-* packages in EXTRA_PERL_PKGS above are required by OpenSSL's
# own `Configure`/generated Makefile (vendored by osquery) -- without
# them, OpenSSL's own build fails with "Can't locate IPC/Cmd.pm"/"Can't
# locate Time/Piece.pm"/"Can't locate FindBin.pm" in @INC before any of
# osquery's own code even starts compiling. Found one at a time via real
# CI failures; checked Configure/util/perl/OpenSSL/*.pm's own `use`
# statements afterward for the complete list -- everything else
# referenced there (Carp, Exporter, File::*, Cwd, Scalar::Util,
# Getopt::Std, POSIX, Config) is a true Perl core module present on every
# distro, not split into its own package anywhere. Add any further
# missing modules the same way if OpenSSL's Configure still complains
# regardless.
#
# No `ccache` here (unlike docker/build.Dockerfile's local-dev image):
# it's not available in manylinux2014_aarch64's repos at all ("No package
# ccache available"), and yum aborts the *entire* install if even one
# requested package is missing ("Not tolerating missing names on
# install"). build.rs never actually wires CMAKE_*_COMPILER_LAUNCHER=
# ccache into the configure anyway, so it was never more than an unused
# nice-to-have here -- just leave it out instead of chasing an EPEL repo
# for a package this build doesn't use (even where it is available, e.g.
# manylinux_2_34, for the same reason: consistency, not necessity).
#
yum install -y git bison flex make curl ca-certificates \
  "$PKGCONFIG_PKG" "${EXTRA_PERL_PKGS[@]}"
yum groupinstall -y "Development Tools"

# CentOS 7's stock yum cmake package is 2.8.12 -- far too old for osquery.
# manylinux2014 ships several Python versions under /opt/python/
# specifically for building wheels; the plain `cmake` PyPI wheel is a
# perfectly good source of a modern, portable prebuilt binary here too.
PYBIN=$(ls -d /opt/python/cp3*-cp3*/bin | sort | tail -1)
"$PYBIN/pip" install --quiet cmake
ln -sf "$PYBIN/cmake" /usr/local/bin/cmake
# osquery's own CMake configure looks for a bare `python3`; manylinux2014
# only provides versioned paths under /opt/python/.
ln -sf "$PYBIN/python3" /usr/local/bin/python3
cmake --version
python3 --version

curl -fsSL -o /tmp/toolchain.tar.xz \
  "https://github.com/osquery/osquery-toolchain/releases/download/1.3.0/osquery-toolchain-1.3.0-${ARCH}.tar.xz"
tar xf /tmp/toolchain.tar.xz -C /usr/local
rm /tmp/toolchain.tar.xz

# osquery vendors augeas, whose gnulib submodule ships a pregenerated
# header assuming <xlocale.h> exists; real xlocale.h was removed from
# modern glibc years ago. This toolchain release's aarch64 build
# genuinely lacks xlocale.h (needs this shim); its x86_64 build already
# ships a complete, real one (an older glibc header snapshot that still
# declares functions using it directly) -- only shim it in if it's
# missing, never overwrite a real one (see docker/build.Dockerfile's
# identical comment for the two archs' actual difference).
if [ ! -f /usr/local/osquery-toolchain/usr/include/xlocale.h ]; then
  printf '#pragma once\n#include <locale.h>\n' \
    > /usr/local/osquery-toolchain/usr/include/xlocale.h
fi

# On AlmaLinux 9, the final link (which uses the host's own default gcc
# as the linker driver, not the osquery-toolchain's own -- see build.rs's
# comment on why) fails with "ld: cannot find
# /usr/lib64/libpthread_nonshared.a: No such file or directory". This is
# a leftover, hardcoded absolute-path reference inside this container's
# own gcc-toolset-14 spec, dating from RHEL's old libpthread-into-libc
# merge transition; RHEL9/AlmaLinux 9 completed that merge and dropped
# the file entirely -- confirmed no package anywhere in this image's
# repos provides it (`yum provides /usr/lib64/libpthread_nonshared.a`
# finds nothing; `glibc-static`, the plausible-looking package, doesn't
# contain it either). The osquery-toolchain itself happens to bundle its
# own tiny copy (a long-standing, effectively-empty RHEL compatibility
# placeholder, not real code) at
# usr/lib/libpthread_nonshared.a in its own sysroot -- just place that at
# the literal path gcc's spec expects, since it's not a real, searchable
# `-lname` reference this can be fixed by adding a `-L` directory for.
# CentOS 7 doesn't need this (its glibc-devel already provides the file
# at that same system path).
if [ ! -f /usr/lib64/libpthread_nonshared.a ] \
    && [ -f /usr/local/osquery-toolchain/usr/lib/libpthread_nonshared.a ]; then
  cp /usr/local/osquery-toolchain/usr/lib/libpthread_nonshared.a /usr/lib64/
fi

export RUSTUP_HOME=/usr/local/rustup
export CARGO_HOME=/usr/local/cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path
export PATH="/usr/local/cargo/bin:$PATH"

# Diagnostic experiment: on this aarch64/AlmaLinux9 combination only,
# osquery-sys's own build-script-emitted native link flags (-l
# static=c++, -l static=osquery_core, etc.) never reach the smoke/
# osquery --test binary's own rustc link invocation -- confirmed real
# (not a log-truncation artifact) across multiple rounds, and NOT fixed
# by merging the build+test cargo invocations into one or by disabling
# incremental compilation. Testing whether this is a regression
# specific to the rust-toolchain.toml-pinned 1.97.0 by forcing an older
# toolchain here instead (RUSTUP_TOOLCHAIN overrides the repo's
# toolchain-file pin). x86_64 is untouched -- still uses whatever
# rust-toolchain.toml pins, via actions-rust-lang/setup-rust-toolchain
# on the host, unaffected by anything in this container-only script.
if [ "$ARCH" = "aarch64" ]; then
  rustup toolchain install 1.90.0 --profile minimal
  export RUSTUP_TOOLCHAIN=1.90.0
fi

# The container runs as root, so anything it writes under the (bind-mounted)
# workspace -- notably target/osquery-sys, which actions/cache needs to read
# back on the host afterward, and pkg/, which release.yml's packaging step
# reads on the host -- must stay readable by the runner's own user.
trap 'chmod -R a+rX target/osquery-sys pkg 2>/dev/null || true' EXIT

"$@"
