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

# No-ops on manylinux_2_34/AlmaLinux 9 (its repo files don't contain
# "mirror.centos.org" at all) -- only actually matters for manylinux2014/
# CentOS 7, which is EOL upstream (mirrorlist.centos.org 404s), so repoint
# yum at the community-maintained vault mirror first.
sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo
# perl-IPC-Cmd/perl-Data-Dumper/perl-Time-Piece: not part of
# manylinux2014's base perl install (manylinux_2_34 already ships some of
# these, but installing an already-installed package is harmless), but
# required by OpenSSL's own `Configure`/generated Makefile (vendored by
# osquery) -- without these, OpenSSL's own build fails with "Can't locate
# IPC/Cmd.pm" or "Can't locate Time/Piece.pm" in @INC before any of
# osquery's own code even starts compiling. Found one at a time via real
# CI failures; add any further missing modules the same way if OpenSSL's
# Configure still complains.
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
yum install -y git bison flex make curl ca-certificates "$PKGCONFIG_PKG" \
  perl-IPC-Cmd perl-Data-Dumper perl-Time-Piece
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

export RUSTUP_HOME=/usr/local/rustup
export CARGO_HOME=/usr/local/cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path
export PATH="/usr/local/cargo/bin:$PATH"

# The container runs as root, so anything it writes under the (bind-mounted)
# workspace -- notably target/osquery-sys, which actions/cache needs to read
# back on the host afterward, and pkg/, which release.yml's packaging step
# reads on the host -- must stay readable by the runner's own user.
trap 'chmod -R a+rX target/osquery-sys pkg 2>/dev/null || true' EXIT

"$@"
