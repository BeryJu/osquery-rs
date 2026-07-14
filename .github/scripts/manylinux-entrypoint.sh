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
# manylinux_2_34 (AlmaLinux 9) renamed it to `pkgconf-pkg-config`. Sourcing
# /etc/os-release's $ID is the actual distinguishing factor, not the
# architecture, even though this project's own CI pairs x86_64 with
# manylinux2014 and aarch64 with manylinux_2_34.
. /etc/os-release
case "$ID" in
  centos) PKGCONFIG_PKG=pkgconfig ;;
  *) PKGCONFIG_PKG=pkgconf-pkg-config ;;
esac

# perl-FindBin: FindBin.pm ships bundled in CentOS 7's base perl already
# (and "perl-FindBin" isn't even a valid package name there); AlmaLinux 9
# splits it out separately, so it's only needed there.
EXTRA_PERL_PKGS=(perl-IPC-Cmd perl-Data-Dumper perl-Time-Piece)
if [ "$ID" != "centos" ]; then
  EXTRA_PERL_PKGS+=(perl-FindBin)
fi

# No-ops on manylinux_2_34/AlmaLinux 9 -- only matters for manylinux2014/
# CentOS 7, which is EOL upstream (mirrorlist.centos.org 404s), so repoint
# yum at the community-maintained vault mirror first.
sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo
# EXTRA_PERL_PKGS above are required by OpenSSL's vendored `Configure`/
# generated Makefile ("Can't locate IPC/Cmd.pm" etc. otherwise); everything
# else it uses (Carp, Exporter, File::*, Cwd, Scalar::Util, Getopt::Std,
# POSIX, Config) is true Perl core, present everywhere.
#
# No `ccache`: unavailable in manylinux2014_aarch64's repos, and build.rs
# never actually wires CMAKE_*_COMPILER_LAUNCHER=ccache into the configure
# anyway, so it's not worth chasing down on any image.
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
# header assuming <xlocale.h> exists (removed from modern glibc years ago).
# This toolchain release's aarch64 build genuinely lacks xlocale.h; its
# x86_64 build already ships a real one -- only shim it in if missing,
# never overwrite a real one.
if [ ! -f /usr/local/osquery-toolchain/usr/include/xlocale.h ]; then
  printf '#pragma once\n#include <locale.h>\n' \
    > /usr/local/osquery-toolchain/usr/include/xlocale.h
fi

# On AlmaLinux 9, the final link (host's own default gcc as the linker
# driver, not the toolchain's -- see build.rs) fails looking for
# /usr/lib64/libpthread_nonshared.a: a leftover hardcoded reference in this
# container's gcc-toolset-14 spec from RHEL's old libpthread-into-libc
# merge, which AlmaLinux 9 completed and no package still provides. The
# osquery-toolchain bundles its own copy of the same (effectively empty,
# compatibility-only) file; just place it at the path gcc's spec expects.
# CentOS 7 doesn't need this -- its glibc-devel already provides the file.
if [ ! -f /usr/lib64/libpthread_nonshared.a ] \
    && [ -f /usr/local/osquery-toolchain/usr/lib/libpthread_nonshared.a ]; then
  cp /usr/local/osquery-toolchain/usr/lib/libpthread_nonshared.a /usr/lib64/
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
