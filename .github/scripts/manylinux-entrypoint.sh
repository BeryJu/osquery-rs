#!/usr/bin/env bash
# Runs inside `docker run ... quay.io/pypa/manylinux2014_<arch>` (x86_64,
# CentOS 7) or `quay.io/pypa/manylinux_2_34_<arch>` (aarch64, AlmaLinux 9)
# -- see the Linux jobs in ci.yml/release.yml for why this is invoked via a
# manual `docker run` rather than the job-level `container:` key. Installs
# everything osquery's from-source build needs that neither container
# ships (yum prerequisites, a modern CMake, `python3`, osquery-toolchain,
# Rust), then execs whatever command was passed as its own arguments.
set -eux

case "$(uname -m)" in
  aarch64) ARCH=aarch64 ;;
  x86_64) ARCH=x86_64 ;;
  *)
    echo "unsupported arch $(uname -m)" >&2
    exit 1
    ;;
esac

# pkg-config's package name differs by distro ($ID), not architecture.
. /etc/os-release
case "$ID" in
  centos) PKGCONFIG_PKG=pkgconfig ;;
  *) PKGCONFIG_PKG=pkgconf-pkg-config ;;
esac

# FindBin.pm ships in CentOS 7's base perl already; AlmaLinux 9 splits it
# into its own package.
EXTRA_PERL_PKGS=(perl-IPC-Cmd perl-Data-Dumper perl-Time-Piece)
if [ "$ID" != "centos" ]; then
  EXTRA_PERL_PKGS+=(perl-FindBin)
fi

# CentOS 7 is EOL upstream (mirrorlist.centos.org 404s); repoint yum at the
# vault mirror first. No-op on AlmaLinux 9.
sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo
# EXTRA_PERL_PKGS above are required by OpenSSL's vendored `Configure`.
# No ccache: unavailable on manylinux2014_aarch64, and build.rs doesn't
# wire CMAKE_*_COMPILER_LAUNCHER=ccache into the configure anyway.
yum install -y git bison flex make curl ca-certificates \
  "$PKGCONFIG_PKG" "${EXTRA_PERL_PKGS[@]}"
yum groupinstall -y "Development Tools"

# CentOS 7's stock cmake package (2.8.12) is far too old for osquery; the
# `cmake` PyPI wheel under manylinux's own Python is a modern replacement.
PYBIN=$(ls -d /opt/python/cp3*-cp3*/bin | sort | tail -1)
"$PYBIN/pip" install --quiet cmake
ln -sf "$PYBIN/cmake" /usr/local/bin/cmake
ln -sf "$PYBIN/python3" /usr/local/bin/python3
cmake --version
python3 --version

curl -fsSL -o /tmp/toolchain.tar.xz \
  "https://github.com/osquery/osquery-toolchain/releases/download/1.3.0/osquery-toolchain-1.3.0-${ARCH}.tar.xz"
tar xf /tmp/toolchain.tar.xz -C /usr/local
rm /tmp/toolchain.tar.xz

# osquery vendors augeas, whose gnulib submodule assumes <xlocale.h>
# exists (removed from modern glibc). This toolchain's aarch64 build lacks
# it; x86_64's already ships a real one -- only shim it in if missing.
if [ ! -f /usr/local/osquery-toolchain/usr/include/xlocale.h ]; then
  printf '#pragma once\n#include <locale.h>\n' \
    > /usr/local/osquery-toolchain/usr/include/xlocale.h
fi

# On AlmaLinux 9, the final link needs /usr/lib64/libpthread_nonshared.a
# (a leftover reference in this container's gcc spec from RHEL's old
# libpthread-into-libc merge, which AlmaLinux 9 completed and no longer
# ships) -- the toolchain bundles its own copy; place it where gcc expects.
if [ ! -f /usr/lib64/libpthread_nonshared.a ] \
    && [ -f /usr/local/osquery-toolchain/usr/lib/libpthread_nonshared.a ]; then
  cp /usr/local/osquery-toolchain/usr/lib/libpthread_nonshared.a /usr/lib64/
fi

export RUSTUP_HOME=/usr/local/rustup
export CARGO_HOME=/usr/local/cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path
export PATH="/usr/local/cargo/bin:$PATH"

# The container runs as root; anything it writes under the bind-mounted
# workspace must stay readable by the runner's own user afterward.
trap 'chmod -R a+rX target/osquery-sys pkg 2>/dev/null || true' EXIT

"$@"
