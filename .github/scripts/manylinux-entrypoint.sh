#!/usr/bin/env bash
# Runs inside `docker run ... quay.io/pypa/manylinux2014_x86_64` (see the
# Linux jobs in ci.yml/release.yml for why this is invoked via a manual
# `docker run` rather than the job-level `container:` key). Sets up
# everything osquery's from-source build needs on this old-glibc base --
# yum prerequisites, a modern CMake, a plain `python3`, osquery-toolchain,
# and Rust itself (this container has none of these) -- then execs
# whatever command was passed as this script's own arguments.
set -eux

sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo
# perl-IPC-Cmd/perl-Data-Dumper/perl-Time-Piece: not part of
# manylinux2014's base perl install, but required by OpenSSL's own
# `Configure`/generated Makefile (vendored by osquery) -- without these,
# OpenSSL's own build fails with "Can't locate IPC/Cmd.pm" or "Can't
# locate Time/Piece.pm" in @INC before any of osquery's own code even
# starts compiling. Found one at a time via real CI failures; add any
# further missing modules the same way if OpenSSL's Configure still
# complains.
yum install -y git bison flex make ccache curl ca-certificates pkgconfig \
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
  "https://github.com/osquery/osquery-toolchain/releases/download/1.3.0/osquery-toolchain-1.3.0-x86_64.tar.xz"
tar xf /tmp/toolchain.tar.xz -C /usr/local
rm /tmp/toolchain.tar.xz

# osquery vendors augeas, whose gnulib submodule ships a pregenerated
# header assuming <xlocale.h> exists; real xlocale.h was removed from
# modern glibc years ago. This toolchain release's x86_64 build already
# ships a complete, real xlocale.h -- only shim it in if it's missing.
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
