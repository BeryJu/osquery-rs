# Build/test environment for osquery-sys, following osquery's own documented
# Linux recipe (docs/wiki/development/building.md in the vendored submodule)
# instead of the host's toolchain, since osquery's macOS build is documented
# as broken on Xcode SDK >= 16.3.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    git python3 bison flex make cmake ccache curl ca-certificates \
    build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
RUN set -eux; \
    case "$(uname -m)" in \
      aarch64) ARCH=aarch64 ;; \
      x86_64) ARCH=x86_64 ;; \
      *) echo "unsupported arch $(uname -m)"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/toolchain.tar.xz \
      "https://github.com/osquery/osquery-toolchain/releases/download/1.3.0/osquery-toolchain-1.3.0-${ARCH}.tar.xz"; \
    tar xf /tmp/toolchain.tar.xz -C /usr/local; \
    rm /tmp/toolchain.tar.xz

# osquery vendors augeas, whose gnulib submodule ships a pregenerated
# header assuming <xlocale.h> exists; real xlocale.h was removed from
# modern glibc years ago. This toolchain release turns out to ship a
# meaningfully OLDER glibc header snapshot for x86_64 than for aarch64,
# though: aarch64's usr/include genuinely lacks xlocale.h (its
# <locale.h>/<string.h>/<time.h> use <bits/types/locale_t.h> instead and
# never need it), while x86_64's usr/include ALREADY HAS a complete, real
# xlocale.h (its headers are old enough to still declare functions using
# __locale_t via that file). Blindly writing a passthrough shim
# unconditionally clobbered x86_64's perfectly good real xlocale.h with a
# `#include <locale.h>`-only stub, which is circular there (locale.h
# itself needs this type before it can finish processing) -- only write
# the shim if the file doesn't already exist.
#
# osquery's build passes --sysroot=/usr/local/osquery-toolchain (set via
# OSQUERY_TOOLCHAIN_SYSROOT), which redirects absolute default header
# search paths (/usr/include, /usr/local/include, ...) into that sysroot
# instead of the container's real filesystem -- so the shim must live
# inside the sysroot, not at the container's own /usr/local/include.
RUN if [ ! -f /usr/local/osquery-toolchain/usr/include/xlocale.h ]; then \
      printf '#pragma once\n#include <locale.h>\n' \
        > /usr/local/osquery-toolchain/usr/include/xlocale.h; \
    fi

# Rust toolchain, to build/test the actual crates once osquery links.
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /work
