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
# linux/aarch64 header assuming <xlocale.h> exists. glibc folded that
# header's contents into <locale.h>/<features.h> and removed it years ago;
# Ubuntu 24.04's glibc no longer ships it. Standard shim: a passthrough
# header satisfies the #include without reintroducing the legacy API.
#
# osquery's build passes --sysroot=/usr/local/osquery-toolchain (set via
# OSQUERY_TOOLCHAIN_SYSROOT), which redirects absolute default header
# search paths (/usr/include, /usr/local/include, ...) into that sysroot
# instead of the container's real filesystem -- so the shim must live
# inside the sysroot, not at the container's own /usr/local/include.
RUN printf '#pragma once\n#include <locale.h>\n' \
      > /usr/local/osquery-toolchain/usr/include/xlocale.h

# Rust toolchain, to build/test the actual crates once osquery links.
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /work
