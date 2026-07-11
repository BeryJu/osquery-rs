// Copyright (c) 2014-present, The osquery authors
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
//
// Compiled into its own tiny static archive and linked at the very end of
// the final link line (see build.rs's adapt_tokens_for_default_linker),
// deliberately NOT bundled into shim.cpp/libosquery_embed_shim.a: that
// archive gets positioned early in the link (wherever Cargo places this
// crate's native static libs), and GNU ld only pulls an archive member in
// if something already needs it at the point the archive is processed --
// the code below is only referenced by osquery objects that appear much
// later in the link line, so bundled there it was silently never pulled
// in. Living in its own archive, explicitly appended last, guarantees it's
// still available by the time anything asks for it.

#include <cerrno>
#include <cstddef>

// osquery/tables/system/linux/sysctl_utils.cpp (part of specs_tables, for
// the sysctl-mirroring table, only compiled on Linux) calls glibc's old
// BSD-style sysctl(2) wrapper. glibc removed it in 2.30+ (Linux's sysctl()
// syscall itself has been deprecated for years in favor of /proc/sys); the
// osquery-toolchain targets an older glibc baseline that still declared
// it, so the compiled object references a symbol our host's actual glibc
// doesn't provide. We don't exercise that specific table for in-process
// SQL queries, so a stub reporting "not supported" (matching what a real,
// syscall-less sysctl() would do on a kernel without CONFIG_SYSCTL_SYSCALL)
// is enough to satisfy the linker without needing real behavior.
//
// Linux-only: macOS's libc provides a real sysctl() (BSD heritage) that a
// global definition here would collide with, and Windows never references
// the symbol at all -- this file compiles to an empty (but harmless)
// archive on those platforms.
#if defined(__linux__)
extern "C" int sysctl(int*, int, void*, size_t*, void*, size_t) {
  errno = ENOSYS;
  return -1;
}
#endif
