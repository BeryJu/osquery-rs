// Copyright (c) 2014-present, The osquery authors
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
//
// Plain-C FFI surface over an in-process embedded osquery runtime. No STL
// types cross this boundary, and no C++ exception may ever unwind across it
// -- every function below traps all exceptions internally and reports
// failure via its return code instead.

#ifndef OSQUERY_EMBED_SHIM_H
#define OSQUERY_EMBED_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum osquery_embed_status {
  OSQUERY_EMBED_OK = 0,
  OSQUERY_EMBED_ALREADY_INITIALIZED = 1,
  OSQUERY_EMBED_NOT_INITIALIZED = 2,
  OSQUERY_EMBED_QUERY_FAILED = 3,
  OSQUERY_EMBED_EXCEPTION = 4,
  OSQUERY_EMBED_UNKNOWN = 5,
};

// Starts the embedded osquery runtime: constructs an osquery::Initializer in
// ToolType::SHELL mode, forces FLAGS_disable_extensions = true (so no Unix
// socket is ever created), and calls Initializer::start(). May be called at
// most once per process -- a second call returns
// OSQUERY_EMBED_ALREADY_INITIALIZED without side effects.
int32_t osquery_embed_init(int argc, char** argv);

// Cleanly shuts down the embedded runtime started by osquery_embed_init.
// Safe to call at most once after a successful init; calling it without a
// prior successful init returns OSQUERY_EMBED_NOT_INITIALIZED.
int32_t osquery_embed_shutdown(void);

// Runs a SQL query in-process and returns the results as a JSON array string
// (one object per row, string-valued fields) via *out_json/*out_len. On
// success returns OSQUERY_EMBED_OK and *out_json is a NUL-terminated buffer
// owned by the caller (free with osquery_embed_free_string). On failure,
// *out_json may still be set to a JSON error envelope, or left NULL.
int32_t osquery_embed_query(const char* sql,
                            size_t sql_len,
                            char** out_json,
                            size_t* out_len);

// Frees a buffer previously returned via an out_json parameter above.
void osquery_embed_free_string(char* ptr);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OSQUERY_EMBED_SHIM_H
