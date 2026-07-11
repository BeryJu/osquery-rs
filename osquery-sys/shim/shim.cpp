// Copyright (c) 2014-present, The osquery authors
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

#include "shim.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <string>

#include <osquery/core/flags.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/core/system.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/info/tool_type.h>

// Declared (CLI_FLAG) in osquery/extensions/extensions.cpp; default false.
// startExtensionManager()/initShellSocket() both check this flag first and
// return/no-op before ever computing a socket path or binding one -- setting
// it true is what actually keeps this process socket-free.
//
// CLI_FLAG in extensions.cpp is invoked from inside `namespace osquery`, so
// the actual linked symbol is `osquery::fLB::FLAGS_disable_extensions` (with
// `osquery::FLAGS_disable_extensions` as gflags' usual unqualified alias
// inside that namespace) -- DECLARE_bool must be issued in the same
// namespace to reference the same symbol, not the global one.
namespace osquery {
DECLARE_bool(disable_extensions);
}

namespace {

std::mutex g_mutex;
std::unique_ptr<osquery::Initializer> g_initializer;
bool g_shutdown_called = false;

// osquery::Initializer stores pointers to the argc/argv it's given for its
// entire lifetime (see osquery/core/system.h), so these must outlive it --
// static storage duration, not locals of osquery_embed_init.
int g_argc = 2;
char g_arg0[] = "osquery_embed";
char g_arg1[] = "--disable_extensions=true";
char* g_argv_storage[] = {g_arg0, g_arg1, nullptr};
char** g_argv = g_argv_storage;

char* dup_cstr(const std::string& s) {
  char* out = new (std::nothrow) char[s.size() + 1];
  if (out == nullptr) {
    return nullptr;
  }
  std::memcpy(out, s.data(), s.size());
  out[s.size()] = '\0';
  return out;
}

} // namespace

extern "C" int32_t osquery_embed_init(int argc, char** argv) {
  (void)argc;
  (void)argv;

  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_initializer != nullptr) {
    return OSQUERY_EMBED_ALREADY_INITIALIZED;
  }

  try {
    // Belt-and-suspenders #1: set before construction, in case anything
    // during construction (before flag parsing) reads it.
    osquery::FLAGS_disable_extensions = true;

    g_initializer = std::make_unique<osquery::Initializer>(
        g_argc, g_argv, osquery::ToolType::SHELL);

    // Belt-and-suspenders #2 (argv above) already covers flag parsing; set
    // again explicitly before start() per the confirmed recipe, in case a
    // config/flagfile the shell auto-loads tried to flip it back.
    osquery::FLAGS_disable_extensions = true;

    g_initializer->start();
    return OSQUERY_EMBED_OK;
  } catch (const std::exception&) {
    g_initializer.reset();
    return OSQUERY_EMBED_EXCEPTION;
  } catch (...) {
    g_initializer.reset();
    return OSQUERY_EMBED_UNKNOWN;
  }
}

extern "C" int32_t osquery_embed_shutdown(void) {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_initializer == nullptr) {
    return OSQUERY_EMBED_NOT_INITIALIZED;
  }
  if (g_shutdown_called) {
    return OSQUERY_EMBED_OK;
  }

  try {
    g_initializer->shutdown(0);
    g_shutdown_called = true;
    return OSQUERY_EMBED_OK;
  } catch (const std::exception&) {
    return OSQUERY_EMBED_EXCEPTION;
  } catch (...) {
    return OSQUERY_EMBED_UNKNOWN;
  }
}

extern "C" int32_t osquery_embed_query(const char* sql,
                                       size_t sql_len,
                                       char** out_json,
                                       size_t* out_len) {
  if (out_json != nullptr) {
    *out_json = nullptr;
  }
  if (out_len != nullptr) {
    *out_len = 0;
  }

  {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_initializer == nullptr) {
      return OSQUERY_EMBED_NOT_INITIALIZED;
    }
  }

  try {
    std::string sql_str(sql, sql_len);
    osquery::QueryData results;
    auto status = osquery::query(sql_str, results);

    if (!status.ok()) {
      std::string err = "{\"error\":\"" + status.getMessage() + "\"}";
      char* buf = dup_cstr(err);
      if (buf != nullptr) {
        if (out_json != nullptr) {
          *out_json = buf;
        }
        if (out_len != nullptr) {
          *out_len = err.size();
        }
      }
      return OSQUERY_EMBED_QUERY_FAILED;
    }

    std::string json;
    auto json_status = osquery::serializeQueryDataJSON(results, json);
    if (!json_status.ok()) {
      return OSQUERY_EMBED_EXCEPTION;
    }

    char* buf = dup_cstr(json);
    if (buf == nullptr) {
      return OSQUERY_EMBED_UNKNOWN;
    }
    if (out_json != nullptr) {
      *out_json = buf;
    }
    if (out_len != nullptr) {
      *out_len = json.size();
    }
    return OSQUERY_EMBED_OK;
  } catch (const std::exception&) {
    return OSQUERY_EMBED_EXCEPTION;
  } catch (...) {
    return OSQUERY_EMBED_UNKNOWN;
  }
}

extern "C" void osquery_embed_free_string(char* ptr) {
  delete[] ptr;
}
