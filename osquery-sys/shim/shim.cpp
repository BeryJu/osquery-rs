// Copyright (c) 2014-present, The osquery authors
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

#include "shim.h"

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <vector>

#include <glog/logging.h>
#include <osquery/core/flags.h>
#include <osquery/core/plugins/logger.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/core/system.h>
#include <osquery/registry/registry_factory.h>
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
//
// --logger_plugin=rust_bridge selects RustBridgeLoggerPlugin (defined
// below) as the *only* active logger plugin, so every internal status log
// (glog's LOG(INFO)/LOG(WARNING)/... calls throughout osquery's own code)
// gets forwarded through osquery_embed_set_log_callback instead of
// osquery's default "filesystem" logger plugin, which would otherwise
// write them to on-disk log files -- another on-disk side effect this
// embedded, in-process use case doesn't want, same reasoning as
// --disable_extensions. NOTE: the CLI flag is `logger_plugin`, not
// `logger` -- "logger" is only the *registry category* name
// (RegistryFactory::get().getActive("logger") etc.); the actual CLI_FLAG
// declared in osquery/logger/logger.cpp is `logger_plugin`. Passing
// `--logger=...` fails at startup with gflags' own
// "ERROR: unknown command line flag 'logger'".
int g_argc = 3;
char g_arg0[] = "osquery_embed";
char g_arg1[] = "--disable_extensions=true";
char g_arg2[] = "--logger_plugin=rust_bridge";
char* g_argv_storage[] = {g_arg0, g_arg1, g_arg2, nullptr};
char** g_argv = g_argv_storage;

// Guarded by std::atomic rather than g_mutex: RustBridgeLoggerPlugin::
// logStatus (below) reads this from whatever internal osquery thread is
// relaying a status log, which must never block on the same mutex
// osquery_embed_query/init/shutdown hold for unrelated reasons.
std::atomic<osquery_embed_log_callback> g_log_callback{nullptr};

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

namespace osquery {

// Bridges osquery's own pluggable logger registry (NOT a raw glog log
// sink -- see README/project notes for why the plugin registry is the
// right layer to hook) to a single C callback, so a Rust consumer can
// route osquery's internal status logs (INFO/WARNING/ERROR/FATAL)
// through its own logging setup (e.g. the `log` crate) instead of them
// going straight to stderr or an on-disk log file uncontrolled.
class RustBridgeLoggerPlugin : public LoggerPlugin {
 public:
  bool usesLogStatus() override {
    return true;
  }

 protected:
  // Scheduled query *result* logging is a separate concern from internal
  // status logging -- not routed through osquery_embed_log_callback here.
  Status logString(const std::string& /*s*/) override {
    return Status::success();
  }

  void init(const std::string& /*name*/,
            const std::vector<StatusLogLine>& log) override {
    // Matches upstream's own StdoutLoggerPlugin::init
    // (plugins/logger/stdout.cpp): now that a plugin is actively
    // receiving every status log instead, stop Glog's own direct-to-
    // stderr writing so messages aren't duplicated.
    FLAGS_alsologtostderr = false;
    FLAGS_logtostderr = false;
    FLAGS_stderrthreshold = 5;

    // Replay whatever status logs accumulated before this plugin was
    // activated (early startup logging -- see LoggerPlugin::init's own
    // doc comment).
    logStatus(log);
  }

  Status logStatus(const std::vector<StatusLogLine>& log) override {
    auto callback = g_log_callback.load(std::memory_order_relaxed);
    if (callback != nullptr) {
      for (const auto& item : log) {
        callback(static_cast<int32_t>(item.severity),
                 item.filename.data(),
                 item.filename.size(),
                 static_cast<int32_t>(item.line),
                 item.message.data(),
                 item.message.size());
      }
    }
    return Status::success();
  }
};

REGISTER(RustBridgeLoggerPlugin, "logger", "rust_bridge");

} // namespace osquery

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

  // Held for the whole call, not just the init check below: osquery's
  // query engine and table generators (e.g. the `users` table's
  // getpwnam/getpwuid, which use process-wide static buffers rather than
  // the thread-safe `_r` variants, and macOS's OpenDirectory calls) plus
  // its internal logger plumbing are not safe for concurrent invocation
  // from multiple threads at once -- osquery's own dispatcher normally
  // only ever runs one query at a time. Without this, two Rust callers
  // (or two tests running in parallel against a shared OsqueryInstance)
  // racing into osquery::query() concurrently intermittently throws a
  // std::future_errc::no_state exception, surfacing here as a generic
  // "no state" QueryFailed error from virtual_table.cpp's own catch block.
  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_initializer == nullptr) {
    return OSQUERY_EMBED_NOT_INITIALIZED;
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

extern "C" void osquery_embed_set_log_callback(
    osquery_embed_log_callback callback) {
  g_log_callback.store(callback, std::memory_order_relaxed);
}
