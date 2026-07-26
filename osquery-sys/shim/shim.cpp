// Copyright (c) 2014-present, The osquery authors
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

#include "shim.h"

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <array>
#include <signal.h>
#endif

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
bool g_init_called = false;
bool g_shutdown_called = false;

// osquery::Initializer::shutdown() enforces (via its own file-local
// kMainThreadId, set to std::this_thread::get_id() inside the constructor
// -- see osquery/core/init.cpp) that it is only ever called from the exact
// OS thread that constructed the Initializer; any other caller gets an
// immediate std::runtime_error("Requested shutdown from service thread").
// Rust's own test harness (and, more generally, any caller that lazily
// initializes a shared/static OsqueryInstance) runs the code that first
// calls osquery_embed_init on an arbitrary, often short-lived worker
// thread -- never the process's real main thread. A later shutdown
// (whether triggered by OsqueryInstance::Drop or a process-exit hook) is
// very likely to run from a *different* thread (e.g. the real CRT main
// thread at process exit), so calling Initializer::shutdown() directly
// from wherever osquery_embed_shutdown happens to be called throws
// immediately, gets swallowed by this file's own catch blocks, and
// silently no-ops -- Dispatcher::stopServices()/joinServices() never
// actually run, leaving Windows's UsersService/GroupsService (started by
// initWorkerWatcher() below) running unjoined at process exit. This is
// the actual cause of a Windows STATUS_STACK_BUFFER_OVERRUN observed at
// exit even after every test passed.
//
// Fix: dedicate one persistent OS thread to own the Initializer's entire
// lifetime. osquery_embed_init spawns it and blocks (via a promise/future)
// until construction+start() finish on that thread; the thread then parks
// on a condition variable until osquery_embed_shutdown signals it, at
// which point it calls Initializer::shutdown() itself -- always from the
// same thread that did the constructing, satisfying kMainThreadId
// regardless of which arbitrary caller thread requested init or shutdown.
// Queries are unaffected: osquery::query() has no such thread-affinity
// check (confirmed by reading virtual_table.cpp/sql.cpp), so
// osquery_embed_query keeps running directly on whichever thread calls it.
std::thread g_owner_thread;
std::mutex g_owner_mutex;
std::condition_variable g_owner_cv;
bool g_owner_shutdown_requested = false;

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

#if !defined(_WIN32)
// osquery::Initializer's constructor/start() install raw signal()/
// sigaction() handlers for these signals, unconditionally replacing
// whatever the host process (e.g. Rust/tokio via signal-hook-registry) had
// installed -- confirmed both by reading this behavior and documented on
// the Rust side in osquery::instance.rs. In this embedded, no-dispatcher-
// loop use case, osquery's own replacement handler is never observed by
// anything (there's no osquery main loop polling a "shutdown requested"
// flag), so once it's installed, the host process's own SIGINT/SIGTERM
// handling silently stops working. Save the host's dispositions before
// Initializer construction and restore them right after, so this embedded
// init doesn't leave the host process unable to be signaled.
constexpr int kGuardedSignals[] = {SIGHUP, SIGINT, SIGTERM, SIGABRT, SIGUSR1};

std::array<struct sigaction, std::size(kGuardedSignals)>
save_signal_dispositions() {
  std::array<struct sigaction, std::size(kGuardedSignals)> saved{};
  for (size_t i = 0; i < std::size(kGuardedSignals); ++i) {
    sigaction(kGuardedSignals[i], nullptr, &saved[i]);
  }
  return saved;
}

void restore_signal_dispositions(
    const std::array<struct sigaction, std::size(kGuardedSignals)>& saved) {
  for (size_t i = 0; i < std::size(kGuardedSignals); ++i) {
    sigaction(kGuardedSignals[i], &saved[i], nullptr);
  }
}
#endif // !defined(_WIN32)

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
  if (g_init_called) {
    return OSQUERY_EMBED_ALREADY_INITIALIZED;
  }
  g_init_called = true;

  // See g_owner_thread's own doc comment above for the full reasoning.
  // Construction/start() run on a dedicated thread that then parks until
  // shutdown is requested, so Initializer::shutdown() is always called
  // from the same thread that constructed it, regardless of which
  // arbitrary caller thread called osquery_embed_init/osquery_embed_shutdown.
  std::promise<int32_t> init_result_promise;
  auto init_result_future = init_result_promise.get_future();

  g_owner_thread = std::thread([&init_result_promise]() {
    int32_t result_code = OSQUERY_EMBED_OK;
#if !defined(_WIN32)
    // See kGuardedSignals' own doc comment: Initializer construction/start()
    // below is about to hijack the host process's signal handlers.
    auto saved_signals = save_signal_dispositions();
#endif
    try {
      // Belt-and-suspenders #1: set before construction, in case anything
      // during construction (before flag parsing) reads it.
      osquery::FLAGS_disable_extensions = true;

      g_initializer = std::make_unique<osquery::Initializer>(
          g_argc, g_argv, osquery::ToolType::SHELL);

      // Belt-and-suspenders #2 (argv above) already covers flag parsing;
      // set again explicitly before start() per the confirmed recipe, in
      // case a config/flagfile the shell auto-loads tried to flip it back.
      osquery::FLAGS_disable_extensions = true;

      // Mirrors upstream osquery/main/main.cpp's own call order
      // (initDaemon() then initWorkerWatcher(), both before start()).
      // initDaemon() is a no-op here (its own !isDaemon() guard returns
      // immediately for ToolType::SHELL), but initWorkerWatcher() is NOT:
      // on Windows it's the only place that arms GlobalUsersGroupsCache's
      // std::shared_future<void> members and starts the UsersService/
      // GroupsService background services that actually populate the
      // users/groups tables (see
      // osquery/core/windows/global_users_groups_cache.{h,cpp} and
      // osquery/core/init.cpp's Initializer::initWorkerWatcher). Nothing
      // else in this shim ever called it, so on Windows that future stayed
      // a default-constructed (no shared state) std::shared_future forever
      // -- GlobalUsersGroupsCache::getUsersCache()'s wait_for() on it
      // throws std::future_error(future_errc::no_state), surfacing as a
      // "no state" QueryFailed error from virtual_table.cpp on every
      // `users`/`groups` query. Safe to call unconditionally on every
      // platform: with the shell tool type forcing
      // FLAGS_disable_watchdog=true (set inside the Initializer
      // constructor above, before ParseCommandLineFlags returns) and no
      // autoloaded extensions, isWatcher() is false, so the rest of
      // initWorkerWatcher()'s body (initWatcher()) returns without
      // blocking or spawning any process -- exactly what osquery's own
      // shell tool does, not something novel to this shim.
      g_initializer->initDaemon();
      g_initializer->initWorkerWatcher();

      g_initializer->start();
    } catch (const std::exception&) {
      g_initializer.reset();
      result_code = OSQUERY_EMBED_EXCEPTION;
    } catch (...) {
      g_initializer.reset();
      result_code = OSQUERY_EMBED_UNKNOWN;
    }

#if !defined(_WIN32)
    // Undo whatever signal handlers Initializer construction/start() just
    // installed, regardless of success/failure -- a partially-constructed
    // Initializer may still have installed them before an exception unwound.
    restore_signal_dispositions(saved_signals);
#endif

    init_result_promise.set_value(result_code);

    if (result_code != OSQUERY_EMBED_OK) {
      // Init itself failed; nothing was started, so there's nothing to
      // wait around to shut down -- exit immediately.
      return;
    }

    {
      std::unique_lock<std::mutex> owner_lock(g_owner_mutex);
      g_owner_cv.wait(owner_lock, [] { return g_owner_shutdown_requested; });
    }

    try {
      g_initializer->shutdown(0);
    } catch (...) {
      // Nothing more this thread can do about a failed shutdown; let it
      // exit regardless so osquery_embed_shutdown's join() doesn't hang.
    }
  });

  auto code = init_result_future.get();
  if (code == OSQUERY_EMBED_OK) {
    // Backstop: guarantees a clean shutdown (stopping/joining
    // UsersService/GroupsService et al.) runs before process teardown even
    // if no Rust Drop ever fires for a leaked/static-held OsqueryInstance.
    // osquery_embed_shutdown is idempotent (see g_shutdown_called), so this
    // is harmless even when the Rust side also calls it explicitly.
    std::atexit([]() { osquery_embed_shutdown(); });
  } else {
    // Failed init already returned on the owner thread; join it and allow
    // a later call to try again.
    g_owner_thread.join();
    g_init_called = false;
  }
  return code;
}

extern "C" int32_t osquery_embed_shutdown(void) {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (!g_init_called) {
    return OSQUERY_EMBED_NOT_INITIALIZED;
  }
  if (g_shutdown_called) {
    return OSQUERY_EMBED_OK;
  }
  g_shutdown_called = true;

  {
    std::lock_guard<std::mutex> owner_lock(g_owner_mutex);
    g_owner_shutdown_requested = true;
  }
  g_owner_cv.notify_all();
  g_owner_thread.join();

  return OSQUERY_EMBED_OK;
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
