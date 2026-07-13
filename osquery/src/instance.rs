use std::ffi::c_char;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::OsqueryError;
use crate::types::QueryResult;

/// Guards against constructing more than one `OsqueryInstance` in this
/// process, ever. `osquery::Initializer` (the C++ type this wraps) installs
/// process-wide signal handlers (SIGTERM/SIGINT/SIGUSR1) and relies on
/// one-shot global state (gflags, google logging); it was not designed to
/// be constructed and destroyed more than once per process. This flag is
/// intentionally never reset to `false` after a `shutdown()`/`Drop` --
/// re-starting after a shutdown in the same process is refused rather than
/// attempted, since doing so has not been verified safe upstream.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// A running, in-process, embedded osquery runtime.
///
/// This is a process-wide singleton, not a per-instance resource: at most
/// one `OsqueryInstance` may ever be started in a given process (see
/// `INITIALIZED` above). Starting it installs global signal handlers in the
/// host process. There is no on-disk Unix socket involved -- the embedded
/// runtime is started with osquery's extensions API disabled, which is what
/// actually suppresses the socket bind that would otherwise occur.
pub struct OsqueryInstance {
    shutdown_called: bool,
}

impl OsqueryInstance {
    /// Starts the embedded osquery runtime. Returns
    /// `OsqueryError::AlreadyInitialized` if an `OsqueryInstance` has
    /// already been started in this process (whether or not it has since
    /// been shut down).
    pub fn start() -> Result<Self, OsqueryError> {
        if INITIALIZED.compare_exchange(
            false,
            true,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) != Ok(false)
        {
            return Err(OsqueryError::AlreadyInitialized);
        }

        // Must happen before osquery_embed_init: the callback is wired
        // into osquery's own logger plugin registry as part of startup,
        // and registering it first means early startup log lines are
        // captured too, not just ones logged after this call returns.
        crate::logging::install();

        // The shim ignores argc/argv today (it constructs its own fixed
        // argv internally so `--disable_extensions=true` is always
        // present); the parameters exist for future flexibility. See
        // shim/shim.cpp.
        let code = unsafe { osquery_sys::osquery_embed_init(0, ptr::null_mut()) };
        match code as u32 {
            osquery_sys::OSQUERY_EMBED_OK => Ok(OsqueryInstance {
                shutdown_called: false,
            }),
            osquery_sys::OSQUERY_EMBED_ALREADY_INITIALIZED => {
                Err(OsqueryError::AlreadyInitialized)
            }
            _ => Err(OsqueryError::Ffi { code }),
        }
    }

    /// Runs a SQL query in-process and parses the JSON result into rows.
    pub fn query(&self, sql: &str) -> Result<QueryResult, OsqueryError> {
        let mut out_json: *mut c_char = ptr::null_mut();
        let mut out_len: usize = 0;

        let code = unsafe {
            osquery_sys::osquery_embed_query(
                sql.as_ptr() as *const c_char,
                sql.len(),
                &mut out_json,
                &mut out_len,
            )
        };

        let json_bytes = read_and_free(out_json, out_len);

        match code as u32 {
            osquery_sys::OSQUERY_EMBED_OK => {
                let json = json_bytes.ok_or(OsqueryError::Ffi { code })?;
                let result: QueryResult = serde_json::from_slice(&json)?;
                Ok(result)
            }
            osquery_sys::OSQUERY_EMBED_QUERY_FAILED => {
                let message = json_bytes
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .and_then(|v| {
                        v.get("error")
                            .and_then(|e| e.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "query failed".to_string());
                Err(OsqueryError::QueryFailed { message })
            }
            osquery_sys::OSQUERY_EMBED_NOT_INITIALIZED => Err(OsqueryError::NotInitialized),
            _ => Err(OsqueryError::Ffi { code }),
        }
    }

    /// Cleanly shuts down the embedded runtime. Safe to call more than
    /// once; also called automatically on `Drop`.
    pub fn shutdown(&mut self) -> Result<(), OsqueryError> {
        if self.shutdown_called {
            return Ok(());
        }
        let code = unsafe { osquery_sys::osquery_embed_shutdown() };
        self.shutdown_called = true;
        match code as u32 {
            osquery_sys::OSQUERY_EMBED_OK => Ok(()),
            osquery_sys::OSQUERY_EMBED_NOT_INITIALIZED => Err(OsqueryError::NotInitialized),
            _ => Err(OsqueryError::Ffi { code }),
        }
    }
}

impl Drop for OsqueryInstance {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn read_and_free(ptr: *mut c_char, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec();
    unsafe { osquery_sys::osquery_embed_free_string(ptr) };
    Some(bytes)
}
