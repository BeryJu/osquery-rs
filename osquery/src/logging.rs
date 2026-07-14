use std::ffi::c_char;

use osquery_sys::{
    OSQUERY_EMBED_LOG_ERROR, OSQUERY_EMBED_LOG_FATAL, OSQUERY_EMBED_LOG_INFO,
    OSQUERY_EMBED_LOG_WARNING,
};

/// Registers a callback with the embedded runtime that forwards every
/// osquery-internal status log (INFO/WARNING/ERROR/FATAL -- osquery's own
/// glog-based diagnostic logging, not scheduled query results) through the
/// `log` crate under target `"osquery"`, instead of it going straight to
/// stderr or an on-disk log file. Called once by `OsqueryInstance::start`,
/// before the embedded runtime itself starts up, so early startup log
/// lines are captured too (see shim.h's `osquery_embed_set_log_callback`).
pub(crate) fn install() {
    unsafe {
        osquery_sys::osquery_embed_set_log_callback(Some(log_trampoline));
    }
}

extern "C" fn log_trampoline(
    severity: i32,
    filename: *const c_char,
    filename_len: usize,
    line: i32,
    message: *const c_char,
    message_len: usize,
) {
    let level = match severity {
        OSQUERY_EMBED_LOG_INFO => log::Level::Info,
        OSQUERY_EMBED_LOG_WARNING => log::Level::Warn,
        OSQUERY_EMBED_LOG_ERROR | OSQUERY_EMBED_LOG_FATAL => log::Level::Error,
        _ => log::Level::Info,
    };

    let metadata = log::Metadata::builder()
        .level(level)
        .target("osquery")
        .build();
    if !log::logger().enabled(&metadata) {
        return;
    }

    // SAFETY: shim.cpp's RustBridgeLoggerPlugin passes pointers into a
    // std::string's own backing buffer, valid (and non-null, even for an
    // empty string, per std::string::data()'s guarantee since C++11) for
    // the duration of this call only.
    let filename = unsafe { std::slice::from_raw_parts(filename as *const u8, filename_len) };
    let message = unsafe { std::slice::from_raw_parts(message as *const u8, message_len) };
    let filename = String::from_utf8_lossy(filename);
    let message = String::from_utf8_lossy(message);

    log::logger().log(
        &log::Record::builder()
            .metadata(metadata)
            .file(Some(&filename))
            .line(Some(line as u32))
            .args(format_args!("{message}"))
            .build(),
    );
}
