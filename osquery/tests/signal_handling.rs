//! Regression test for the signal-hijacking bug fixed in
//! `osquery-sys/shim/shim.cpp`: constructing `osquery::Initializer` used to
//! install raw `signal()`/`sigaction()` handlers for SIGHUP/SIGINT/SIGTERM/
//! SIGABRT/SIGUSR1 that unconditionally replaced whatever the host process
//! already had installed for those signals -- with no osquery dispatcher
//! loop ever observing the "shutdown requested" flag its own handler set, so
//! once installed, the host's own signal handling silently stopped working.
//!
//! This lives in its own integration test binary (cargo gives every file
//! under `tests/` its own process), so it's free to control global signal
//! state without racing other tests that also start an `OsqueryInstance`:
//! it installs a distinctive sentinel handler for a signal
//! `osquery::Initializer` is known to touch (SIGUSR1) *before* the first
//! `OsqueryInstance::start()` call in this process, then asserts the
//! handler survives that call unchanged.

use std::mem;

use osquery::OsqueryInstance;

extern "C" fn sentinel(_: libc::c_int) {}

fn sigusr1_disposition() -> libc::sighandler_t {
    let mut current: libc::sigaction = unsafe { mem::zeroed() };
    let rc = unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut current) };
    assert_eq!(rc, 0, "failed to read current SIGUSR1 disposition");
    current.sa_sigaction
}

#[test]
fn start_preserves_host_signal_handlers() {
    let sentinel_addr = sentinel as *const () as libc::sighandler_t;

    let mut sentinel_action: libc::sigaction = unsafe { mem::zeroed() };
    sentinel_action.sa_sigaction = sentinel_addr;
    unsafe { libc::sigemptyset(&mut sentinel_action.sa_mask) };

    let rc = unsafe { libc::sigaction(libc::SIGUSR1, &sentinel_action, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "failed to install sentinel SIGUSR1 handler");
    assert_eq!(
        sigusr1_disposition(),
        sentinel_addr,
        "sentinel handler wasn't actually installed"
    );

    let _instance = OsqueryInstance::start().expect("failed to start embedded osquery");

    assert_eq!(
        sigusr1_disposition(),
        sentinel_addr,
        "OsqueryInstance::start() overwrote the host's SIGUSR1 handler instead of leaving it \
         intact -- osquery::Initializer construction/start() must save and restore signal \
         dispositions for signals it touches (see shim.cpp)"
    );
}
