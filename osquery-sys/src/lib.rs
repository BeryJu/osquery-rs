//! Raw, unsafe FFI bindings to the `osquery_embed_shim` C API (see
//! `shim/shim.h`). This crate has no lifecycle safety guarantees of its own
//! (no singleton enforcement, no `Drop`) -- see the `osquery` crate for a
//! safe wrapper. Prefer that crate unless you have a specific reason not to.
//!
//! Hand-written rather than bindgen-generated: shim.h's surface is four
//! functions and one enum, and bindgen requires libclang to be available at
//! build time purely to parse that -- not worth the extra system dependency
//! for a header this small. Keep this in sync with shim/shim.h by hand.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

pub const OSQUERY_EMBED_OK: u32 = 0;
pub const OSQUERY_EMBED_ALREADY_INITIALIZED: u32 = 1;
pub const OSQUERY_EMBED_NOT_INITIALIZED: u32 = 2;
pub const OSQUERY_EMBED_QUERY_FAILED: u32 = 3;
pub const OSQUERY_EMBED_EXCEPTION: u32 = 4;
pub const OSQUERY_EMBED_UNKNOWN: u32 = 5;

extern "C" {
    pub fn osquery_embed_init(argc: c_int, argv: *mut *mut c_char) -> i32;
    pub fn osquery_embed_shutdown() -> i32;
    pub fn osquery_embed_query(
        sql: *const c_char,
        sql_len: usize,
        out_json: *mut *mut c_char,
        out_len: *mut usize,
    ) -> i32;
    pub fn osquery_embed_free_string(ptr: *mut c_char);
}
