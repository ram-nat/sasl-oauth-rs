//! FFI bindings for the Cyrus SASL plugin API.
//!
//! Generated at build time by bindgen from <sasl/sasl.h> and <sasl/saslplug.h>.
//! This guarantees correct struct layouts for whatever version of libsasl2-dev
//! is installed on the build machine.
//!
//! Build requirement: libsasl2-dev (apt install libsasl2-dev)

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    clippy::all
)]

include!(concat!(env!("OUT_DIR"), "/sasl_bindings.rs"));

// ---------------------------------------------------------------------------
// Convenience type aliases for callback function pointers.
// These are not in the SASL headers but are needed for transmuting
// the generic callback returned by getcallback into typed callbacks.
// ---------------------------------------------------------------------------

use std::os::raw::{c_char, c_int, c_uint, c_void};

/// Callback for getting simple string values (auth name, etc.)
pub type sasl_getsimple_t = unsafe extern "C" fn(
    context: *mut c_void,
    id: c_int,
    result: *mut *const c_char,
    len: *mut c_uint,
) -> c_int;

/// Callback for getting the password/secret.
pub type sasl_getsecret_t = unsafe extern "C" fn(
    conn: *mut sasl_conn_t,
    context: *mut c_void,
    id: c_int,
    psecret: *mut *mut sasl_secret_t,
) -> c_int;

// Safety: the plugin struct contains only function pointers and a const string
// pointer. It is initialized once and never mutated.
unsafe impl Sync for sasl_client_plug_t {}
unsafe impl Send for sasl_client_plug_t {}
