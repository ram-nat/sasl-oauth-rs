//! SASL XOAUTH2 plugin entry point.
//!
//! Exports `sasl_client_plug_init` for Cyrus SASL to discover and load.

mod client;
pub mod config;
mod ffi;
pub mod log;
pub mod token_store;

use libc::{c_char, c_int, c_uint, c_void};
use std::ptr;

use crate::client::Client;
use crate::ffi::*;

// ---------------------------------------------------------------------------
// Plugin callback functions (C ABI)
// ---------------------------------------------------------------------------

/// Called by SASL when a new authentication exchange begins.
unsafe extern "C" fn mech_new(
    _glob_context: *mut c_void,
    _params: *mut sasl_client_params_t,
    context: *mut *mut c_void,
) -> c_int {
    let client = Box::new(Client::new());
    *context = Box::into_raw(client) as *mut c_void;
    SASL_OK
}

/// Called by SASL for each step of the authentication exchange.
unsafe extern "C" fn mech_step(
    context: *mut c_void,
    params: *mut sasl_client_params_t,
    from_server: *const c_char,
    from_server_len: c_uint,
    prompt_need: *mut *mut sasl_interact_t,
    to_server: *mut *const c_char,
    to_server_len: *mut c_uint,
    out_params: *mut sasl_out_params_t,
) -> c_int {
    if context.is_null() {
        return SASL_BADPARAM;
    }
    let client = &mut *(context as *mut Client);
    client.do_step(
        params,
        from_server,
        from_server_len,
        prompt_need,
        to_server,
        to_server_len,
        out_params,
    )
}

/// Called by SASL when the authentication exchange is done (cleanup).
unsafe extern "C" fn mech_dispose(context: *mut c_void, _utils: *const sasl_utils_t) {
    if !context.is_null() {
        // Reconstruct the Box so it gets dropped properly
        let _ = Box::from_raw(context as *mut Client);
    }
}

// ---------------------------------------------------------------------------
// Static plugin descriptor
// ---------------------------------------------------------------------------

/// The mechanism name as a C string (must be 'static and null-terminated).
static MECH_NAME: &[u8] = b"XOAUTH2\0";

/// Plugin descriptor — static, lives for the lifetime of the process.
static PLUGIN: sasl_client_plug_t = sasl_client_plug_t {
    mech_name: MECH_NAME.as_ptr() as *const c_char,
    max_ssf: 60,
    security_flags: (SASL_SEC_NOANONYMOUS | SASL_SEC_PASS_CREDENTIALS) as u32,
    features: (SASL_FEAT_WANT_CLIENT_FIRST | SASL_FEAT_ALLOWS_PROXY) as u32,
    required_prompts: ptr::null(),
    glob_context: ptr::null_mut(),
    mech_new: Some(mech_new),
    mech_step: Some(mech_step),
    mech_dispose: Some(mech_dispose),
    mech_free: None,
    idle: None,
    spare_fptr1: None,
    spare_fptr2: None,
};

// ---------------------------------------------------------------------------
// Exported entry point
// ---------------------------------------------------------------------------

/// Entry point called by Cyrus SASL when loading this plugin.
///
/// # Safety
/// Called by the SASL framework with valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sasl_client_plug_init(
    utils: *const sasl_utils_t,
    max_version: c_int,
    out_version: *mut c_int,
    plug_list: *mut *const sasl_client_plug_t,
    plug_count: *mut c_int,
) -> c_int {
    if max_version < SASL_CLIENT_PLUG_VERSION {
        if !utils.is_null() {
            if let Some(seterror) = (*utils).seterror {
                let msg = b"sasl-xoauth2: need version %d, got %d\0";
                seterror(
                    (*utils).conn,
                    0,
                    msg.as_ptr() as *const c_char,
                    SASL_CLIENT_PLUG_VERSION,
                    max_version,
                );
            }
        }
        return SASL_BADVERS;
    }

    // Initialize config before chroot (Postfix chroots after plugin init).
    let err = config::Config::init();
    if err != SASL_OK {
        return err;
    }

    *out_version = SASL_CLIENT_PLUG_VERSION;
    *plug_list = &PLUGIN as *const sasl_client_plug_t;
    *plug_count = 1;
    SASL_OK
}
