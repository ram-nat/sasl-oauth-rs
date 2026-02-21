//! XOAUTH2 client state machine — the core SASL mechanism logic.
//!
//! Implements the two-step XOAUTH2 protocol:
//! 1. InitialStep: extract user + token path from SASL callbacks, send bearer token
//! 2. TokenSentStep: handle server response, retry on 401/400

use libc::{c_char, c_int, c_uint, c_ulong, c_void};
use std::ptr;
use std::slice;

use crate::config::Config;
use crate::ffi::*;
use crate::log::{Log, LogMode};
use crate::token_store::TokenStore;

#[derive(Debug, PartialEq)]
enum State {
    Initial,
    TokenSent,
}

pub struct Client {
    state: State,
    user: String,
    response: Vec<u8>, // kept alive so the pointer we return to SASL remains valid
    log: Log,
    token: Option<TokenStore>,
}

impl Client {
    pub fn new() -> Self {
        let config = Config::get();
        let mode = if config.always_log_to_syslog {
            LogMode::Immediate
        } else if config.log_full_trace_on_failure {
            LogMode::FullTraceOnFailure
        } else if config.log_to_syslog_on_failure {
            LogMode::OnFailure
        } else {
            LogMode::None
        };

        let log = Log::new(mode);
        log.write("Client: created");

        Self {
            state: State::Initial,
            user: String::new(),
            response: Vec::new(),
            log,
            token: None,
        }
    }

    /// Main entry point called by the SASL framework for each protocol step.
    pub unsafe fn do_step(
        &mut self,
        params: *mut sasl_client_params_t,
        from_server: *const c_char,
        from_server_len: c_uint,
        prompt_need: *mut *mut sasl_interact_t,
        to_server: *mut *const c_char,
        to_server_len: *mut c_uint,
        out_params: *mut sasl_out_params_t,
    ) -> c_int {
        self.log
            .write(format!("Client::do_step: state={:?}", self.state));

        let err = match self.state {
            State::Initial => {
                self.initial_step(params, prompt_need, to_server, to_server_len, out_params)
            }
            State::TokenSent => self.token_sent_step(
                params,
                from_server,
                from_server_len,
                to_server,
                to_server_len,
            ),
        };

        if err != SASL_OK && err != SASL_INTERACT {
            self.log.set_flush_on_destroy();
        }
        self.log
            .write(format!("Client::do_step: new state={:?}, err={}", self.state, err));
        err
    }

    unsafe fn initial_step(
        &mut self,
        params: *mut sasl_client_params_t,
        prompt_need: *mut *mut sasl_interact_t,
        to_server: *mut *const c_char,
        to_server_len: *mut c_uint,
        out_params: *mut sasl_out_params_t,
    ) -> c_int {
        *to_server = ptr::null();
        *to_server_len = 0;

        let p = &*params;
        let utils = &*p.utils;

        // Try to get auth name from prompts, then from callback
        let mut auth_name = String::new();
        if !prompt_need.is_null() && !(*prompt_need).is_null() {
            auth_name = read_prompt(*prompt_need, SASL_CB_AUTHNAME);
        }
        if auth_name.is_empty() {
            if let Some(name) = trigger_auth_name_callback(utils) {
                auth_name = name;
            }
        }
        self.log
            .write(format!("initial_step: auth_name='{}'", auth_name));

        // Try to get password (token file path) from prompts, then from callback
        let mut password = String::new();
        if !prompt_need.is_null() && !(*prompt_need).is_null() {
            password = read_prompt(*prompt_need, SASL_CB_PASS);
        }
        if password.is_empty() {
            if let Some(pass) = trigger_password_callback(utils) {
                password = pass;
            }
        }
        self.log
            .write(format!("initial_step: password/path='{}'", password));

        // Free any previous prompts
        if !prompt_need.is_null() && !(*prompt_need).is_null() {
            if let Some(free_fn) = utils.free {
                free_fn(*prompt_need as *mut c_void);
            }
            *prompt_need = ptr::null_mut();
        }

        // If we still need info, request prompts
        if !prompt_need.is_null() && (auth_name.is_empty() || password.is_empty()) {
            self.log.write("initial_step: need prompts, returning SASL_INTERACT");
            return request_prompts(
                params,
                prompt_need,
                auth_name.is_empty(),
                password.is_empty(),
            );
        }

        // Canonicalize user
        if let Some(canon_user) = p.canon_user {
            let err = canon_user(
                utils.conn,
                auth_name.as_ptr() as *const c_char,
                auth_name.len() as c_uint,
                (SASL_CU_AUTHID | SASL_CU_AUTHZID) as c_uint,
                out_params,
            );
            if err != SASL_OK {
                self.log
                    .write(format!("initial_step: canon_user failed: {}", err));
                return err;
            }
        }

        self.user = auth_name;

        // Password field contains the path to the token file
        let store = match TokenStore::new(&self.log, &password) {
            Some(s) => s,
            None => {
                self.log
                    .write(format!("initial_step: TokenStore::new failed for path '{}'", password));
                return SASL_FAIL;
            }
        };

        // If token file has a user override, use that
        if let Some(token_user) = store.user() {
            self.user = token_user.to_string();
        }

        self.token = Some(store);
        let err = self.send_token(to_server, to_server_len);
        if err != SASL_OK {
            return err;
        }

        self.state = State::TokenSent;
        SASL_OK
    }

    unsafe fn token_sent_step(
        &mut self,
        _params: *mut sasl_client_params_t,
        from_server: *const c_char,
        from_server_len: c_uint,
        to_server: *mut *const c_char,
        to_server_len: *mut c_uint,
    ) -> c_int {
        *to_server = ptr::null();
        *to_server_len = 0;

        if from_server_len == 0 {
            return SASL_OK;
        }

        let server_data =
            slice::from_raw_parts(from_server as *const u8, from_server_len as usize);
        let server_str = String::from_utf8_lossy(server_data);
        self.log
            .write(format!("Client::token_sent_step: from server: {}", server_str));

        // Try to parse as JSON and check status
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&server_str) {
            if let Some(status) = json.get("status").and_then(|v| v.as_str()) {
                if status == "400" || status == "401" {
                    // Token was rejected, try refreshing
                    if let Some(ref mut store) = self.token {
                        if let Err(e) = store.refresh(&self.log) {
                            return e;
                        }
                        return SASL_TRYAGAIN;
                    }
                }

                if !status.is_empty() {
                    self.log
                        .write(format!("Client::token_sent_step: status: {}", status));
                    return SASL_BADPROT;
                }
            }
        }

        // Blank status or non-JSON — assume success
        self.log
            .write("Client::token_sent_step: blank status, assuming OK");
        SASL_OK
    }

    unsafe fn send_token(
        &mut self,
        to_server: *mut *const c_char,
        to_server_len: *mut c_uint,
    ) -> c_int {
        let token = match self.token {
            Some(ref mut store) => match store.get_access_token(&self.log) {
                Ok(t) => t,
                Err(e) => return e,
            },
            None => return SASL_FAIL,
        };

        // Build XOAUTH2 response: user=<email>\x01auth=Bearer <token>\x01\x01
        self.response = format!("user={}\x01auth=Bearer {}\x01\x01", self.user, token)
            .into_bytes();

        self.log
            .write(format!("Client::send_token: response len={}", self.response.len()));

        *to_server = self.response.as_ptr() as *const c_char;
        *to_server_len = self.response.len() as c_uint;

        SASL_OK
    }
}

// ---------------------------------------------------------------------------
// Helper functions for interacting with SASL callbacks
// ---------------------------------------------------------------------------

unsafe fn read_prompt(prompts: *mut sasl_interact_t, id: c_int) -> String {
    if prompts.is_null() {
        return String::new();
    }
    let mut p = prompts;
    loop {
        if (*p).id == SASL_CB_LIST_END as c_ulong {
            break;
        }
        if (*p).id == id as c_ulong && !(*p).result.is_null() && (*p).len > 0 {
            let data = slice::from_raw_parts((*p).result as *const u8, (*p).len as usize);
            return String::from_utf8_lossy(data).to_string();
        }
        p = p.add(1);
    }
    String::new()
}

unsafe fn trigger_auth_name_callback(utils: &sasl_utils_t) -> Option<String> {
    let getcallback = utils.getcallback?;
    let mut callback: sasl_callback_ft = None;
    let mut context: *mut c_void = ptr::null_mut();
    let err = getcallback(
        utils.conn,
        SASL_CB_AUTHNAME as c_ulong,
        &mut callback as *mut sasl_callback_ft,
        &mut context,
    );
    if err != SASL_OK {
        return None;
    }
    let cb: sasl_getsimple_t = std::mem::transmute(callback?);
    let mut result: *const c_char = ptr::null();
    let mut len: c_uint = 0;
    let err = cb(context, SASL_CB_AUTHNAME, &mut result, &mut len);
    if err != SASL_OK || result.is_null() {
        return None;
    }
    let data = slice::from_raw_parts(result as *const u8, len as usize);
    Some(String::from_utf8_lossy(data).to_string())
}

unsafe fn trigger_password_callback(utils: &sasl_utils_t) -> Option<String> {
    let getcallback = utils.getcallback?;
    let mut callback: sasl_callback_ft = None;
    let mut context: *mut c_void = ptr::null_mut();
    let err = getcallback(
        utils.conn,
        SASL_CB_PASS as c_ulong,
        &mut callback as *mut sasl_callback_ft,
        &mut context,
    );
    if err != SASL_OK {
        return None;
    }
    let cb: sasl_getsecret_t = std::mem::transmute(callback?);
    let mut secret: *mut sasl_secret_t = ptr::null_mut();
    let err = cb(utils.conn, context, SASL_CB_PASS, &mut secret);
    if err != SASL_OK || secret.is_null() {
        return None;
    }
    let data = slice::from_raw_parts((*secret).data.as_ptr(), (*secret).len as usize);
    Some(String::from_utf8_lossy(data).to_string())
}

unsafe fn request_prompts(
    params: *mut sasl_client_params_t,
    prompts: *mut *mut sasl_interact_t,
    need_auth_name: bool,
    need_password: bool,
) -> c_int {
    if prompts.is_null() || (!need_auth_name && !need_password) {
        return SASL_BADPARAM;
    }

    let utils = &*(*params).utils;
    let malloc = match utils.malloc {
        Some(f) => f,
        None => return SASL_NOMEM,
    };

    // +1 for trailing LIST_END sentinel
    let num_prompts = (need_auth_name as usize) + (need_password as usize) + 1;
    let size = std::mem::size_of::<sasl_interact_t>() * num_prompts;
    let ptr = malloc(size) as *mut sasl_interact_t;
    if ptr.is_null() {
        return SASL_NOMEM;
    }
    std::ptr::write_bytes(ptr, 0, num_prompts);

    let mut i = 0;
    if need_auth_name {
        let p = &mut *ptr.add(i);
        p.id = SASL_CB_AUTHNAME as c_ulong;
        p.challenge = b"Authentication Name\0".as_ptr() as *const c_char;
        p.prompt = b"Authentication Name\0".as_ptr() as *const c_char;
        i += 1;
    }
    if need_password {
        let p = &mut *ptr.add(i);
        p.id = SASL_CB_PASS as c_ulong;
        p.challenge = b"Password\0".as_ptr() as *const c_char;
        p.prompt = b"Password\0".as_ptr() as *const c_char;
        i += 1;
    }
    // Sentinel
    (*ptr.add(i)).id = SASL_CB_LIST_END as c_ulong;

    *prompts = ptr;
    SASL_INTERACT
}
