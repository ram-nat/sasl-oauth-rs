//! Logging wrapper with optional syslog output.
//!
//! Supports three modes:
//! - Immediate: always write to syslog
//! - OnFailure: buffer lines, flush to syslog on failure
//! - None: discard all log output

use std::fmt;
use std::sync::Mutex;

/// Logging mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogMode {
    /// Always write to syslog immediately.
    Immediate,
    /// Buffer in memory, flush to syslog if `flush()` is called.
    OnFailure,
    /// Buffer the full trace, flush everything on failure.
    FullTraceOnFailure,
    /// Discard all output.
    None,
}

/// Logger instance (one per SASL client session).
pub struct Log {
    mode: LogMode,
    lines: Mutex<Vec<String>>,
    flush_on_destroy: Mutex<bool>,
}

impl Log {
    pub fn new(mode: LogMode) -> Self {
        Self {
            mode,
            lines: Mutex::new(Vec::new()),
            flush_on_destroy: Mutex::new(false),
        }
    }

    /// Write a log message.
    pub fn write(&self, msg: impl fmt::Display) {
        let message = format!("sasl-xoauth2: {}", msg);
        match self.mode {
            LogMode::Immediate => {
                Self::write_to_syslog(&message);
            }
            LogMode::OnFailure | LogMode::FullTraceOnFailure => {
                if let Ok(mut lines) = self.lines.lock() {
                    lines.push(message);
                }
            }
            LogMode::None => {}
        }
    }

    /// Mark that logs should be flushed when this logger is dropped (auth failure).
    pub fn set_flush_on_destroy(&self) {
        if let Ok(mut f) = self.flush_on_destroy.lock() {
            *f = true;
        }
    }

    /// Flush buffered logs to syslog.
    pub fn flush(&self) {
        if let Ok(lines) = self.lines.lock() {
            match self.mode {
                LogMode::FullTraceOnFailure => {
                    for line in lines.iter() {
                        Self::write_to_syslog(line);
                    }
                }
                LogMode::OnFailure => {
                    // Write a summary of the last few lines
                    if let Some(last) = lines.last() {
                        Self::write_to_syslog(last);
                    }
                }
                _ => {}
            }
        }
    }

    fn write_to_syslog(msg: &str) {
        // Use libc syslog directly since we're in a shared library context.
        // LOG_MAIL (2<<3 = 16) | LOG_WARNING (4)
        let c_msg = std::ffi::CString::new(msg).unwrap_or_default();
        let fmt = std::ffi::CString::new("%s").unwrap();
        unsafe {
            libc::syslog(16 | 4, fmt.as_ptr(), c_msg.as_ptr());
        }
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        if let Ok(f) = self.flush_on_destroy.lock() {
            if *f {
                self.flush();
            }
        }
    }
}
