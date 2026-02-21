//! Global configuration loaded from `/etc/sasl-xoauth2.conf`.

use serde::Deserialize;
use std::fs;
use std::sync::OnceLock;

use crate::ffi;

/// Default config file path.
const DEFAULT_CONFIG_PATH: &str = "/etc/sasl-xoauth2.conf";

/// Default token endpoint (O365).
const DEFAULT_TOKEN_ENDPOINT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/token";

static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default = "default_token_endpoint")]
    pub token_endpoint: String,
    #[serde(default = "default_true")]
    pub log_to_syslog_on_failure: bool,
    #[serde(default)]
    pub always_log_to_syslog: bool,
    #[serde(default)]
    pub log_full_trace_on_failure: bool,
    #[serde(default = "default_refresh_window")]
    pub refresh_window: i64,
}

fn default_token_endpoint() -> String {
    DEFAULT_TOKEN_ENDPOINT.to_string()
}

fn default_true() -> bool {
    true
}

fn default_refresh_window() -> i64 {
    10
}

impl Config {
    /// Initialize the global config from the default path.
    /// Called once during `sasl_client_plug_init` (before chroot).
    pub fn init() -> i32 {
        Self::init_from_path(DEFAULT_CONFIG_PATH)
    }

    /// Initialize from a specific path (useful for testing).
    pub fn init_from_path(path: &str) -> i32 {
        match fs::read_to_string(path) {
            Ok(contents) => match serde_json::from_str::<Config>(&contents) {
                Ok(config) => {
                    let _ = CONFIG.set(config);
                    ffi::SASL_OK
                }
                Err(e) => {
                    eprintln!("sasl-xoauth2: failed to parse config {}: {}", path, e);
                    ffi::SASL_FAIL
                }
            },
            Err(e) => {
                eprintln!("sasl-xoauth2: failed to read config {}: {}", path, e);
                ffi::SASL_FAIL
            }
        }
    }

    /// Get the global config. Panics if not initialized.
    pub fn get() -> &'static Config {
        CONFIG.get().expect("Config not initialized")
    }

    /// Check if config has been initialized (for testing).
    pub fn is_initialized() -> bool {
        CONFIG.get().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_full_config() {
        let json = r#"{
            "client_id": "test-id",
            "client_secret": "test-secret",
            "token_endpoint": "https://example.com/token",
            "always_log_to_syslog": true,
            "refresh_window": 600
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.client_id, "test-id");
        assert_eq!(config.client_secret, "test-secret");
        assert_eq!(config.token_endpoint, "https://example.com/token");
        assert!(config.always_log_to_syslog);
        assert_eq!(config.refresh_window, 600);
    }

    #[test]
    fn test_parse_minimal_config() {
        let json = r#"{ "client_id": "id123" }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.client_id, "id123");
        assert_eq!(config.client_secret, "");
        assert_eq!(config.token_endpoint, DEFAULT_TOKEN_ENDPOINT);
        assert!(config.log_to_syslog_on_failure);
        assert!(!config.always_log_to_syslog);
        assert_eq!(config.refresh_window, 10);
    }

    #[test]
    fn test_init_from_file() {
        let mut f = NamedTempFile::new().unwrap();
        write!(
            f,
            r#"{{ "client_id": "from-file", "client_secret": "s" }}"#
        )
        .unwrap();
        let result = Config::init_from_path(f.path().to_str().unwrap());
        assert_eq!(result, ffi::SASL_OK);
    }

    #[test]
    fn test_init_missing_file() {
        let result = Config::init_from_path("/nonexistent/path/config.json");
        assert_eq!(result, ffi::SASL_FAIL);
    }
}
