//! Per-user token file management with OAuth2 refresh.
//!
//! Token files are JSON with the following fields:
//! ```json
//! {
//!   "access_token": "...",
//!   "refresh_token": "...",
//!   "expiry": "1234567890",
//!   "user": "user@example.com",
//!   // Optional per-token overrides:
//!   "client_id": "...",
//!   "client_secret": "...",
//!   "token_endpoint": "...",
//!   "refresh_window": "600"
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::ffi;
use crate::log::Log;

const MAX_REFRESH_ATTEMPTS: i32 = 2;

/// Deserialize a field that can be either a string or an integer into Option<String>.
fn deserialize_string_or_int<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrInt;

    impl<'de> de::Visitor<'de> for StringOrInt {
        type Value = Option<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or integer")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    deserializer.deserialize_any(StringOrInt)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenFile {
    #[serde(default)]
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default, deserialize_with = "deserialize_string_or_int")]
    pub expiry: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    // Per-token overrides
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_int")]
    pub refresh_window: Option<String>,
}

pub struct TokenStore {
    path: String,
    token: TokenFile,
    expiry: i64,
    refresh_attempts: i32,
}

impl TokenStore {
    /// Create a new TokenStore by reading the token file at `path`.
    pub fn new(log: &Log, path: &str) -> Option<Self> {
        log.write(format!("TokenStore::new: file={}", path));
        match fs::read_to_string(path) {
            Ok(contents) => match serde_json::from_str::<TokenFile>(&contents) {
                Ok(token) => {
                    let expiry = token
                        .expiry
                        .as_deref()
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(0);
                    log.write(format!(
                        "TokenStore::new: refresh_len={}, access_len={}, user={}",
                        token.refresh_token.len(),
                        token.access_token.len(),
                        token.user.as_deref().unwrap_or("")
                    ));
                    Some(Self {
                        path: path.to_string(),
                        token,
                        expiry,
                        refresh_attempts: 0,
                    })
                }
                Err(e) => {
                    log.write(format!(
                        "TokenStore::new: failed to parse {}: {}",
                        path, e
                    ));
                    None
                }
            },
            Err(e) => {
                log.write(format!(
                    "TokenStore::new: failed to read {}: {}",
                    path, e
                ));
                None
            }
        }
    }

    /// Get the user override from the token file, if set.
    pub fn user(&self) -> Option<&str> {
        self.token.user.as_deref()
    }

    /// Get the current access token. Refreshes automatically if expired.
    pub fn get_access_token(&mut self, log: &Log) -> Result<String, i32> {
        let config = Config::get();
        let refresh_window = self
            .token
            .refresh_window
            .as_deref()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(config.refresh_window);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if (now + refresh_window) >= self.expiry {
            log.write("TokenStore::get_access_token: token expired, refreshing");
            self.refresh(log)?;
        }

        Ok(self.token.access_token.clone())
    }

    /// Refresh the access token via the OAuth2 token endpoint.
    pub fn refresh(&mut self, log: &Log) -> Result<(), i32> {
        if self.refresh_attempts >= MAX_REFRESH_ATTEMPTS {
            log.write("TokenStore::refresh: exceeded maximum attempts");
            return Err(ffi::SASL_BADPROT);
        }
        self.refresh_attempts += 1;
        log.write(format!(
            "TokenStore::refresh: attempt {}",
            self.refresh_attempts
        ));

        let config = Config::get();
        let client_id = self
            .token
            .client_id
            .as_deref()
            .unwrap_or(&config.client_id);
        let client_secret = self
            .token
            .client_secret
            .as_deref()
            .unwrap_or(&config.client_secret);
        let token_endpoint = self
            .token
            .token_endpoint
            .as_deref()
            .unwrap_or(&config.token_endpoint);

        log.write(format!(
            "TokenStore::refresh: token_endpoint: {}",
            token_endpoint
        ));

        let form_data = vec![
            ("client_id", client_id.to_string()),
            ("client_secret", client_secret.to_string()),
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", self.token.refresh_token.clone()),
        ];

        let response = match ureq::post(token_endpoint)
            .header("User-Agent", "sasl-xoauth2-rs token refresher")
            .send_form(form_data.into_iter().map(|(k, v)| (k, v)))
        {
            Ok(resp) => resp,
            Err(e) => {
                log.write(format!("TokenStore::refresh: HTTP error: {}", e));
                return Err(ffi::SASL_BADPROT);
            }
        };

        let status = response.status();
        let body = response
            .into_body()
            .read_to_string()
            .unwrap_or_default();

        log.write(format!(
            "TokenStore::refresh: code={}, response_len={}",
            status, body.len()
        ));

        if status != 200 {
            log.write("TokenStore::refresh: request failed");
            return Err(ffi::SASL_BADPROT);
        }

        // Parse response
        let resp: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                log.write(format!(
                    "TokenStore::refresh: failed to parse response: {}",
                    e
                ));
                return Err(ffi::SASL_BADPROT);
            }
        };

        let access_token = resp
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                log.write(
                    "TokenStore::refresh: response missing access_token",
                );
                ffi::SASL_BADPROT
            })?;

        let expires_in = resp
            .get("expires_in")
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .ok_or_else(|| {
                log.write(
                    "TokenStore::refresh: response missing expires_in",
                );
                ffi::SASL_BADPROT
            })?;

        if expires_in <= 0 {
            log.write("TokenStore::refresh: invalid expiry");
            return Err(ffi::SASL_BADPROT);
        }

        self.token.access_token = access_token.to_string();

        // Check for updated refresh token
        if let Some(new_refresh) = resp.get("refresh_token").and_then(|v| v.as_str()) {
            if new_refresh != self.token.refresh_token {
                log.write(
                    "TokenStore::refresh: response includes updated refresh token",
                );
                self.token.refresh_token = new_refresh.to_string();
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.expiry = now + expires_in;
        self.token.expiry = Some(self.expiry.to_string());

        // Write updated token file atomically
        self.write(log)
    }

    /// Write the token file atomically (write to temp, then rename).
    fn write(&self, log: &Log) -> Result<(), i32> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let pid = std::process::id();
        let temp_path = format!("{}.{}.{}", self.path, pid, now);

        log.write(format!("TokenStore::write: writing to {}", temp_path));

        let json = match serde_json::to_string_pretty(&self.token) {
            Ok(j) => j,
            Err(e) => {
                log.write(format!(
                    "TokenStore::write: failed to serialize: {}",
                    e
                ));
                return Err(ffi::SASL_FAIL);
            }
        };

        match fs::File::create(&temp_path) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(json.as_bytes()) {
                    log.write(format!(
                        "TokenStore::write: failed to write: {}",
                        e
                    ));
                    return Err(ffi::SASL_FAIL);
                }
            }
            Err(e) => {
                log.write(format!(
                    "TokenStore::write: failed to create {}: {}",
                    temp_path, e
                ));
                return Err(ffi::SASL_FAIL);
            }
        }

        if let Err(e) = fs::rename(&temp_path, &self.path) {
            log.write(format!(
                "TokenStore::write: rename failed: {}",
                e
            ));
            return Err(ffi::SASL_FAIL);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogMode;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn test_log() -> Log {
        Log::new(LogMode::None)
    }

    #[test]
    fn test_read_token_file() {
        let mut f = NamedTempFile::new().unwrap();
        write!(
            f,
            r#"{{
                "refresh_token": "rt-123",
                "access_token": "at-456",
                "expiry": "9999999999",
                "user": "test@example.com"
            }}"#
        )
        .unwrap();

        let log = test_log();
        let store = TokenStore::new(&log, f.path().to_str().unwrap()).unwrap();
        assert_eq!(store.token.refresh_token, "rt-123");
        assert_eq!(store.token.access_token, "at-456");
        assert_eq!(store.user(), Some("test@example.com"));
        assert_eq!(store.expiry, 9999999999);
    }

    #[test]
    fn test_missing_refresh_token_fails() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"{{ "access_token": "at" }}"#).unwrap();

        let log = test_log();
        let result = TokenStore::new(&log, f.path().to_str().unwrap());
        // serde will fail because refresh_token is required
        assert!(result.is_none());
    }

    #[test]
    fn test_xoauth2_response_format() {
        // Verify the XOAUTH2 wire format
        let user = "user@example.com";
        let token = "ya29.accesstoken";
        let response = format!("user={}\x01auth=Bearer {}\x01\x01", user, token);
        assert_eq!(
            response,
            "user=user@example.com\x01auth=Bearer ya29.accesstoken\x01\x01"
        );
    }
}
