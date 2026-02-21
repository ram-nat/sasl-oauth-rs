# sasl-xoauth2-rs

A Rust reimplementation of [sasl-xoauth2](https://github.com/tarickb/sasl-xoauth2) — a SASL client plugin providing XOAUTH2 authentication for SMTP relays like **Microsoft 365** and **Gmail**.

## Why Rust?

The genie preferred it and it sounded fun. It does avoid the dependency on openssl and libcurl - however, it brings in rust equivalent in rustls and ureq.

## Quick Start

### Build

```bash
# Install build dependencies
sudo apt install libsasl2-dev

# Build
cargo build --release
```

### Install

```bash
# Copy the plugin
sudo cp target/release/libsaslxoauth2.so /usr/lib/x86_64-linux-gnu/sasl2/

# Copy the config
sudo cp config/sasl-xoauth2.conf /etc/
```

### Configure

Edit `/etc/sasl-xoauth2.conf` with your Azure app credentials:

```json
{
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "",
  "token_endpoint": "https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/token"
}
```

### Bootstrap Tokens

Use the included Python script to acquire initial tokens via device flow:

```bash
pip3 install msal

# Outlook / O365 (uses device flow by default)
./scripts/sasl-xoauth2-tool get-token outlook \
    --client-id=YOUR_CLIENT_ID \
    --tenant=YOUR_TENANT_ID \
    /path/to/token-file.json
```

The script will display a URL and code — sign in from any browser to authorize.

### Postfix Configuration

```ini
# /etc/postfix/main.cf
relayhost = [smtp.office365.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options =
smtp_sasl_mechanism_filter = xoauth2
smtp_tls_security_level = encrypt
```

```
# /etc/postfix/sasl_passwd
# The "password" is the path to the token file
[smtp.office365.com]:587 user@example.com:/etc/tokens/user@example.com
```

```bash
sudo postmap /etc/postfix/sasl_passwd
sudo chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
```

### Token File Permissions

The plugin needs to write updated tokens after refresh. If Postfix runs chrooted:

```bash
sudo mkdir -p /var/spool/postfix/etc/tokens/
sudo chown postfix:postfix /var/spool/postfix/etc/tokens/
sudo chmod 700 /var/spool/postfix/etc/tokens/
# Token files go here; sasl_passwd paths are relative to the chroot
```

## Testing Token Refresh

Test that your config and token file work without going through Postfix:

```bash
# Build the test tool
cargo build --release

# Test token refresh
./target/release/sasl-xoauth2-test /path/to/token-file.json

# With a custom config path
./target/release/sasl-xoauth2-test /path/to/token-file.json --config /path/to/sasl-xoauth2.conf
```

## Configuration Reference

`/etc/sasl-xoauth2.conf`:

| Field | Default | Description |
|-------|---------|-------------|
| `client_id` | *(required)* | OAuth2 application client ID |
| `client_secret` | `""` | OAuth2 client secret (empty for public apps) |
| `token_endpoint` | O365 common | OAuth2 token endpoint URL |
| `always_log_to_syslog` | `false` | Log all trace messages immediately |
| `log_to_syslog_on_failure` | `false` | Log buffered messages on auth failure |
| `log_full_trace_on_failure` | `false` | Log full trace on auth failure |
| `refresh_window` | `600` | Seconds before expiry to trigger refresh |

## Token File Format

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "expiry": 1234567890,
  "user": "user@example.com"
}
```

Optional per-token overrides: `client_id`, `client_secret`, `token_endpoint`, `refresh_window`.

## Packaging

```bash
cargo install cargo-deb
cargo deb
# Produces target/debian/sasl-xoauth2_0.1.0_amd64.deb
```

## License

Apache-2.0

## Acknowledgments

Based on [sasl-xoauth2](https://github.com/tarickb/sasl-xoauth2) by Tarick Bedeir.
