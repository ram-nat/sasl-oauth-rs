//! CLI tool for testing SASL XOAUTH2 token refresh without Postfix.
//!
//! Usage:
//!   sasl-xoauth2-test <token-file> [--config <config-path>]
//!
//! Loads the plugin configuration, reads the token file, forces a refresh,
//! and reports success or failure.

use std::env;
use std::process;

use saslxoauth2::config::Config;
use saslxoauth2::log::{Log, LogMode};
use saslxoauth2::token_store::TokenStore;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        eprintln!("Usage: {} <token-file> [--config <config-path>]", args[0]);
        eprintln!();
        eprintln!("Tests SASL XOAUTH2 token refresh without running Postfix.");
        eprintln!();
        eprintln!("Arguments:");
        eprintln!("  <token-file>                 Path to the OAuth2 token JSON file");
        eprintln!("  --config <path>              Config file (default: /etc/sasl-xoauth2.conf)");
        process::exit(1);
    }

    let token_path = &args[1];
    let config_path = if let Some(pos) = args.iter().position(|a| a == "--config") {
        args.get(pos + 1)
            .unwrap_or_else(|| {
                eprintln!("Error: --config requires a path argument");
                process::exit(1);
            })
            .as_str()
    } else {
        "/etc/sasl-xoauth2.conf"
    };

    // Load config
    println!("Loading config from: {}", config_path);
    let err = Config::init_from_path(config_path);
    if err != 0 {
        eprintln!("Error: failed to load config from {}", config_path);
        process::exit(1);
    }

    let config = Config::get();
    println!("  client_id: {}", config.client_id);
    println!("  token_endpoint: {}", config.token_endpoint);

    // Load token file
    let log = Log::new(LogMode::Immediate);
    println!("\nLoading token file: {}", token_path);
    let mut store = match TokenStore::new(&log, token_path) {
        Some(s) => s,
        None => {
            eprintln!("Error: failed to load token file {}", token_path);
            process::exit(1);
        }
    };

    if let Some(user) = store.user() {
        println!("  user: {}", user);
    }

    // Force refresh
    println!("\nAttempting token refresh...");
    match store.refresh(&log) {
        Ok(()) => {
            println!("Token refresh successful!");
            println!("  New token written to: {}", token_path);
        }
        Err(code) => {
            eprintln!("Token refresh failed with SASL error code: {}", code);
            process::exit(1);
        }
    }
}
