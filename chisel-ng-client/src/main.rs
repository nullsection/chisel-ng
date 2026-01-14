//! chisel-ng client - Agent component
//!
//! Connects outbound to the server (operator), establishes SSH session
//! over WebSocket, and provides tunnel access into the local network.

use chisel_ng_client::{proto_str, static_str, log_info, log_debug, log_error};
use chisel_ng_client::{ssh, tls, websocket};
use anyhow::Result;
use clap::{Arg, ArgAction, Command};
use chisel_ng_common::PresharedKey;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

fn build_cli() -> Command {
    Command::new(static_str!("chisel-client"))
        .about(static_str!("chisel-ng client (agent component)"))
        .arg(
            Arg::new(static_str!("server"))
                .short('s')
                .long(static_str!("server"))
                .help(static_str!("Server address to connect to (host:port)"))
                .required(true)
        )
        .arg(
            Arg::new(static_str!("psk"))
                .short('p')
                .long(static_str!("psk"))
                .env(static_str!("CHISEL_PSK"))
                .help(static_str!("Pre-shared key (64-char hex) or passphrase"))
                .required(true)
        )
        .arg(
            Arg::new(static_str!("user"))
                .short('u')
                .long(static_str!("user"))
                .help(static_str!("Session label displayed in server CLI (not used for auth)"))
                .default_value(static_str!("agent"))
        )
        .arg(
            Arg::new(static_str!("insecure"))
                .short('k')
                .long(static_str!("insecure"))
                .help(static_str!("Skip TLS certificate verification (for self-signed certs)"))
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new(static_str!("no-reconnect"))
                .long(static_str!("no-reconnect"))
                .help(static_str!("Disable auto-reconnect (by default, client reconnects on disconnect)"))
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new(static_str!("interval"))
                .short('i')
                .long(static_str!("interval"))
                .help(static_str!("Reconnect interval in seconds"))
                .default_value(static_str!("30"))
        )
        .arg(
            Arg::new(static_str!("heartbeat"))
                .long(static_str!("heartbeat"))
                .help(static_str!("Heartbeat interval in seconds (0 to disable)"))
                .default_value(static_str!("30"))
        )
        .arg(
            Arg::new(static_str!("verbose"))
                .short('v')
                .long(static_str!("verbose"))
                .help(static_str!("Verbose output (-v, -vv, -vvv)"))
                .action(ArgAction::Count)
        )
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = build_cli().get_matches();

    // Extract arguments
    let server = matches.get_one::<String>(static_str!("server")).unwrap();
    let psk_str = matches.get_one::<String>(static_str!("psk")).unwrap();
    let user = matches.get_one::<String>(static_str!("user")).unwrap();
    let insecure = matches.get_flag(static_str!("insecure"));
    let no_reconnect = matches.get_flag(static_str!("no-reconnect"));
    let interval: u64 = matches
        .get_one::<String>(static_str!("interval"))
        .unwrap()
        .parse()?;
    let heartbeat: u64 = matches
        .get_one::<String>(static_str!("heartbeat"))
        .unwrap()
        .parse()?;
    let verbose = matches.get_count(static_str!("verbose"));

    // Initialize logging
    let filter = match verbose {
        0 => EnvFilter::from_default_env()
            .add_directive("chisel_client=warn".parse().unwrap()),
        1 => EnvFilter::from_default_env()
            .add_directive("chisel_client=info".parse().unwrap())
            .add_directive("chisel_ng_common=warn".parse().unwrap()),
        2 => EnvFilter::from_default_env()
            .add_directive("chisel_client=debug".parse().unwrap())
            .add_directive("chisel_ng_common=debug".parse().unwrap())
            .add_directive("russh=info".parse().unwrap()),
        _ => EnvFilter::from_default_env()
            .add_directive("trace".parse().unwrap()),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(verbose >= 2)
        .with_thread_ids(verbose >= 3)
        .init();

    // Parse PSK: 64 hex chars = raw PSK, otherwise treat as passphrase
    let psk = if psk_str.len() == 64 && psk_str.chars().all(|c| c.is_ascii_hexdigit()) {
        PresharedKey::from_hex(psk_str).expect("Valid hex")
    } else {
        PresharedKey::from_passphrase(psk_str)
    };

    log_info!("PSK fingerprint: {}", psk.fingerprint());

    // Parse server address
    let server_addr = if server.contains("://") {
        server.clone()
    } else {
        format!("{}://{}", proto_str!("wss"), server)
    };

    log_info!("Connecting to {}", server_addr);

    // Main connection loop with auto-reconnect
    let mut _attempt = 0u32;
    loop {
        _attempt += 1;
        // Attempt to connect and run the session
        match connect(&server_addr, user, &psk, insecure, heartbeat).await {
            Ok(()) => {
                log_info!("Connection closed gracefully");
                _attempt = 0; // Reset counter on successful connection
            }
            Err(_e) => {
                let _err_msg = format!("{:#}", _e);
                // Check if user requested exit (Ctrl+C)
                if _err_msg.contains(proto_str!("User requested exit")) {
                    log_info!("Exiting...");
                    break;
                }
                log_error!("Connection error: {}", _err_msg);
            }
        }

        // Exit if auto-reconnect is disabled
        if no_reconnect {
            break;
        }

        log_info!(
            "Waiting {} seconds before reconnection attempt #{}...",
            interval,
            _attempt + 1
        );

        // Wait before reconnecting, but allow Ctrl+C to interrupt
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                log_info!("Attempting to reconnect to {}", server_addr);
            }
            _ = tokio::signal::ctrl_c() => {
                log_info!("Received Ctrl+C, exiting...");
                break;
            }
        }
    }

    Ok(())
}

/// Connection timeout for TCP + TLS + WebSocket handshake
const CONNECT_TIMEOUT_SECS: u64 = 5;

// Establish connection to server through the full protocol stack
async fn connect(server_addr: &str, user: &str, psk: &PresharedKey, insecure: bool, heartbeat: u64) -> Result<()> {
    // Parse URL to extract host and port for connection
    let url = url::Url::parse(server_addr).map_err(|_| anyhow::anyhow!("url"))?;
    let host = url.host_str().ok_or_else(|| anyhow::anyhow!("host"))?;
    let port = url.port().unwrap_or(443);

    log_debug!("Resolving {}:{}", host, port);

    // Step 1: Establish TCP connection to server (with timeout)
    let tcp_addr = format!("{}:{}", host, port);
    let tcp_stream = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(&tcp_addr)
    )
    .await??;

    log_debug!("TCP connection established to {}", tcp_addr);

    // Step 2: TLS handshake - encrypt the connection (with timeout)
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tls::connect(tcp_stream, host, insecure)
    )
    .await??;

    log_debug!("TLS handshake complete");

    // Step 3: WebSocket upgrade - establish framing layer (with timeout)
    let ws_stream = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        websocket::connect(tls_stream, server_addr)
    )
    .await??;

    log_debug!("WebSocket connection established");

    // Step 4: Run SSH client - authenticate and handle control messages
    ssh::run_client(ws_stream, user, psk, heartbeat).await?;

    Ok(())
}

// Minimal URL parsing without external crate
mod url {
    pub struct Url {
        host: String,
        port: Option<u16>,
    }

    impl Url {
        pub fn parse(s: &str) -> Result<Self, &'static str> {
            let (_scheme, rest) = s.split_once("://").ok_or("no scheme")?;

            let (authority, _path) = rest.find('/').map_or((rest, "/"), |i| {
                (&rest[..i], &rest[i..])
            });

            let (host, port) = if let Some(idx) = authority.rfind(':') {
                let port_str = &authority[idx + 1..];
                if let Ok(p) = port_str.parse::<u16>() {
                    (&authority[..idx], Some(p))
                } else {
                    (authority, None)
                }
            } else {
                (authority, None)
            };

            Ok(Self {
                host: host.to_string(),
                port,
            })
        }

        pub fn host_str(&self) -> Option<&str> {
            Some(&self.host)
        }

        pub fn port(&self) -> Option<u16> {
            self.port
        }
    }
}
