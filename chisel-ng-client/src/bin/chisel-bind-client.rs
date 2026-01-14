//! chisel-ng bind client - Agent component (bind mode)
//!
//! Binds to a local port and waits for the server to connect.
//! When connected, initiates TLS/WebSocket/SSH as client to blend
//! with outbound traffic patterns.

use chisel_ng_client::{proto_str, static_str, log_info, log_debug, log_error};
use chisel_ng_client::{ssh, tls, websocket};

use anyhow::Result;
use clap::{Arg, ArgAction, Command};
use chisel_ng_common::PresharedKey;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

fn build_cli() -> Command {
    Command::new(static_str!("chisel-bind-client"))
        .about(static_str!("chisel-ng bind client (accepts inbound, acts as client)"))
        .arg(
            Arg::new(static_str!("listen"))
                .short('l')
                .long(static_str!("listen"))
                .help(static_str!("Address to bind and listen on (e.g., 0.0.0.0:9000)"))
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
    let listen: SocketAddr = matches
        .get_one::<String>(static_str!("listen"))
        .unwrap()
        .parse()?;
    let psk_str = matches.get_one::<String>(static_str!("psk")).unwrap();
    let user = matches.get_one::<String>(static_str!("user")).unwrap();
    let insecure = matches.get_flag(static_str!("insecure"));
    let heartbeat: u64 = matches
        .get_one::<String>(static_str!("heartbeat"))
        .unwrap()
        .parse()?;
    let verbose = matches.get_count(static_str!("verbose"));

    // Initialize logging
    let filter = match verbose {
        0 => EnvFilter::from_default_env()
            .add_directive("chisel_bind_client=warn".parse().unwrap()),
        1 => EnvFilter::from_default_env()
            .add_directive("chisel_bind_client=info".parse().unwrap())
            .add_directive("chisel_ng_common=warn".parse().unwrap()),
        2 => EnvFilter::from_default_env()
            .add_directive("chisel_bind_client=debug".parse().unwrap())
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

    // Parse PSK
    let psk = if psk_str.len() == 64 && psk_str.chars().all(|c| c.is_ascii_hexdigit()) {
        PresharedKey::from_hex(psk_str).expect("Valid hex")
    } else {
        PresharedKey::from_passphrase(psk_str)
    };

    log_info!("PSK fingerprint: {}", psk.fingerprint());

    // Bind listener
    let listener = TcpListener::bind(listen).await?;

    log_info!("Listening on {}, waiting for connection...", listen);

    // Main loop - accept connections and handle them
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((tcp_stream, _peer_addr)) => {
                        log_info!("Connection from {}", _peer_addr);

                        // Handle the connection
                        match handle_connection(tcp_stream, user, &psk, insecure, heartbeat).await {
                            Ok(()) => {
                                log_info!("Session ended, waiting for next connection...");
                            }
                            Err(_e) => {
                                log_error!("Session error: {:#}", _e);
                            }
                        }
                    }
                    Err(_e) => {
                        log_error!("Accept error: {}", _e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                log_info!("Received Ctrl+C, exiting...");
                break;
            }
        }
    }

    Ok(())
}

/// Handle an incoming connection - act as TLS/WebSocket/SSH client
async fn handle_connection(
    tcp_stream: tokio::net::TcpStream,
    user: &str,
    psk: &PresharedKey,
    insecure: bool,
    heartbeat: u64,
) -> Result<()> {
    // Get peer address for logging
    let peer_addr = tcp_stream.peer_addr()?;

    log_debug!("Starting TLS client handshake with {}", peer_addr);

    // TLS client handshake - we initiate as client even though we accepted TCP
    // Use peer IP as server name for TLS (server will have cert)
    let server_host = peer_addr.ip().to_string();
    let tls_stream = tls::connect(tcp_stream, &server_host, insecure).await?;

    log_debug!("TLS handshake complete");

    // WebSocket client upgrade - we send the upgrade request
    // Use a synthetic URL since we're the "client" side of WebSocket
    let ws_url = format!("{}://{}/", proto_str!("wss"), peer_addr);
    let ws_stream = websocket::connect(tls_stream, &ws_url).await?;

    log_debug!("WebSocket upgrade complete");

    // Run SSH client session
    log_info!("Starting SSH session");
    ssh::run_client(ws_stream, user, psk, heartbeat).await?;

    Ok(())
}
