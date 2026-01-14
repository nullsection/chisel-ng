//! chisel-ng server - Operator side component
//!
//! Listens for incoming WebSocket connections from agents (clients),
//! establishes SSH sessions over WebSocket, and provides tunnel access.

mod cli;
mod session;
mod socks5;
mod ssh;
mod tls;
mod websocket;

use session::SessionManager;

use anyhow::{Context, Result};
use clap::Parser;
use chisel_ng_common::PresharedKey;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "chisel-server", about = "chisel-ng server (operator component)")]
struct Args {
    /// Address to listen on
    #[arg(short, long, default_value = "0.0.0.0:8443")]
    listen: SocketAddr,

    /// Pre-shared key (64-char hex) or passphrase
    #[arg(short, long, env = "CHISEL_PSK", required_unless_present = "generate_psk")]
    psk: Option<String>,

    /// TLS certificate file (PEM). If not provided, generates self-signed.
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key file (PEM). Required if --cert is provided.
    #[arg(long)]
    key: Option<PathBuf>,

    /// Generate and print a new random PSK, then exit
    #[arg(long)]
    generate_psk: bool,

    /// Verbose output (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    // -v = INFO (connections, auth, tunnels)
    // -vv = DEBUG (detailed flow)
    // -vvv = TRACE (everything)
    let filter = match args.verbose {
        0 => EnvFilter::from_default_env()
            .add_directive("chisel_server=warn".parse().unwrap()),
        1 => EnvFilter::from_default_env()
            .add_directive("chisel_server=info".parse().unwrap())
            .add_directive("chisel_ng_common=warn".parse().unwrap()),
        2 => EnvFilter::from_default_env()
            .add_directive("chisel_server=debug".parse().unwrap())
            .add_directive("chisel_ng_common=debug".parse().unwrap())
            .add_directive("russh=info".parse().unwrap()),
        _ => EnvFilter::from_default_env()
            .add_directive("trace".parse().unwrap()),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(args.verbose >= 2)
        .with_thread_ids(args.verbose >= 3)
        .init();

    // Handle --generate-psk
    if args.generate_psk {
        let psk = PresharedKey::generate();
        println!("Generated PSK (hex): {}", psk.to_hex());
        println!("Fingerprint: {}", psk.fingerprint());
        return Ok(());
    }

    // Parse PSK: 64 hex chars = raw PSK, otherwise treat as passphrase
    let psk_str = args.psk.expect("PSK required when not generating");
    let psk = if psk_str.len() == 64 && psk_str.chars().all(|c| c.is_ascii_hexdigit()) {
        PresharedKey::from_hex(&psk_str).expect("Valid hex")
    } else {
        PresharedKey::from_passphrase(&psk_str)
    };

    info!("PSK fingerprint: {}", psk.fingerprint());

    // Setup TLS
    let tls_config = if let Some(cert_path) = &args.cert {
        let key_path = args.key.as_ref().context("--key required when --cert is provided")?;
        tls::load_tls_config(cert_path, key_path).await?
    } else {
        info!("No certificate provided, generating self-signed certificate");
        tls::generate_self_signed_config()?
    };

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    // Generate SSH host key
    let ssh_key = ssh::generate_host_key()?;
    info!("SSH host key fingerprint: {}", ssh::key_fingerprint(&ssh_key));

    // Bind listener
    let listener = TcpListener::bind(args.listen).await?;
    info!("Listening on wss://{}", args.listen);

    // Create session manager
    let session_manager = SessionManager::new();

    // Spawn CLI on separate task with access to connection resources
    let cli_session_manager = session_manager.clone();
    let cli_tls_acceptor = tls_acceptor.clone();
    let cli_ssh_key = ssh_key.clone();
    let cli_psk = psk.clone();
    tokio::spawn(async move {
        cli::run(cli_session_manager, cli_tls_acceptor, cli_ssh_key, cli_psk).await;
        // CLI exited - shutdown server
        std::process::exit(0);
    });

    // Main accept loop - handle incoming agent connections
    loop {
        // Wait for next TCP connection
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        info!("New connection from {}", peer_addr);
        debug!("Performing TLS handshake with {}", peer_addr);

        // Clone shared resources for the spawned task
        let tls_acceptor = tls_acceptor.clone();
        let psk = psk.clone();
        let ssh_key = ssh_key.clone();
        let session_manager = session_manager.clone();

        // Handle each connection in a separate task
        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp_stream, tls_acceptor, psk, ssh_key, peer_addr, session_manager).await {
                error!("Connection {} error: {:#}", peer_addr, e);
            }
        });
    }
}

// Handle a single agent connection through the full protocol stack
async fn handle_connection(
    tcp_stream: tokio::net::TcpStream,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    psk: PresharedKey,
    ssh_key: russh::keys::PrivateKey,
    peer_addr: SocketAddr,
    session_manager: Arc<SessionManager>,
) -> Result<()> {
    // Step 1: TLS handshake - encrypt the connection
    let tls_stream = tls_acceptor
        .accept(tcp_stream)
        .await
        .context("TLS handshake failed")?;

    debug!("[{}] TLS handshake complete", peer_addr);

    // Step 2: WebSocket upgrade - establish framing layer
    let ws_stream = websocket::accept(tls_stream)
        .await
        .context("WebSocket upgrade failed")?;

    debug!("[{}] WebSocket upgrade complete", peer_addr);

    // Step 3: Run SSH server - authenticate and handle channels
    ssh::run_server(ws_stream, ssh_key, psk, peer_addr, session_manager).await?;

    info!("[{}] Connection closed", peer_addr);
    Ok(())
}
