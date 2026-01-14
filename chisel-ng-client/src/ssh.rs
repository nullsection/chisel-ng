//! SSH client implementation over WebSocket

use crate::process;
use crate::{proto_bytes, log_info, log_debug, log_trace, log_warn, log_error};
use anyhow::Result;
use russh::client::{Config, Handler, Handle};
use russh::keys::PublicKey;
use russh::{Channel, ChannelMsg};
use chisel_ng_common::{PresharedKey, WsStream};
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Error codes for CONNECT_FAILED message (maps to SOCKS5 RFC 1928 reply codes)
const ERR_GENERAL: u8 = 0x01;          // General failure
const ERR_NETWORK_UNREACHABLE: u8 = 0x03;
const ERR_HOST_UNREACHABLE: u8 = 0x04;
const ERR_CONNECTION_REFUSED: u8 = 0x05; // Target port closed
const ERR_TIMEOUT: u8 = 0x06;            // Connection attempt timed out

/// Run the SSH client over a WebSocket stream
pub async fn run_client<S>(
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
    user: &str,
    psk: &PresharedKey,
    heartbeat_secs: u64,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    log_debug!("Starting SSH client");

    // WsStream adapts WebSocket to AsyncRead/AsyncWrite for russh
    let ws_adapter = WsStream::new(ws_stream);

    let config = Arc::new(Config::default());
    let handler = ClientHandler::new();

    // Establish SSH session - performs key exchange and algorithm negotiation
    log_debug!("Initiating SSH handshake");
    let mut session = russh::client::connect_stream(config, ws_adapter, handler).await?;

    log_debug!("SSH handshake complete");

    // Authenticate with PSK as password
    let psk_hex = psk.to_hex();
    log_debug!("Authenticating as user: {}", user);

    let auth_result = session
        .authenticate_password(user, &psk_hex)
        .await?;

    if auth_result.success() {
        log_info!("SSH authentication successful");
    } else {
        log_error!("SSH authentication rejected");
        return Err(anyhow::anyhow!("auth"));
    }

    // Open a session channel for control messages (PING/PONG, CONNECT requests)
    log_debug!("Opening SSH session channel");
    let channel = session
        .channel_open_session()
        .await?;

    log_debug!("SSH session channel opened: {:?}", channel.id());

    log_info!("Connected and authenticated successfully");

    // Run the main control loop
    run_control_loop(channel, session, heartbeat_secs).await?;

    Ok(())
}

/// Main control loop - handles CONNECT requests and spawns tunnel tasks
async fn run_control_loop(
    mut channel: Channel<russh::client::Msg>,
    mut session: Handle<ClientHandler>,
    heartbeat_secs: u64,
) -> Result<()> {
    log_debug!("Entering control loop");

    // Send hostname to server
    let hostname = process::get_hostname();
    log_debug!("Sending hostname: {}", hostname);
    let hostname_bytes = hostname.as_bytes();
    let mut hostname_packet = proto_bytes!(b"HOSTNAME")[..].to_vec();
    hostname_packet.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
    hostname_packet.extend_from_slice(hostname_bytes);
    if let Err(_e) = channel.data(&hostname_packet[..]).await {
        log_warn!("Failed to send hostname: {}", _e);
    }

    // Heartbeat interval to keep connection alive (0 = disabled)
    let heartbeat_enabled = heartbeat_secs > 0;
    let mut heartbeat_interval = tokio::time::interval(std::time::Duration::from_secs(
        if heartbeat_enabled { heartbeat_secs } else { 3600 } // Use 1 hour if disabled (won't be used)
    ));
    heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    if heartbeat_enabled {
        log_debug!("Heartbeat enabled: every {} seconds", heartbeat_secs);
    }

    loop {
        tokio::select! {
            // Periodic heartbeat to prevent connection timeout
            _ = heartbeat_interval.tick(), if heartbeat_enabled => {
                log_trace!("Sending heartbeat");
                if let Err(_e) = channel.data(&proto_bytes!(b"HEARTBEAT\n")[..]).await {
                    log_warn!("Failed to send heartbeat: {}", _e);
                    break;
                }
            }

            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        // Check for KILL request from server (exit completely)
                        if data.starts_with(&proto_bytes!(b"KILL")[..]) {
                            log_info!("Server requested termination, exiting...");
                            std::process::exit(0);
                        }

                        // Check for DISCONNECT request from server (will reconnect)
                        if data.starts_with(&proto_bytes!(b"DISCONNECT")[..]) {
                            log_info!("Server requested disconnect, will reconnect...");
                            break;  // Returns Ok(()) → main loop will reconnect
                        }

                        // Check for PING
                        if data.starts_with(&proto_bytes!(b"PING")[..]) {
                            log_trace!("Received PING, sending PONG");
                            if let Err(_e) = channel.data(&proto_bytes!(b"PONG\n")[..]).await {
                                log_warn!("Failed to send PONG: {}", _e);
                            }
                            continue;
                        }

                        // Check for CONNECT request
                        // Format: CONNECT<req_id:4><host_len:2><host><port:2>
                        if data.len() >= 15 && data.starts_with(&proto_bytes!(b"CONNECT")[..]) {
                            let req_id = u32::from_be_bytes([data[7], data[8], data[9], data[10]]);
                            let host_len = u16::from_be_bytes([data[11], data[12]]) as usize;

                            if data.len() >= 15 + host_len {
                                let host = String::from_utf8_lossy(&data[13..13 + host_len]).to_string();
                                let port = u16::from_be_bytes([data[13 + host_len], data[14 + host_len]]);

                                log_debug!("CONNECT request {} -> {}:{}", req_id, host, port);

                                // Handle CONNECT inline (session cannot be cloned)
                                // Pass control channel to send CONNECT_FAILED on error
                                if let Err(_e) = handle_connect_request(&mut session, &mut channel, req_id, &host, port).await {
                                    log_warn!("Tunnel {} failed: {}", req_id, _e);
                                }
                            } else {
                                log_warn!("CONNECT packet too short");
                            }
                            continue;
                        }

                        // Check for PROCESSLIST request
                        if data.starts_with(&proto_bytes!(b"PROCESSLIST")[..]) {
                            log_debug!("Received PROCESSLIST request, gathering processes...");
                            let processes = process::list_processes();
                            let json = match serde_json::to_vec(&processes) {
                                Ok(j) => j,
                                Err(_e) => {
                                    log_warn!("Failed to serialize process list: {}", _e);
                                    continue;
                                }
                            };

                            // Send response: PSRESP<len:4><json>
                            let mut response = proto_bytes!(b"PSRESP")[..].to_vec();
                            response.extend_from_slice(&(json.len() as u32).to_be_bytes());
                            response.extend_from_slice(&json);

                            if let Err(_e) = channel.data(&response[..]).await {
                                log_warn!("Failed to send process list: {}", _e);
                            } else {
                                log_debug!("Sent process list ({} processes, {} bytes)", processes.len(), json.len());
                            }
                            continue;
                        }

                        // Check for NETSTAT request
                        if data.starts_with(&proto_bytes!(b"NETSTAT")[..]) {
                            log_debug!("Received NETSTAT request, gathering connections...");
                            let connections = process::list_connections();
                            let json = match serde_json::to_vec(&connections) {
                                Ok(j) => j,
                                Err(_e) => {
                                    log_warn!("Failed to serialize connection list: {}", _e);
                                    continue;
                                }
                            };

                            // Send response: NSRESP<len:4><json>
                            let mut response = proto_bytes!(b"NSRESP")[..].to_vec();
                            response.extend_from_slice(&(json.len() as u32).to_be_bytes());
                            response.extend_from_slice(&json);

                            if let Err(_e) = channel.data(&response[..]).await {
                                log_warn!("Failed to send connection list: {}", _e);
                            } else {
                                log_debug!("Sent connection list ({} connections, {} bytes)", connections.len(), json.len());
                            }
                            continue;
                        }

                        log_trace!("Unknown control data: {:?}", &data[..data.len().min(32)]);
                    }
                    Some(_msg) => {
                        log_trace!("Control channel message: {:?}", _msg);
                    }
                    None => {
                        log_debug!("Control channel closed by server");
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                log_info!("Received Ctrl+C, disconnecting...");
                // Graceful disconnect
                log_debug!("Disconnecting SSH session");
                session
                    .disconnect(russh::Disconnect::ByApplication, "Client disconnect", "en")
                    .await?;
                return Err(anyhow::anyhow!("User requested exit"));
            }
        }
    }

    // Graceful disconnect
    log_debug!("Disconnecting SSH session");
    session
        .disconnect(russh::Disconnect::ByApplication, "Client disconnect", "en")
        .await?;

    log_info!("SSH session closed");
    Ok(())
}

/// Handle a CONNECT request by opening a direct-tcpip channel
/// This creates the tunnel: Server -> SSH Channel -> Client -> TCP -> Target
/// On failure, sends CONNECT_FAILED message on control channel
async fn handle_connect_request(
    session: &mut Handle<ClientHandler>,
    control_channel: &mut Channel<russh::client::Msg>,
    req_id: u32,
    host: &str,
    port: u16,
) -> Result<()> {
    // Connect to the target service on the local/internal network with timeout
    let dest_addr = format!("{}:{}", host, port);
    log_debug!("Connecting to {}", dest_addr);

    // 10 second timeout for TCP connect
    let connect_result = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&dest_addr)
    ).await;

    let tcp_stream = match connect_result {
        Ok(Ok(stream)) => {
            log_debug!("Connected to {}", dest_addr);
            stream
        }
        Ok(Err(e)) => {
            // Connection error - categorize and report
            let error_code = categorize_io_error(&e);
            log_debug!("Connection to {} failed: {} (code {})", dest_addr, e, error_code);
            send_connect_failed(control_channel, req_id, error_code).await?;
            return Err(anyhow::anyhow!("Connection failed: {}", e));
        }
        Err(_) => {
            // Timeout
            log_debug!("Connection to {} timed out", dest_addr);
            send_connect_failed(control_channel, req_id, ERR_TIMEOUT).await?;
            return Err(anyhow::anyhow!("Connection timed out"));
        }
    };

    // Open SSH direct-tcpip channel back to server
    // req_id in originator_address lets server match this channel to the pending socket
    let channel = session
        .channel_open_direct_tcpip(host, port as u32, &req_id.to_string(), 0)
        .await?;

    log_debug!("Direct-tcpip channel opened for req_id {}", req_id);

    // Spawn bridge task to relay data between SSH channel and TCP socket
    tokio::spawn(async move {
        if let Err(_e) = bridge_channel_tcp(channel, tcp_stream).await {
            log_trace!("Bridge error for req_id {}: {}", req_id, _e);
        }
    });

    Ok(())
}

/// Categorize an IO error into our error codes
fn categorize_io_error(e: &std::io::Error) -> u8 {
    match e.kind() {
        ErrorKind::ConnectionRefused => ERR_CONNECTION_REFUSED,
        ErrorKind::NetworkUnreachable => ERR_NETWORK_UNREACHABLE,
        ErrorKind::HostUnreachable => ERR_HOST_UNREACHABLE,
        ErrorKind::TimedOut => ERR_TIMEOUT,
        _ => ERR_GENERAL,
    }
}

/// Send CONNECT_FAILED message on control channel
/// Format: CONNECT_FAILED<req_id:4><error_code:1>
async fn send_connect_failed(
    channel: &mut Channel<russh::client::Msg>,
    req_id: u32,
    error_code: u8,
) -> Result<()> {
    let mut packet = proto_bytes!(b"CONNECT_FAILED")[..].to_vec();
    packet.extend_from_slice(&req_id.to_be_bytes());
    packet.push(error_code);
    channel.data(&packet[..]).await?;
    log_debug!("Sent CONNECT_FAILED for req_id {} with error code {}", req_id, error_code);
    Ok(())
}

/// Bridge data bidirectionally between an SSH channel and a TCP stream
/// Uses tokio::select! to handle both directions concurrently
async fn bridge_channel_tcp(
    mut channel: Channel<russh::client::Msg>,
    tcp_stream: TcpStream,
) -> Result<()> {
    // Split TCP stream for concurrent read/write
    let (mut tcp_reader, mut tcp_writer) = tcp_stream.into_split();
    let mut buf = [0u8; 8192];

    loop {
        tokio::select! {
            // Direction 1: TCP (target) -> SSH channel (server)
            result = tcp_reader.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        log_trace!("TCP connection closed");
                        break;
                    }
                    Ok(n) => {
                        if let Err(_e) = channel.data(&buf[..n]).await {
                            log_trace!("Channel write error: {}", _e);
                            break;
                        }
                    }
                    Err(_e) => {
                        log_trace!("TCP read error: {}", _e);
                        break;
                    }
                }
            }
            // Direction 2: SSH channel (server) -> TCP (target)
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        if let Err(_e) = tcp_writer.write_all(&data).await {
                            log_trace!("TCP write error: {}", _e);
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) | None => {
                        log_trace!("Channel closed");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    let _ = channel.close().await;
    Ok(())
}

/// SSH client handler
struct ClientHandler {}

impl ClientHandler {
    fn new() -> Self {
        Self {}
    }
}

impl Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let _fingerprint = key_fingerprint(server_public_key);
        log_debug!("Server host key fingerprint: {}", _fingerprint);
        log_debug!("Accepting server key without verification (development mode)");
        Ok(true)
    }
}

fn key_fingerprint(key: &PublicKey) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(key.to_bytes().unwrap_or_default());
    let hash = hasher.finalize();
    format!("SHA256:{}", base64_encode(&hash))
}

/// Simple base64 encoder for key fingerprints (avoids external dependency)
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[(b0 >> 2) & 0x3f] as char);
        result.push(ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3f] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3f] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }
    result
}
