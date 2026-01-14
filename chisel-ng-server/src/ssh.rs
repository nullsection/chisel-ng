//! SSH server implementation over WebSocket

use crate::session::{NetstatEntry, ProcessInfo, SessionManager, PendingSocket};
use crate::socks5;
use anyhow::{Context, Result};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelMsg};
use chisel_ng_common::{PresharedKey, WsStream};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tracing::{debug, error, info, trace, warn};

/// Generate an Ed25519 host key for the SSH server
pub fn generate_host_key() -> Result<PrivateKey> {
    let key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519)
        .context("Failed to generate host key")?;
    Ok(key)
}

/// Get a fingerprint of the SSH key
pub fn key_fingerprint(key: &PrivateKey) -> String {
    let public = key.public_key();
    let mut hasher = Sha256::new();
    hasher.update(public.to_bytes().unwrap_or_default());
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

/// Run the SSH server over a WebSocket stream with session management
pub async fn run_server<S>(
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
    host_key: PrivateKey,
    psk: PresharedKey,
    peer_addr: SocketAddr,
    session_manager: Arc<SessionManager>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!("[{}] Starting SSH server", peer_addr);

    let ws_adapter = WsStream::new(ws_stream);

    let config = russh::server::Config {
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    };

    let config = Arc::new(config);
    let handler = ServerHandler::new(psk, peer_addr, session_manager.clone());

    let session = russh::server::run_stream(config, ws_adapter, handler).await?;

    match session.await {
        Ok(_) => {
            info!("[{}] SSH session completed", peer_addr);
        }
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("Disconnect") {
                info!("[{}] SSH client disconnected", peer_addr);
            } else {
                error!("[{}] SSH session error: {:?}", peer_addr, e);
            }
        }
    }

    Ok(())
}

/// SSH server handler with session management
struct ServerHandler {
    psk: PresharedKey,                                          // Pre-shared key for authentication
    peer_addr: SocketAddr,                                      // Remote client address
    authenticated: bool,                                        // Whether client has authenticated
    session_manager: Arc<SessionManager>,                       // Shared session registry
    session_id: Option<u32>,                                    // Assigned session ID after auth
    control_tx: mpsc::Sender<Vec<u8>>,                         // Send CONNECT requests to client
    control_rx: Arc<TokioMutex<mpsc::Receiver<Vec<u8>>>>,      // Receive tunnel requests from CLI
    pending_sockets: Arc<TokioMutex<HashMap<u32, PendingSocket>>>, // TCP sockets awaiting channel
    disconnect_flag: Arc<AtomicBool>,                          // Signal to disconnect client
    kill_flag: Arc<AtomicBool>,                                // Signal to terminate client
    ping_requested: Arc<AtomicBool>,                           // Ping request from CLI
    ping_sent_at: Arc<TokioMutex<Option<Instant>>>,           // Timestamp when ping was sent
    ping_result_ms: Arc<TokioMutex<Option<u64>>>,             // Measured latency in ms
}

impl ServerHandler {
    fn new(psk: PresharedKey, peer_addr: SocketAddr, session_manager: Arc<SessionManager>) -> Self {
        let (control_tx, control_rx) = mpsc::channel(256);
        Self {
            psk,
            peer_addr,
            authenticated: false,
            session_manager,
            session_id: None,
            control_tx,
            control_rx: Arc::new(TokioMutex::new(control_rx)),
            pending_sockets: Arc::new(TokioMutex::new(HashMap::new())),
            disconnect_flag: Arc::new(AtomicBool::new(false)),
            kill_flag: Arc::new(AtomicBool::new(false)),
            ping_requested: Arc::new(AtomicBool::new(false)),
            ping_sent_at: Arc::new(TokioMutex::new(None)),
            ping_result_ms: Arc::new(TokioMutex::new(None)),
        }
    }
}

impl Handler for ServerHandler {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<Auth, Self::Error> {
        debug!("[{}] Auth attempt for user: {}", self.peer_addr, user);

        let provided_psk = match PresharedKey::from_hex(password) {
            Ok(psk) => psk,
            Err(_) => PresharedKey::from_passphrase(password),
        };

        if self.psk.verify(&provided_psk) {
            info!("[{}] Authentication successful for user: {}", self.peer_addr, user);
            self.authenticated = true;

            // Register session
            let handle = self.session_manager
                .register(self.peer_addr, user.to_string())
                .await;

            self.session_id = Some(handle.id);
            info!("[{}] Registered as session {}", self.peer_addr, handle.id);

            // Use shared state from session
            self.disconnect_flag = handle.disconnect_flag;
            self.kill_flag = handle.kill_flag;
            self.ping_requested = handle.ping_requested;
            self.ping_result_ms = handle.ping_result_ms;
            self.pending_sockets = handle.pending_sockets;

            // Set the control sender so tunnels can send CONNECT messages
            *handle.control_sender.lock().await = Some(self.control_tx.clone());

            Ok(Auth::Accept)
        } else {
            warn!("[{}] Authentication failed for user: {}", self.peer_addr, user);
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.authenticated {
            return Ok(false);
        }

        let channel_id = channel.id();
        debug!("[{}] Control channel {:?} opened", self.peer_addr, channel_id);

        // Spawn control channel handler - receives tunnel requests from CLI, forwards to client
        let control_rx = self.control_rx.clone();
        let disconnect_flag = self.disconnect_flag.clone();
        let kill_flag = self.kill_flag.clone();
        let ping_requested = self.ping_requested.clone();
        let ping_sent_at = self.ping_sent_at.clone();
        let ping_result_ms = self.ping_result_ms.clone();
        let peer_addr = self.peer_addr;
        let session_manager = self.session_manager.clone();
        let session_id = self.session_id;
        let pending_sockets = self.pending_sockets.clone();

        tokio::spawn(async move {
            let mut rx = control_rx.lock().await;
            let mut channel = channel;
            let mut psresp_buffer: Vec<u8> = Vec::new();
            let mut psresp_expected_len: Option<usize> = None;
            let mut nsresp_buffer: Vec<u8> = Vec::new();
            let mut nsresp_expected_len: Option<usize> = None;

            loop {
                tokio::select! {
                    biased;

                    Some(data) = rx.recv() => {
                        if let Err(e) = channel.data(&data[..]).await {
                            warn!("[{}] Control channel send failed: {}", peer_addr, e);
                            break;
                        }
                    }

                    msg = channel.wait() => {
                        match msg {
                            Some(russh::ChannelMsg::Data { data }) => {
                                // If we're buffering PSRESP, append data
                                if psresp_expected_len.is_some() {
                                    psresp_buffer.extend_from_slice(&data);

                                    // Check if we have enough data
                                    if let Some(expected) = psresp_expected_len {
                                        if psresp_buffer.len() >= 10 + expected {
                                            let json_data = &psresp_buffer[10..10 + expected];
                                            match serde_json::from_slice::<Vec<ProcessInfo>>(json_data) {
                                                Ok(processes) => {
                                                    debug!("[{}] Received process list: {} processes", peer_addr, processes.len());
                                                    if let Some(sid) = session_id {
                                                        session_manager.handle_process_list_response(sid, processes).await;
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("[{}] Failed to parse process list: {}", peer_addr, e);
                                                }
                                            }
                                            psresp_buffer.clear();
                                            psresp_expected_len = None;
                                        }
                                    }
                                    continue;
                                }

                                // If we're buffering NSRESP, append data
                                if nsresp_expected_len.is_some() {
                                    nsresp_buffer.extend_from_slice(&data);

                                    // Check if we have enough data
                                    if let Some(expected) = nsresp_expected_len {
                                        if nsresp_buffer.len() >= 10 + expected {
                                            let json_data = &nsresp_buffer[10..10 + expected];
                                            match serde_json::from_slice::<Vec<NetstatEntry>>(json_data) {
                                                Ok(connections) => {
                                                    debug!("[{}] Received netstat: {} connections", peer_addr, connections.len());
                                                    if let Some(sid) = session_id {
                                                        session_manager.handle_netstat_response(sid, connections).await;
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("[{}] Failed to parse netstat: {}", peer_addr, e);
                                                }
                                            }
                                            nsresp_buffer.clear();
                                            nsresp_expected_len = None;
                                        }
                                    }
                                    continue;
                                }

                                // Handle PONG response
                                if data.starts_with(b"PONG") {
                                    if let Some(sent_at) = *ping_sent_at.lock().await {
                                        let latency = sent_at.elapsed().as_millis() as u64;
                                        debug!("[{}] Ping latency: {}ms", peer_addr, latency);
                                        *ping_result_ms.lock().await = Some(latency);
                                    }
                                }
                                // Handle HEARTBEAT (client keepalive)
                                else if data.starts_with(b"HEARTBEAT") {
                                    trace!("[{}] Heartbeat received", peer_addr);
                                }
                                // Handle HOSTNAME message from client
                                // Format: HOSTNAME<len:2><hostname>
                                else if data.starts_with(b"HOSTNAME") && data.len() >= 10 {
                                    let hostname_len = u16::from_be_bytes([data[8], data[9]]) as usize;
                                    if data.len() >= 10 + hostname_len {
                                        let hostname = String::from_utf8_lossy(&data[10..10 + hostname_len]).to_string();
                                        info!("[{}] Client hostname: {}", peer_addr, hostname);
                                        if let Some(sid) = session_id {
                                            session_manager.set_hostname(sid, hostname).await;
                                        }
                                    }
                                }
                                // Handle PSRESP (process list response)
                                // Format: PSRESP<len:4><json>
                                else if data.starts_with(b"PSRESP") && data.len() >= 10 {
                                    let json_len = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;
                                    debug!("[{}] Received PSRESP header, expecting {} bytes", peer_addr, json_len);

                                    if data.len() >= 10 + json_len {
                                        // Complete in one chunk
                                        let json_data = &data[10..10 + json_len];
                                        match serde_json::from_slice::<Vec<ProcessInfo>>(json_data) {
                                            Ok(processes) => {
                                                debug!("[{}] Received process list: {} processes", peer_addr, processes.len());
                                                if let Some(sid) = session_id {
                                                    session_manager.handle_process_list_response(sid, processes).await;
                                                }
                                            }
                                            Err(e) => {
                                                warn!("[{}] Failed to parse process list: {}", peer_addr, e);
                                            }
                                        }
                                    } else {
                                        // Need to buffer more data
                                        psresp_buffer = data.to_vec();
                                        psresp_expected_len = Some(json_len);
                                    }
                                }
                                // Handle NSRESP (netstat response)
                                // Format: NSRESP<len:4><json>
                                else if data.starts_with(b"NSRESP") && data.len() >= 10 {
                                    let json_len = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;
                                    debug!("[{}] Received NSRESP header, expecting {} bytes", peer_addr, json_len);

                                    if data.len() >= 10 + json_len {
                                        // Complete in one chunk
                                        let json_data = &data[10..10 + json_len];
                                        match serde_json::from_slice::<Vec<NetstatEntry>>(json_data) {
                                            Ok(connections) => {
                                                info!("[{}] Received netstat: {} connections", peer_addr, connections.len());
                                                if let Some(sid) = session_id {
                                                    session_manager.handle_netstat_response(sid, connections).await;
                                                }
                                            }
                                            Err(e) => {
                                                warn!("[{}] Failed to parse netstat: {}", peer_addr, e);
                                            }
                                        }
                                    } else {
                                        // Need to buffer more data
                                        nsresp_buffer = data.to_vec();
                                        nsresp_expected_len = Some(json_len);
                                    }
                                }
                                // Handle CONNECT_FAILED - client couldn't reach target
                                // Maps error code to SOCKS5 reply for proper client feedback
                                else if data.starts_with(b"CONNECT_FAILED") && data.len() >= 19 {
                                    let req_id = u32::from_be_bytes([data[14], data[15], data[16], data[17]]);
                                    let error_code = data[18];
                                    debug!("[{}] CONNECT_FAILED for req_id {} with error code {}", peer_addr, req_id, error_code);

                                    // Get pending socket and send SOCKS5 error
                                    if let Some(pending) = pending_sockets.lock().await.remove(&req_id) {
                                        if pending.socks5_bind_addr.is_some() {
                                            let mut stream = pending.stream;
                                            let error = match error_code {
                                                0x05 => socks5::ConnectError::ConnectionRefused,
                                                0x04 => socks5::ConnectError::HostUnreachable,
                                                0x06 => socks5::ConnectError::Timeout,
                                                0x03 => socks5::ConnectError::NetworkUnreachable,
                                                _ => socks5::ConnectError::GeneralFailure,
                                            };
                                            if let Err(e) = socks5::send_error(&mut stream, error).await {
                                                warn!("[{}] Failed to send SOCKS5 error: {}", peer_addr, e);
                                            } else {
                                                debug!("[{}] Sent SOCKS5 error for req_id {}", peer_addr, req_id);
                                            }
                                        }
                                        // Non-SOCKS5 connections (direct tunnels) just get dropped silently
                                    } else {
                                        warn!("[{}] No pending socket for CONNECT_FAILED req_id {}", peer_addr, req_id);
                                    }
                                }
                            }
                            Some(russh::ChannelMsg::Eof) | None => {
                                trace!("[{}] Control channel closed", peer_addr);
                                break;
                            }
                            _ => {}
                        }
                    }

                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                        // Check kill flag first (client exits completely)
                        if kill_flag.load(Ordering::Relaxed) {
                            info!("[{}] Sending KILL to client", peer_addr);
                            let _ = channel.data(&b"KILL\n"[..]).await;
                            let _ = channel.close().await;
                            break;
                        }

                        // Check disconnect flag (client will reconnect)
                        if disconnect_flag.load(Ordering::Relaxed) {
                            info!("[{}] Sending DISCONNECT to client", peer_addr);
                            let _ = channel.data(&b"DISCONNECT\n"[..]).await;
                            let _ = channel.close().await;
                            break;
                        }

                        if ping_requested.swap(false, Ordering::Relaxed) {
                            *ping_sent_at.lock().await = Some(Instant::now());
                            let _ = channel.data(&b"PING\n"[..]).await;
                        }
                    }
                }
            }
        });

        Ok(true)
    }

    // Called when client opens a direct-tcpip channel after successful TCP connect
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        originator_address: &str, // Contains req_id to match pending socket
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.authenticated {
            return Ok(false);
        }

        // req_id encoded in originator_address by client
        let req_id: u32 = match originator_address.parse() {
            Ok(id) => id,
            Err(_) => {
                warn!("[{}] Invalid req_id in direct-tcpip: {}", self.peer_addr, originator_address);
                return Ok(false);
            }
        };

        debug!("[{}] Direct-tcpip channel for req_id {}", self.peer_addr, req_id);

        // Get pending socket
        let pending = self.pending_sockets.lock().await.remove(&req_id);

        match pending {
            Some(pending_socket) => {
                debug!("[{}] Bridging channel to local socket for req_id {}", self.peer_addr, req_id);

                // Spawn bridge task
                let peer_addr = self.peer_addr;
                tokio::spawn(async move {
                    let mut stream = pending_socket.stream;

                    // Send SOCKS5 success if this is a SOCKS5 connection
                    if let Some(bind_addr) = pending_socket.socks5_bind_addr {
                        if let Err(e) = socks5::send_success(&mut stream, bind_addr).await {
                            warn!("[{}] Failed to send SOCKS5 success: {}", peer_addr, e);
                            return;
                        }
                        debug!("[{}] SOCKS5 success sent for req_id {}", peer_addr, req_id);
                    }

                    if let Err(e) = bridge_channel_to_socket(channel, stream).await {
                        trace!("[{}] Bridge error for req_id {}: {}", peer_addr, req_id, e);
                    }
                });

                Ok(true)
            }
            None => {
                warn!("[{}] No pending socket for req_id {}", self.peer_addr, req_id);
                Ok(false)
            }
        }
    }

}

/// Bridge data between an SSH channel and a TCP stream using select!
async fn bridge_channel_to_socket(
    mut channel: Channel<Msg>,
    tcp_stream: tokio::net::TcpStream,
) -> Result<()> {
    let (mut tcp_reader, mut tcp_writer) = tcp_stream.into_split();
    let mut buf = [0u8; 8192];

    loop {
        tokio::select! {
            // Read from TCP, write to channel
            result = tcp_reader.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        trace!("Local socket closed");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = channel.data(&buf[..n]).await {
                            trace!("Channel write error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        trace!("Local socket read error: {}", e);
                        break;
                    }
                }
            }
            // Read from channel, write to TCP
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        if let Err(e) = tcp_writer.write_all(&data).await {
                            trace!("Local socket write error: {}", e);
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) | None => {
                        trace!("Channel closed");
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

impl Drop for ServerHandler {
    /// Cleanup: remove session from manager when connection drops
    fn drop(&mut self) {
        if let Some(session_id) = self.session_id {
            let session_manager = self.session_manager.clone();
            tokio::spawn(async move {
                session_manager.unregister(session_id).await;
            });
        }
    }
}
