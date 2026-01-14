//! Session management for connected clients

use crate::socks5;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, Mutex as TokioMutex, RwLock};
use tracing::{debug, info, warn};

/// Auto-incrementing session ID for each new connection
static SESSION_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Auto-incrementing request ID to match CONNECT requests with direct-tcpip channels
static REQUEST_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Information about a session
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: u32,
    pub peer_addr: SocketAddr,
    pub connected_at: DateTime<Utc>,
    pub username: String,
    pub hostname: String,
    pub active_tunnels: Vec<TunnelInfo>,
}

/// Information about an active tunnel
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

/// Handle to control a running tunnel
pub struct TunnelHandle {
    pub info: TunnelInfo,
    pub shutdown_tx: tokio::sync::oneshot::Sender<()>,
}


/// Process information from remote client
#[derive(Debug, Clone, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub threads: u32,
}

/// Network connection information from remote client
#[derive(Debug, Clone, Deserialize)]
pub struct NetstatEntry {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
}

/// Handle to control a running SOCKS5 proxy
pub struct Socks5Handle {
    pub shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

/// TCP socket waiting for client to open matching direct-tcpip channel
pub struct PendingSocket {
    pub stream: tokio::net::TcpStream,
    /// If Some, this is a SOCKS5 connection - send success reply before bridging
    pub socks5_bind_addr: Option<std::net::SocketAddr>,
}

/// Represents a connected client session
pub struct Session {
    pub id: u32,
    pub peer_addr: SocketAddr,
    pub connected_at: DateTime<Utc>,
    pub username: String,
    /// Remote hostname (set by client after connection)
    pub hostname: Arc<TokioMutex<String>>,
    /// Shared flag to signal disconnect (client will reconnect)
    pub disconnect_flag: Arc<AtomicBool>,
    /// Shared flag to signal kill (client will exit)
    pub kill_flag: Arc<AtomicBool>,
    /// Flag to request a ping
    pub ping_requested: Arc<AtomicBool>,
    /// Ping result in milliseconds (None = pending, Some = completed)
    pub ping_result_ms: Arc<TokioMutex<Option<u64>>>,
    /// Active tunnels (port -> shutdown handle)
    pub active_tunnels: Arc<TokioMutex<HashMap<u16, TunnelHandle>>>,
    /// Active SOCKS5 proxies (port -> shutdown handle)
    pub active_socks5: Arc<TokioMutex<HashMap<u16, Socks5Handle>>>,
    /// Sender for CONNECT messages to client (set after channel opens)
    pub control_sender: Arc<TokioMutex<Option<mpsc::Sender<Vec<u8>>>>>,
    /// Pending sockets waiting for direct-tcpip channels (req_id -> socket)
    pub pending_sockets: Arc<TokioMutex<HashMap<u32, PendingSocket>>>,
    /// Pending process list response channel
    pub ps_response_tx: Arc<TokioMutex<Option<oneshot::Sender<Vec<ProcessInfo>>>>>,
    /// Pending netstat response channel
    pub ns_response_tx: Arc<TokioMutex<Option<oneshot::Sender<Vec<NetstatEntry>>>>>,
}

/// Handle given to the session's connection handler
pub struct SessionHandle {
    pub id: u32,
    /// Shared flag to signal disconnect (client will reconnect)
    pub disconnect_flag: Arc<AtomicBool>,
    /// Shared flag to signal kill (client will exit)
    pub kill_flag: Arc<AtomicBool>,
    /// Flag to request a ping
    pub ping_requested: Arc<AtomicBool>,
    /// Ping result in milliseconds
    pub ping_result_ms: Arc<TokioMutex<Option<u64>>>,
    /// Sender for CONNECT messages - SSH handler sets this
    pub control_sender: Arc<TokioMutex<Option<mpsc::Sender<Vec<u8>>>>>,
    /// Pending sockets (shared with Session)
    pub pending_sockets: Arc<TokioMutex<HashMap<u32, PendingSocket>>>,
}

impl Session {
    /// Create a new session and its corresponding handle
    pub fn new(peer_addr: SocketAddr, username: String) -> (Self, SessionHandle) {
        let id = SESSION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let connected_at = Utc::now();

        // Shared state between Session and SessionHandle
        let disconnect_flag = Arc::new(AtomicBool::new(false));
        let kill_flag = Arc::new(AtomicBool::new(false));
        let ping_requested = Arc::new(AtomicBool::new(false));
        let ping_result_ms = Arc::new(TokioMutex::new(None));
        let control_sender = Arc::new(TokioMutex::new(None));
        let pending_sockets = Arc::new(TokioMutex::new(HashMap::new()));

        let session = Session {
            id,
            peer_addr,
            connected_at,
            username,
            hostname: Arc::new(TokioMutex::new(String::from("unknown"))),
            disconnect_flag: disconnect_flag.clone(),
            kill_flag: kill_flag.clone(),
            ping_requested: ping_requested.clone(),
            ping_result_ms: ping_result_ms.clone(),
            active_tunnels: Arc::new(TokioMutex::new(HashMap::new())),
            active_socks5: Arc::new(TokioMutex::new(HashMap::new())),
            control_sender: control_sender.clone(),
            pending_sockets: pending_sockets.clone(),
            ps_response_tx: Arc::new(TokioMutex::new(None)),
            ns_response_tx: Arc::new(TokioMutex::new(None)),
        };

        let handle = SessionHandle {
            id,
            disconnect_flag,
            kill_flag,
            ping_requested,
            ping_result_ms,
            control_sender,
            pending_sockets,
        };

        (session, handle)
    }

    /// Get session info
    pub async fn info(&self) -> SessionInfo {
        SessionInfo {
            id: self.id,
            peer_addr: self.peer_addr,
            connected_at: self.connected_at,
            username: self.username.clone(),
            hostname: self.hostname.lock().await.clone(),
            active_tunnels: vec![],
        }
    }

    /// Signal this session to disconnect (client will reconnect)
    pub fn signal_disconnect(&self) {
        self.disconnect_flag.store(true, Ordering::Relaxed);
        debug!("Session {} disconnect flag set", self.id);
    }

    /// Signal this session to be killed (client will exit)
    pub fn signal_kill(&self) {
        self.kill_flag.store(true, Ordering::Relaxed);
        debug!("Session {} kill flag set", self.id);
    }
}

/// Manages all connected sessions
pub struct SessionManager {
    sessions: RwLock<HashMap<u32, Session>>,
}

impl SessionManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: RwLock::new(HashMap::new()),
        })
    }

    /// Register a new session, returns the session handle for the connection handler
    pub async fn register(&self, peer_addr: SocketAddr, username: String) -> SessionHandle {
        let (session, handle) = Session::new(peer_addr, username);
        let id = session.id;

        info!("Session {} registered: {} ({})", id, peer_addr, session.username);

        self.sessions.write().await.insert(id, session);
        handle
    }

    /// Unregister a session when it disconnects
    pub async fn unregister(&self, id: u32) {
        if let Some(session) = self.sessions.write().await.remove(&id) {
            info!("Session {} unregistered: {}", id, session.peer_addr);
        }
    }

    /// Get a list of all sessions
    pub async fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        let mut infos = Vec::new();
        for session in sessions.values() {
            infos.push(session.info().await);
        }
        infos
    }

    /// Get session count
    pub async fn count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Kill a session (client will exit completely)
    pub async fn kill_session(&self, id: u32) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            session.signal_kill();
            Ok(())
        } else {
            Err(format!("Session {} not found", id))
        }
    }

    /// Disconnect a session (client will reconnect)
    pub async fn disconnect_session(&self, id: u32) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            session.signal_disconnect();
            Ok(())
        } else {
            Err(format!("Session {} not found", id))
        }
    }

    /// Request a ping to a session, returns latency in ms or error
    pub async fn ping_session(&self, id: u32) -> Result<u64, String> {
        {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(&id) {
                *session.ping_result_ms.lock().await = None;
                session.ping_requested.store(true, Ordering::Relaxed);
            } else {
                return Err(format!("Session {} not found", id));
            }
        }

        let start = Instant::now();
        let timeout = std::time::Duration::from_secs(5);

        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(&id) {
                if let Some(latency) = *session.ping_result_ms.lock().await {
                    return Ok(latency);
                }
            } else {
                return Err(format!("Session {} disconnected", id));
            }

            if start.elapsed() > timeout {
                return Err("Ping timeout (5s)".to_string());
            }
        }
    }

    /// Get session info by ID
    pub async fn get_info(&self, id: u32) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            Some(session.info().await)
        } else {
            None
        }
    }

    /// Start a tunnel on a session - binds port and spawns listener
    pub async fn start_tunnel(
        &self,
        id: u32,
        bind_addr: &str,
        bind_port: u16,
        dest_host: &str,
        dest_port: u16,
    ) -> Result<(), String> {
        debug!("start_tunnel: session={}, {}:{} -> {}:{}", id, bind_addr, bind_port, dest_host, dest_port);

        // Get session data we need
        let (control_sender, pending_sockets, active_tunnels, peer_addr) = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&id).ok_or_else(|| format!("Session {} not found", id))?;

            if session.active_tunnels.lock().await.contains_key(&bind_port) {
                return Err(format!("Tunnel already exists on port {}", bind_port));
            }

            (
                session.control_sender.clone(),
                session.pending_sockets.clone(),
                session.active_tunnels.clone(),
                session.peer_addr,
            )
        };

        // Check if control sender is available
        if control_sender.lock().await.is_none() {
            return Err("SSH channel not ready yet".to_string());
        }

        // Bind the TCP listener
        let listen_addr = format!("{}:{}", bind_addr, bind_port);
        let listener = TcpListener::bind(&listen_addr).await
            .map_err(|e| format!("Failed to bind {}: {}", listen_addr, e))?;

        info!("[{}] Tunnel bound on {} -> {}:{}", peer_addr, listen_addr, dest_host, dest_port);

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

        // Store tunnel handle
        let tunnel_info = TunnelInfo {
            local_port: bind_port,
            remote_host: dest_host.to_string(),
            remote_port: dest_port,
        };
        active_tunnels.lock().await.insert(bind_port, TunnelHandle {
            info: tunnel_info,
            shutdown_tx,
        });

        // Spawn accept loop
        let dest_host = dest_host.to_string();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, client_addr)) => {
                                debug!("[{}] Tunnel connection from {}", peer_addr, client_addr);

                                let req_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

                                // Store pending socket (no SOCKS5 response needed for direct tunnels)
                                pending_sockets.lock().await.insert(req_id, PendingSocket {
                                    stream,
                                    socks5_bind_addr: None,
                                });

                                // Build and send CONNECT request to client
                                // Client will TCP connect to target, then open direct-tcpip channel with req_id
                                let host_bytes = dest_host.as_bytes();
                                let mut packet = b"CONNECT".to_vec();
                                packet.extend_from_slice(&req_id.to_be_bytes());
                                packet.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
                                packet.extend_from_slice(host_bytes);
                                packet.extend_from_slice(&dest_port.to_be_bytes());

                                let sent = if let Some(sender) = control_sender.lock().await.as_ref() {
                                    sender.send(packet).await.is_ok()
                                } else {
                                    false
                                };

                                if !sent {
                                    warn!("[{}] Failed to send CONNECT request", peer_addr);
                                    pending_sockets.lock().await.remove(&req_id);
                                }
                            }
                            Err(e) => {
                                warn!("[{}] Accept error on port {}: {}", peer_addr, bind_port, e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        debug!("[{}] Tunnel on port {} shutdown", peer_addr, bind_port);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop a tunnel on a session
    pub async fn stop_tunnel(&self, id: u32, bind_port: u16) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut tunnels = session.active_tunnels.lock().await;
            if let Some(handle) = tunnels.remove(&bind_port) {
                let _ = handle.shutdown_tx.send(());
                debug!("Tunnel on port {} stopped for session {}", bind_port, id);
                Ok(())
            } else {
                Err(format!("No tunnel on port {}", bind_port))
            }
        } else {
            Err(format!("Session {} not found", id))
        }
    }

    /// List active tunnels for a session
    pub async fn list_tunnels(&self, id: u32) -> Result<Vec<TunnelInfo>, String> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let tunnels = session.active_tunnels.lock().await;
            let infos: Vec<TunnelInfo> = tunnels.values().map(|h| h.info.clone()).collect();
            Ok(infos)
        } else {
            Err(format!("Session {} not found", id))
        }
    }

    /// Start a SOCKS5 proxy on a session - binds port and spawns listener
    pub async fn start_socks5(
        &self,
        id: u32,
        bind_addr: &str,
        bind_port: u16,
    ) -> Result<(), String> {
        debug!("start_socks5: session={}, {}:{}", id, bind_addr, bind_port);

        // Get session data we need
        let (control_sender, pending_sockets, active_socks5, peer_addr) = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&id).ok_or_else(|| format!("Session {} not found", id))?;

            if session.active_socks5.lock().await.contains_key(&bind_port) {
                return Err(format!("SOCKS5 proxy already exists on port {}", bind_port));
            }

            if session.active_tunnels.lock().await.contains_key(&bind_port) {
                return Err(format!("Tunnel already exists on port {}", bind_port));
            }

            (
                session.control_sender.clone(),
                session.pending_sockets.clone(),
                session.active_socks5.clone(),
                session.peer_addr,
            )
        };

        // Check if control sender is available
        if control_sender.lock().await.is_none() {
            return Err("SSH channel not ready yet".to_string());
        }

        // Bind the TCP listener
        let listen_addr = format!("{}:{}", bind_addr, bind_port);
        let listener = TcpListener::bind(&listen_addr).await
            .map_err(|e| format!("Failed to bind {}: {}", listen_addr, e))?;

        info!("[{}] SOCKS5 proxy bound on {}", peer_addr, listen_addr);

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

        // Store SOCKS5 handle
        active_socks5.lock().await.insert(bind_port, Socks5Handle {
            shutdown_tx,
        });

        // Spawn accept loop
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((mut stream, client_addr)) => {
                                debug!("[{}] SOCKS5 connection from {}", peer_addr, client_addr);

                                // Perform SOCKS5 handshake
                                let request = match socks5::handshake(&mut stream).await {
                                    Ok(req) => req,
                                    Err(e) => {
                                        warn!("[{}] SOCKS5 handshake failed: {}", peer_addr, e);
                                        continue;
                                    }
                                };

                                info!("[{}] SOCKS5 CONNECT -> {}:{}", peer_addr, request.dest_host, request.dest_port);

                                let req_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

                                // Store pending socket with SOCKS5 bind address
                                // Success response sent by SSH handler when direct-tcpip channel arrives
                                let bind_sock_addr: SocketAddr = format!("0.0.0.0:{}", bind_port).parse().unwrap();
                                pending_sockets.lock().await.insert(req_id, PendingSocket {
                                    stream,
                                    socks5_bind_addr: Some(bind_sock_addr),
                                });

                                // Send CONNECT request
                                let host_bytes = request.dest_host.as_bytes();
                                let mut packet = b"CONNECT".to_vec();
                                packet.extend_from_slice(&req_id.to_be_bytes());
                                packet.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
                                packet.extend_from_slice(host_bytes);
                                packet.extend_from_slice(&request.dest_port.to_be_bytes());

                                let sent = if let Some(sender) = control_sender.lock().await.as_ref() {
                                    sender.send(packet).await.is_ok()
                                } else {
                                    false
                                };

                                if !sent {
                                    warn!("[{}] Failed to send SOCKS5 CONNECT request", peer_addr);
                                    pending_sockets.lock().await.remove(&req_id);
                                }
                            }
                            Err(e) => {
                                warn!("[{}] SOCKS5 accept error on port {}: {}", peer_addr, bind_port, e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        debug!("[{}] SOCKS5 proxy on port {} shutdown", peer_addr, bind_port);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop a SOCKS5 proxy on a session
    pub async fn stop_socks5(&self, id: u32, bind_port: u16) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut proxies = session.active_socks5.lock().await;
            if let Some(handle) = proxies.remove(&bind_port) {
                let _ = handle.shutdown_tx.send(());
                debug!("SOCKS5 proxy on port {} stopped for session {}", bind_port, id);
                Ok(())
            } else {
                Err(format!("No SOCKS5 proxy on port {}", bind_port))
            }
        } else {
            Err(format!("Session {} not found", id))
        }
    }

    /// Request process list from remote client
    pub async fn request_process_list(&self, id: u32) -> Result<Vec<ProcessInfo>, String> {
        // Create oneshot channel for response
        let (tx, rx) = oneshot::channel();

        // Setup the request
        {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&id).ok_or_else(|| format!("Session {} not found", id))?;

            // Store the response channel
            *session.ps_response_tx.lock().await = Some(tx);

            // Send PROCESSLIST request
            let control_sender = session.control_sender.lock().await;
            if let Some(sender) = control_sender.as_ref() {
                sender.send(b"PROCESSLIST".to_vec()).await
                    .map_err(|_| "Failed to send PROCESSLIST request".to_string())?;
            } else {
                return Err("SSH channel not ready".to_string());
            }
        }

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(processes)) => Ok(processes),
            Ok(Err(_)) => Err("Response channel closed".to_string()),
            Err(_) => Err("Timeout waiting for process list".to_string()),
        }
    }

    /// Called by SSH handler when PSRESP is received
    pub async fn handle_process_list_response(&self, id: u32, processes: Vec<ProcessInfo>) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            if let Some(tx) = session.ps_response_tx.lock().await.take() {
                let _ = tx.send(processes);
            }
        }
    }

    /// Request network connection list from remote client
    pub async fn request_netstat(&self, id: u32) -> Result<Vec<NetstatEntry>, String> {
        // Create oneshot channel for response
        let (tx, rx) = oneshot::channel();

        // Setup the request
        {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&id).ok_or_else(|| format!("Session {} not found", id))?;

            // Store the response channel
            *session.ns_response_tx.lock().await = Some(tx);

            // Send NETSTAT request
            let control_sender = session.control_sender.lock().await;
            if let Some(sender) = control_sender.as_ref() {
                sender.send(b"NETSTAT".to_vec()).await
                    .map_err(|_| "Failed to send NETSTAT request".to_string())?;
            } else {
                return Err("SSH channel not ready".to_string());
            }
        }

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(connections)) => Ok(connections),
            Ok(Err(_)) => Err("Response channel closed".to_string()),
            Err(_) => Err("Timeout waiting for netstat".to_string()),
        }
    }

    /// Called by SSH handler when NSRESP is received
    pub async fn handle_netstat_response(&self, id: u32, connections: Vec<NetstatEntry>) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            if let Some(tx) = session.ns_response_tx.lock().await.take() {
                let _ = tx.send(connections);
            }
        }
    }

    /// Update session hostname (called by SSH handler when HOSTNAME message received)
    pub async fn set_hostname(&self, id: u32, hostname: String) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            *session.hostname.lock().await = hostname;
            debug!("Session {} hostname set", id);
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}
