//! Interactive CLI for the server

use crate::session::{SessionManager, SessionInfo};
use crate::{ssh, websocket};
use chisel_ng_common::PresharedKey;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, debug};

const BANNER: &str = r#"
       _     _          _
   ___| |__ (_)___  ___| |      _ __   __ _
  / __| '_ \| / __|/ _ \ |_____| '_ \ / _` |
 | (__| | | | \__ \  __/ |_____| | | | (_| |
  \___|_| |_|_|___/\___|_|     |_| |_|\__, |
                                      |___/
"#;

const MAIN_HELP: &str = r#"
Commands:
  sessions           List all connected sessions
  session <id>       Interact with a specific session
  session            Interactive session selection
  connect <host:port> Connect to a bind client
  disconnect <id>    Disconnect a session (client will reconnect)
  kill <id>          Kill a session (client exits completely)
  help               Show this help message
  exit               Exit the server
"#;

const SESSION_HELP: &str = r#"
Session Commands:
  info                                      Show session information
  ping                                      Ping client and measure latency
  ps                                        List processes on remote client
  netstat                                   List network connections on remote client
  tunnel <bindport>:<dest_ip>:<destport>    Start a tunnel (binds 0.0.0.0)
  tunnel --local <bindport>:<dest>:<port>   Start a tunnel (binds 127.0.0.1)
  tunnels                                   List active tunnels
  tunnel stop <bindport>                    Stop a tunnel
  socks5 <port>                             Start SOCKS5 proxy (binds 0.0.0.0)
  socks5 --local <port>                     Start SOCKS5 proxy (binds 127.0.0.1)
  socks5 stop <port>                        Stop SOCKS5 proxy
  disconnect                                Disconnect (client will reconnect)
  kill                                      Kill client (exits completely)
  back                                      Return to main menu
  help                                      Show this help message
"#;

/// Run the interactive CLI
pub async fn run(
    session_manager: Arc<SessionManager>,
    tls_acceptor: TlsAcceptor,
    ssh_key: russh::keys::PrivateKey,
    psk: PresharedKey,
) {
    println!("{}", BANNER);
    println!("Type 'help' for available commands.\n");

    let mut rl = match DefaultEditor::new() {
        Ok(rl) => rl,
        Err(e) => {
            error!("Failed to initialize CLI: {}", e);
            return;
        }
    };

    loop {
        let session_count = session_manager.count().await;
        let prompt = format!("chisel-ng ({} sessions) > ", session_count);

        // block_in_place allows synchronous readline without blocking tokio's async runtime
        let result = tokio::task::block_in_place(|| rl.readline(&prompt));
        match result {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let _ = rl.add_history_entry(line);

                let parts: Vec<&str> = line.split_whitespace().collect();
                let cmd = parts.first().map(|s| *s).unwrap_or("");

                match cmd {
                    "help" | "?" => {
                        println!("{}", MAIN_HELP);
                    }
                    "sessions" | "list" => {
                        list_sessions(&session_manager).await;
                    }
                    "session" => {
                        if let Some(id_str) = parts.get(1) {
                            if let Ok(id) = id_str.parse::<u32>() {
                                enter_session(&mut rl, &session_manager, id).await;
                            } else {
                                println!("Invalid session ID: {}", id_str);
                            }
                        } else {
                            // Interactive session selection
                            select_session(&mut rl, &session_manager).await;
                        }
                    }
                    "kill" => {
                        if let Some(id_str) = parts.get(1) {
                            if let Ok(id) = id_str.parse::<u32>() {
                                kill_session(&session_manager, id).await;
                            } else {
                                println!("Invalid session ID: {}", id_str);
                            }
                        } else {
                            println!("Usage: kill <session_id>");
                        }
                    }
                    "connect" => {
                        if let Some(addr) = parts.get(1) {
                            println!("Connecting to {}...", addr);
                            let addr = addr.to_string();
                            let tls = tls_acceptor.clone();
                            let key = ssh_key.clone();
                            let p = psk.clone();
                            let mgr = session_manager.clone();
                            tokio::spawn(async move {
                                match connect_to_bind_client(&addr, tls, key, p, mgr).await {
                                    Ok(()) => info!("Bind client session ended: {}", addr),
                                    Err(e) => println!("Connect failed: {}", e),
                                }
                            });
                        } else {
                            println!("Usage: connect <host:port>");
                        }
                    }
                    "disconnect" => {
                        if let Some(id_str) = parts.get(1) {
                            if let Ok(id) = id_str.parse::<u32>() {
                                disconnect_session(&session_manager, id).await;
                            } else {
                                println!("Invalid session ID: {}", id_str);
                            }
                        } else {
                            println!("Usage: disconnect <session_id>");
                        }
                    }
                    "exit" | "quit" => {
                        println!("Exiting...");
                        break;
                    }
                    _ => {
                        println!("Unknown command: {}. Type 'help' for available commands.", cmd);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("exit");
                break;
            }
            Err(err) => {
                error!("CLI error: {}", err);
                break;
            }
        }
    }
}

/// List all connected sessions
async fn list_sessions(session_manager: &SessionManager) {
    let sessions = session_manager.list().await;

    if sessions.is_empty() {
        println!("No active sessions.");
        return;
    }

    println!();
    println!("  {:<4} {:<25} {:<15} {:<10} {:<20}", "ID", "Address", "Hostname", "User", "Connected");
    println!("  {}", "-".repeat(78));

    for session in sessions {
        let connected = session.connected_at.format("%Y-%m-%d %H:%M:%S").to_string();
        // Truncate hostname if too long
        let hostname = if session.hostname.len() > 14 {
            format!("{}…", &session.hostname[..13])
        } else {
            session.hostname.clone()
        };
        println!(
            "  {:<4} {:<25} {:<15} {:<10} {:<20}",
            session.id, session.peer_addr, hostname, session.username, connected
        );
    }
    println!();
}

/// Interactive session selection
async fn select_session(rl: &mut DefaultEditor, session_manager: &SessionManager) {
    let sessions = session_manager.list().await;

    if sessions.is_empty() {
        println!("No active sessions.");
        return;
    }

    println!("\nAvailable sessions:");
    for (idx, session) in sessions.iter().enumerate() {
        println!(
            "  [{}] Session {} - {} ({})",
            idx + 1,
            session.id,
            session.peer_addr,
            session.username
        );
    }
    println!();

    let result = tokio::task::block_in_place(|| rl.readline("Select session: "));
    match result {
        Ok(line) => {
            let line = line.trim();
            if line.is_empty() {
                return;
            }

            // Try parsing as index first (1-based)
            if let Ok(idx) = line.parse::<usize>() {
                if idx > 0 && idx <= sessions.len() {
                    let session = &sessions[idx - 1];
                    enter_session(rl, session_manager, session.id).await;
                    return;
                }
            }

            // Try parsing as session ID
            if let Ok(id) = line.parse::<u32>() {
                if sessions.iter().any(|s| s.id == id) {
                    enter_session(rl, session_manager, id).await;
                    return;
                }
            }

            println!("Invalid selection.");
        }
        Err(_) => {}
    }
}

/// Enter a session's subshell
async fn enter_session(rl: &mut DefaultEditor, session_manager: &SessionManager, id: u32) {
    let info = match session_manager.get_info(id).await {
        Some(info) => info,
        None => {
            println!("Session {} not found.", id);
            return;
        }
    };

    println!();
    println!("Entering session {} ({})...", id, info.peer_addr);
    println!("Type 'help' for session commands, 'back' to return.\n");

    loop {
        let prompt = format!("[session-{}] {} > ", id, info.peer_addr);

        let result = tokio::task::block_in_place(|| rl.readline(&prompt));
        match result {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let _ = rl.add_history_entry(line);

                let parts: Vec<&str> = line.split_whitespace().collect();
                let cmd = parts.first().map(|s| *s).unwrap_or("");

                match cmd {
                    "help" | "?" => {
                        println!("{}", SESSION_HELP);
                    }
                    "back" | "exit" => {
                        println!("Returning to main menu.\n");
                        break;
                    }
                    "info" => {
                        print_session_info(&info);
                    }
                    "tunnel" => {
                        if parts.len() < 2 {
                            println!("Usage: tunnel [--local] <bindport>:<dest_ip>:<destport>");
                            println!("       tunnel stop <bindport>");
                            continue;
                        }

                        let (local_only, spec) = if parts.get(1) == Some(&"--local") {
                            (true, parts.get(2))
                        } else if parts.get(1) == Some(&"stop") {
                            // Handle tunnel stop
                            if let Some(port_str) = parts.get(2) {
                                if let Ok(port) = port_str.parse::<u16>() {
                                    match session_manager.stop_tunnel(id, port).await {
                                        Ok(()) => println!("Tunnel on port {} stopped.", port),
                                        Err(e) => println!("Failed to stop tunnel: {}", e),
                                    }
                                } else {
                                    println!("Invalid port: {}", port_str);
                                }
                            } else {
                                println!("Usage: tunnel stop <bindport>");
                            }
                            continue;
                        } else {
                            (false, parts.get(1))
                        };

                        if let Some(spec) = spec {
                            // Parse bindport:dest_ip:destport
                            let parts: Vec<&str> = spec.split(':').collect();
                            if parts.len() != 3 {
                                println!("Invalid format. Use: <bindport>:<dest_ip>:<destport>");
                                continue;
                            }

                            let bind_port: u16 = match parts[0].parse() {
                                Ok(p) => p,
                                Err(_) => {
                                    println!("Invalid bind port: {}", parts[0]);
                                    continue;
                                }
                            };

                            let dest_ip = parts[1].to_string();

                            let dest_port: u16 = match parts[2].parse() {
                                Ok(p) => p,
                                Err(_) => {
                                    println!("Invalid dest port: {}", parts[2]);
                                    continue;
                                }
                            };

                            let bind_addr = if local_only { "127.0.0.1" } else { "0.0.0.0" };

                            match session_manager.start_tunnel(id, bind_addr, bind_port, &dest_ip, dest_port).await {
                                Ok(()) => println!("Tunnel started on {}:{}", bind_addr, bind_port),
                                Err(e) => println!("Failed to start tunnel: {}", e),
                            }
                        } else {
                            println!("Usage: tunnel [--local] <bindport>:<dest_ip>:<destport>");
                        }
                    }
                    "tunnels" => {
                        match session_manager.list_tunnels(id).await {
                            Ok(tunnels) => {
                                if tunnels.is_empty() {
                                    println!("No active tunnels.");
                                } else {
                                    println!("\nActive tunnels:");
                                    for t in tunnels {
                                        println!("  :{} -> {}:{}", t.local_port, t.remote_host, t.remote_port);
                                    }
                                    println!();
                                }
                            }
                            Err(e) => println!("Failed to list tunnels: {}", e),
                        }
                    }
                    "socks5" => {
                        if parts.len() < 2 {
                            println!("Usage: socks5 [--local] <port>");
                            println!("       socks5 stop <port>");
                            continue;
                        }

                        let (local_only, port_arg) = if parts.get(1) == Some(&"--local") {
                            (true, parts.get(2))
                        } else if parts.get(1) == Some(&"stop") {
                            // Handle socks5 stop
                            if let Some(port_str) = parts.get(2) {
                                if let Ok(port) = port_str.parse::<u16>() {
                                    match session_manager.stop_socks5(id, port).await {
                                        Ok(()) => println!("SOCKS5 proxy on port {} stopped.", port),
                                        Err(e) => println!("Failed to stop SOCKS5 proxy: {}", e),
                                    }
                                } else {
                                    println!("Invalid port: {}", port_str);
                                }
                            } else {
                                println!("Usage: socks5 stop <port>");
                            }
                            continue;
                        } else {
                            (false, parts.get(1))
                        };

                        if let Some(port_str) = port_arg {
                            if let Ok(port) = port_str.parse::<u16>() {
                                let bind_addr = if local_only { "127.0.0.1" } else { "0.0.0.0" };
                                match session_manager.start_socks5(id, bind_addr, port).await {
                                    Ok(()) => println!("SOCKS5 proxy started on {}:{}", bind_addr, port),
                                    Err(e) => println!("Failed to start SOCKS5 proxy: {}", e),
                                }
                            } else {
                                println!("Invalid port: {}", port_str);
                            }
                        } else {
                            println!("Usage: socks5 [--local] <port>");
                        }
                    }
                    "ping" => {
                        println!("Pinging...");
                        match session_manager.ping_session(id).await {
                            Ok(latency_ms) => {
                                println!("Pong: {}ms", latency_ms);
                            }
                            Err(e) => {
                                println!("Ping failed: {}", e);
                            }
                        }
                    }
                    "ps" => {
                        println!("Requesting process list...");
                        match session_manager.request_process_list(id).await {
                            Ok(processes) => {
                                println!();
                                println!("  {:<8} {:<8} {:<8} {}", "PID", "PPID", "THREADS", "NAME");
                                println!("  {}", "-".repeat(60));
                                for p in processes {
                                    println!("  {:<8} {:<8} {:<8} {}", p.pid, p.ppid, p.threads, p.name);
                                }
                                println!();
                            }
                            Err(e) => {
                                println!("Failed to get process list: {}", e);
                            }
                        }
                    }
                    "netstat" => {
                        println!("Requesting network connections...");
                        match session_manager.request_netstat(id).await {
                            Ok(connections) => {
                                println!();
                                println!("  {:<5} {:<22} {:<22} {:<12} {:<8}", "PROTO", "LOCAL", "REMOTE", "STATE", "PID");
                                println!("  {}", "-".repeat(75));
                                for c in connections {
                                    let local = format!("{}:{}", c.local_addr, c.local_port);
                                    let remote = if c.remote_port > 0 {
                                        format!("{}:{}", c.remote_addr, c.remote_port)
                                    } else {
                                        c.remote_addr.clone()
                                    };
                                    println!("  {:<5} {:<22} {:<22} {:<12} {:<8}", c.protocol, local, remote, c.state, c.pid);
                                }
                                println!();
                            }
                            Err(e) => {
                                println!("Failed to get network connections: {}", e);
                            }
                        }
                    }
                    "disconnect" => {
                        match session_manager.disconnect_session(id).await {
                            Ok(()) => {
                                println!("Disconnect sent. Client will reconnect.");
                                break;
                            }
                            Err(e) => {
                                println!("Failed to disconnect session: {}", e);
                            }
                        }
                    }
                    "kill" => {
                        match session_manager.kill_session(id).await {
                            Ok(()) => {
                                println!("Kill sent. Client will exit.");
                                break;
                            }
                            Err(e) => {
                                println!("Failed to kill session: {}", e);
                            }
                        }
                    }
                    _ => {
                        println!("Unknown command: {}. Type 'help' for session commands.", cmd);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C (use 'back' to exit session)");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("back");
                break;
            }
            Err(err) => {
                error!("CLI error: {}", err);
                break;
            }
        }
    }
}

/// Print detailed session info
fn print_session_info(info: &SessionInfo) {
    println!();
    println!("  Session ID:    {}", info.id);
    println!("  Remote:        {}", info.peer_addr);
    println!("  Hostname:      {}", info.hostname);
    println!("  User:          {}", info.username);
    println!("  Connected:     {}", info.connected_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Tunnels:       {}", info.active_tunnels.len());

    if !info.active_tunnels.is_empty() {
        println!("  Active tunnels:");
        for tunnel in &info.active_tunnels {
            println!(
                "    :{} -> {}:{}",
                tunnel.local_port, tunnel.remote_host, tunnel.remote_port
            );
        }
    }
    println!();
}

/// Kill a session by ID (client exits completely)
async fn kill_session(session_manager: &SessionManager, id: u32) {
    match session_manager.kill_session(id).await {
        Ok(()) => {
            println!("Kill sent to session {}. Client will exit.", id);
        }
        Err(e) => {
            println!("Failed to kill session {}: {}", id, e);
        }
    }
}

/// Disconnect a session by ID (client will reconnect)
async fn disconnect_session(session_manager: &SessionManager, id: u32) {
    match session_manager.disconnect_session(id).await {
        Ok(()) => {
            println!("Disconnect sent to session {}. Client will reconnect.", id);
        }
        Err(e) => {
            println!("Failed to disconnect session {}: {}", id, e);
        }
    }
}

/// Connect to a bind client (outbound TCP, then accept TLS/WS/SSH)
async fn connect_to_bind_client(
    addr: &str,
    tls_acceptor: TlsAcceptor,
    ssh_key: russh::keys::PrivateKey,
    psk: PresharedKey,
    session_manager: Arc<SessionManager>,
) -> anyhow::Result<()> {
    // Parse address (IP:port only, no DNS resolution)
    let socket_addr: SocketAddr = addr.parse()
        .map_err(|_| anyhow::anyhow!("Invalid address format. Use IP:port (no DNS resolution)"))?;

    // TCP connect to bind client
    debug!("TCP connecting to {}", addr);
    let tcp_stream = TcpStream::connect(socket_addr).await
        .map_err(|e| anyhow::anyhow!("TCP connect failed: {}", e))?;

    let peer_addr = tcp_stream.peer_addr()?;
    info!("Connected to bind client at {}", peer_addr);

    // TLS accept (bind client initiates as TLS client)
    debug!("Waiting for TLS handshake from {}", peer_addr);
    let tls_stream = tls_acceptor.accept(tcp_stream).await
        .map_err(|e| anyhow::anyhow!("TLS handshake failed: {}", e))?;

    debug!("TLS handshake complete with {}", peer_addr);

    // WebSocket accept (bind client initiates upgrade)
    let ws_stream = websocket::accept(tls_stream).await
        .map_err(|e| anyhow::anyhow!("WebSocket upgrade failed: {}", e))?;

    debug!("WebSocket upgrade complete with {}", peer_addr);

    // Run SSH server (same as incoming connections)
    ssh::run_server(ws_stream, ssh_key, psk, peer_addr, session_manager).await?;

    info!("Bind client session closed: {}", peer_addr);
    Ok(())
}
