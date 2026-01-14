//! Native process enumeration without spawning subprocesses

use crate::proto_str;
use serde::Serialize;

/// Information about a running process
#[derive(Debug, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub threads: u32,
}

/// List all running processes using Win32 ToolHelp API (no subprocess spawn)
#[cfg(windows)]
pub fn list_processes() -> Vec<ProcessInfo> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
        TH32CS_SNAPPROCESS,
    };

    let mut processes = Vec::new();

    unsafe {
        // Create snapshot of all processes
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return processes,
        };

        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        // Get first process
        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                // Extract process name from szExeFile (null-terminated char array)
                let name_bytes: Vec<u8> = entry
                    .szExeFile
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8)
                    .collect();
                let name = String::from_utf8_lossy(&name_bytes).to_string();

                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    ppid: entry.th32ParentProcessID,
                    name,
                    threads: entry.cntThreads,
                });

                // Get next process
                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    processes
}

/// List all running processes using /proc filesystem (Linux)
#[cfg(target_os = "linux")]
pub fn list_processes() -> Vec<ProcessInfo> {
    use std::fs;

    let mut processes = Vec::new();

    // Read /proc directory for process entries
    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(_) => return processes,
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Only process numeric directories (PIDs)
        if let Ok(pid) = name_str.parse::<u32>() {
            if let Some(info) = read_process_info(pid) {
                processes.push(info);
            }
        }
    }

    processes
}

#[cfg(target_os = "linux")]
fn read_process_info(pid: u32) -> Option<ProcessInfo> {
    use std::fs;

    // Read /proc/[pid]/stat
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = fs::read_to_string(&stat_path).ok()?;

    // Parse stat file: pid (comm) state ppid ...
    // The comm field is in parentheses and may contain spaces
    let open_paren = stat_content.find('(')?;
    let close_paren = stat_content.rfind(')')?;

    let name = stat_content[open_paren + 1..close_paren].to_string();
    let after_name = &stat_content[close_paren + 2..];
    let fields: Vec<&str> = after_name.split_whitespace().collect();

    // fields[0] = state, fields[1] = ppid, ...
    // fields[17] = num_threads (20th field in stat, index 19, but we skip pid and comm)
    let ppid = fields.get(1)?.parse::<u32>().ok()?;
    let threads = fields.get(17)?.parse::<u32>().unwrap_or(1);

    Some(ProcessInfo {
        pid,
        ppid,
        name,
        threads,
    })
}

/// Stub for non-Linux/non-Windows platforms
#[cfg(not(any(windows, target_os = "linux")))]
pub fn list_processes() -> Vec<ProcessInfo> {
    Vec::new()
}

/// Information about a network connection
#[derive(Debug, Serialize)]
pub struct NetstatEntry {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
}

/// List TCP/UDP connections using Win32 IP Helper API (no subprocess spawn)
#[cfg(windows)]
pub fn list_connections() -> Vec<NetstatEntry> {
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSE_WAIT,
        MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB,
        MIB_TCP_STATE_FIN_WAIT1, MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK,
        MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_SYN_SENT,
        MIB_TCP_STATE_TIME_WAIT, MIB_TCPTABLE_OWNER_PID,
        MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut connections = Vec::new();

    unsafe {
        // Get TCP connections
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if result == NO_ERROR.0
            {
                let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr(),
                    table.dwNumEntries as usize,
                );

                for row in rows {
                    let state = match row.dwState {
                        x if x == MIB_TCP_STATE_CLOSED.0 as u32 => proto_str!("CLOSED").to_string(),
                        x if x == MIB_TCP_STATE_LISTEN.0 as u32 => proto_str!("LISTEN").to_string(),
                        x if x == MIB_TCP_STATE_SYN_SENT.0 as u32 => proto_str!("SYN_SENT").to_string(),
                        x if x == MIB_TCP_STATE_SYN_RCVD.0 as u32 => proto_str!("SYN_RCVD").to_string(),
                        x if x == MIB_TCP_STATE_ESTAB.0 as u32 => proto_str!("ESTABLISHED").to_string(),
                        x if x == MIB_TCP_STATE_FIN_WAIT1.0 as u32 => proto_str!("FIN_WAIT1").to_string(),
                        x if x == MIB_TCP_STATE_FIN_WAIT2.0 as u32 => proto_str!("FIN_WAIT2").to_string(),
                        x if x == MIB_TCP_STATE_CLOSE_WAIT.0 as u32 => proto_str!("CLOSE_WAIT").to_string(),
                        x if x == MIB_TCP_STATE_CLOSING.0 as u32 => proto_str!("CLOSING").to_string(),
                        x if x == MIB_TCP_STATE_LAST_ACK.0 as u32 => proto_str!("LAST_ACK").to_string(),
                        x if x == MIB_TCP_STATE_TIME_WAIT.0 as u32 => proto_str!("TIME_WAIT").to_string(),
                        x if x == MIB_TCP_STATE_DELETE_TCB.0 as u32 => proto_str!("DELETE_TCB").to_string(),
                        _ => proto_str!("UNKNOWN").to_string(),
                    };

                    connections.push(NetstatEntry {
                        protocol: proto_str!("TCP").to_string(),
                        local_addr: format_ipv4(row.dwLocalAddr),
                        local_port: u16::from_be(row.dwLocalPort as u16),
                        remote_addr: format_ipv4(row.dwRemoteAddr),
                        remote_port: u16::from_be(row.dwRemotePort as u16),
                        state,
                        pid: row.dwOwningPid,
                    });
                }
            }
        }

        // Get UDP connections
        size = 0;
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if result == NO_ERROR.0
            {
                let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr(),
                    table.dwNumEntries as usize,
                );

                for row in rows {
                    connections.push(NetstatEntry {
                        protocol: proto_str!("UDP").to_string(),
                        local_addr: format_ipv4(row.dwLocalAddr),
                        local_port: u16::from_be(row.dwLocalPort as u16),
                        remote_addr: proto_str!("*").to_string(),
                        remote_port: 0,
                        state: proto_str!("-").to_string(),
                        pid: row.dwOwningPid,
                    });
                }
            }
        }
    }

    connections
}

#[cfg(windows)]
fn format_ipv4(addr: u32) -> String {
    let bytes = addr.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// List all network connections using /proc/net (Linux)
#[cfg(target_os = "linux")]
pub fn list_connections() -> Vec<NetstatEntry> {
    use std::fs;

    let mut connections = Vec::new();

    // Build inode -> pid mapping from /proc/[pid]/fd
    let inode_to_pid = build_inode_pid_map();

    // Parse TCP connections
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        parse_proc_net(&content, proto_str!("TCP"), &inode_to_pid, &mut connections);
    }

    // Parse TCP6 connections
    if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
        parse_proc_net(&content, proto_str!("TCP6"), &inode_to_pid, &mut connections);
    }

    // Parse UDP connections
    if let Ok(content) = fs::read_to_string("/proc/net/udp") {
        parse_proc_net(&content, proto_str!("UDP"), &inode_to_pid, &mut connections);
    }

    // Parse UDP6 connections
    if let Ok(content) = fs::read_to_string("/proc/net/udp6") {
        parse_proc_net(&content, proto_str!("UDP6"), &inode_to_pid, &mut connections);
    }

    connections
}

/// Build socket inode to PID mapping by scanning /proc/[pid]/fd symlinks
#[cfg(target_os = "linux")]
fn build_inode_pid_map() -> std::collections::HashMap<u64, u32> {
    use std::fs;
    use std::collections::HashMap;

    let mut map = HashMap::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if let Ok(pid) = name_str.parse::<u32>() {
            let fd_path = format!("/proc/{}/fd", pid);
            if let Ok(fd_dir) = fs::read_dir(&fd_path) {
                for fd_entry in fd_dir.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        // Format: socket:[12345]
                        if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                            if let Ok(inode) = link_str[8..link_str.len() - 1].parse::<u64>() {
                                map.insert(inode, pid);
                            }
                        }
                    }
                }
            }
        }
    }

    map
}

#[cfg(target_os = "linux")]
fn parse_proc_net(
    content: &str,
    protocol: &str,
    inode_to_pid: &std::collections::HashMap<u64, u32>,
    connections: &mut Vec<NetstatEntry>,
) {
    // Skip header line
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        // Fields: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
        let local = fields[1];
        let remote = fields[2];
        let state_hex = fields[3];
        let inode_str = fields.get(9).unwrap_or(&"0");

        let (local_addr, local_port) = parse_addr_port(local, protocol.contains('6'));
        let (remote_addr, remote_port) = parse_addr_port(remote, protocol.contains('6'));

        let state = if protocol.starts_with(&proto_str!("UDP")[..]) {
            proto_str!("-").to_string()
        } else {
            tcp_state_from_hex(state_hex)
        };

        let inode = inode_str.parse::<u64>().unwrap_or(0);
        let pid = inode_to_pid.get(&inode).copied().unwrap_or(0);

        connections.push(NetstatEntry {
            protocol: protocol.to_string(),
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid,
        });
    }
}

#[cfg(target_os = "linux")]
fn parse_addr_port(addr_port: &str, is_ipv6: bool) -> (String, u16) {
    let parts: Vec<&str> = addr_port.split(':').collect();
    if parts.len() != 2 {
        return ("0.0.0.0".to_string(), 0);
    }

    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    let addr = if is_ipv6 {
        parse_ipv6_hex(parts[0])
    } else {
        parse_ipv4_hex(parts[0])
    };

    (addr, port)
}

#[cfg(target_os = "linux")]
fn parse_ipv4_hex(hex: &str) -> String {
    if hex.len() != 8 {
        return "0.0.0.0".to_string();
    }

    // Linux stores IPv4 in little-endian hex
    let bytes: Vec<u8> = (0..4)
        .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect();

    if bytes.len() == 4 {
        format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
    } else {
        "0.0.0.0".to_string()
    }
}

#[cfg(target_os = "linux")]
fn parse_ipv6_hex(hex: &str) -> String {
    if hex.len() != 32 {
        return "::".to_string();
    }

    // Parse 16 bytes, handle endianness (Linux stores each 4-byte group in little-endian)
    let mut groups = Vec::new();
    for i in 0..4 {
        let offset = i * 8;
        let group = &hex[offset..offset + 8];
        // Each 4-byte group is stored little-endian
        let b0 = u8::from_str_radix(&group[0..2], 16).unwrap_or(0);
        let b1 = u8::from_str_radix(&group[2..4], 16).unwrap_or(0);
        let b2 = u8::from_str_radix(&group[4..6], 16).unwrap_or(0);
        let b3 = u8::from_str_radix(&group[6..8], 16).unwrap_or(0);
        groups.push(format!("{:02x}{:02x}", b3, b2));
        groups.push(format!("{:02x}{:02x}", b1, b0));
    }

    // Simple formatting (not compressed)
    groups.join(":")
}

#[cfg(target_os = "linux")]
fn tcp_state_from_hex(hex: &str) -> String {
    match u8::from_str_radix(hex, 16).unwrap_or(0) {
        0x01 => proto_str!("ESTABLISHED").to_string(),
        0x02 => proto_str!("SYN_SENT").to_string(),
        0x03 => proto_str!("SYN_RECV").to_string(),
        0x04 => proto_str!("FIN_WAIT1").to_string(),
        0x05 => proto_str!("FIN_WAIT2").to_string(),
        0x06 => proto_str!("TIME_WAIT").to_string(),
        0x07 => proto_str!("CLOSE").to_string(),
        0x08 => proto_str!("CLOSE_WAIT").to_string(),
        0x09 => proto_str!("LAST_ACK").to_string(),
        0x0A => proto_str!("LISTEN").to_string(),
        0x0B => proto_str!("CLOSING").to_string(),
        _ => proto_str!("UNKNOWN").to_string(),
    }
}

/// Stub for non-Linux/non-Windows platforms
#[cfg(not(any(windows, target_os = "linux")))]
pub fn list_connections() -> Vec<NetstatEntry> {
    Vec::new()
}

/// Get the hostname of the local machine (Windows)
#[cfg(windows)]
pub fn get_hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}

/// Get the hostname of the local machine (Linux)
#[cfg(target_os = "linux")]
pub fn get_hostname() -> String {
    // Try /etc/hostname first
    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        let hostname = hostname.trim().to_string();
        if !hostname.is_empty() {
            return hostname;
        }
    }
    // Fall back to HOSTNAME env var
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

/// Stub for non-Linux/non-Windows platforms
#[cfg(not(any(windows, target_os = "linux")))]
pub fn get_hostname() -> String {
    "unknown".to_string()
}
