//! SOCKS5 protocol implementation (RFC 1928)

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 version
const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication methods
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

/// SOCKS5 commands
const CMD_CONNECT: u8 = 0x01;

/// SOCKS5 address types
const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x03;
const ADDR_IPV6: u8 = 0x04;

/// SOCKS5 reply codes (RFC 1928)
const REPLY_SUCCESS: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Connection error types mapped to RFC 1928 reply codes
#[derive(Debug, Clone, Copy)]
pub enum ConnectError {
    GeneralFailure,      // 0x01
    NetworkUnreachable,  // 0x03
    HostUnreachable,     // 0x04
    ConnectionRefused,   // 0x05 - port closed
    Timeout,             // mapped to 0x04
}

#[derive(Debug, Error)]
pub enum Socks5Error {
    #[error("Invalid SOCKS version: {0}")]
    InvalidVersion(u8),
    #[error("No acceptable authentication method")]
    NoAcceptableAuth,
    #[error("Unsupported command: {0}")]
    UnsupportedCommand(u8),
    #[error("Unsupported address type: {0}")]
    UnsupportedAddressType(u8),
    #[error("Invalid domain name")]
    InvalidDomain,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result of SOCKS5 handshake - the requested destination
#[derive(Debug, Clone)]
pub struct Socks5Request {
    pub dest_host: String,
    pub dest_port: u16,
}

/// Perform SOCKS5 handshake and return the requested destination
pub async fn handshake<S>(stream: &mut S) -> Result<Socks5Request, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: Read client greeting
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    let version = header[0];
    if version != SOCKS5_VERSION {
        return Err(Socks5Error::InvalidVersion(version));
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // Check if no-auth (0x00) is supported
    let method = if methods.contains(&AUTH_NO_AUTH) {
        AUTH_NO_AUTH
    } else {
        // Send "no acceptable methods" and fail
        stream.write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]).await?;
        return Err(Socks5Error::NoAcceptableAuth);
    };

    // Step 2: Send server choice
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    stream.write_all(&[SOCKS5_VERSION, method]).await?;

    // Step 3: Read client request
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    let mut request_header = [0u8; 4];
    stream.read_exact(&mut request_header).await?;

    let version = request_header[0];
    if version != SOCKS5_VERSION {
        return Err(Socks5Error::InvalidVersion(version));
    }

    let cmd = request_header[1];
    if cmd != CMD_CONNECT {
        send_reply(stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(Socks5Error::UnsupportedCommand(cmd));
    }

    let addr_type = request_header[3];

    // Parse destination address based on type
    let dest_host = match addr_type {
        ADDR_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        ADDR_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let len = len[0] as usize;

            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;

            String::from_utf8(domain).map_err(|_| Socks5Error::InvalidDomain)?
        }
        ADDR_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        _ => {
            send_reply(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(Socks5Error::UnsupportedAddressType(addr_type));
        }
    };

    // Read destination port
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let dest_port = u16::from_be_bytes(port_bytes);

    Ok(Socks5Request {
        dest_host,
        dest_port,
    })
}

/// Send SOCKS5 success reply
pub async fn send_success<S>(stream: &mut S, bind_addr: SocketAddr) -> Result<(), Socks5Error>
where
    S: AsyncWrite + Unpin,
{
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    let mut reply = vec![SOCKS5_VERSION, REPLY_SUCCESS, 0x00];

    match bind_addr {
        SocketAddr::V4(addr) => {
            reply.push(ADDR_IPV4);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            reply.push(ADDR_IPV6);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    stream.write_all(&reply).await?;
    Ok(())
}

/// Send SOCKS5 error reply based on connection error type
pub async fn send_error<S>(stream: &mut S, error: ConnectError) -> Result<(), Socks5Error>
where
    S: AsyncWrite + Unpin,
{
    let reply_code = match error {
        ConnectError::ConnectionRefused => REPLY_CONNECTION_REFUSED,
        ConnectError::Timeout | ConnectError::HostUnreachable => REPLY_HOST_UNREACHABLE,
        ConnectError::NetworkUnreachable => REPLY_NETWORK_UNREACHABLE,
        ConnectError::GeneralFailure => REPLY_GENERAL_FAILURE,
    };
    send_reply(stream, reply_code).await
}

/// Send a SOCKS5 reply with the given code
async fn send_reply<S>(stream: &mut S, reply_code: u8) -> Result<(), Socks5Error>
where
    S: AsyncWrite + Unpin,
{
    // Reply with 0.0.0.0:0 as bind address for errors
    let reply = [
        SOCKS5_VERSION,
        reply_code,
        0x00,        // RSV
        ADDR_IPV4,   // ATYP
        0, 0, 0, 0,  // BND.ADDR (0.0.0.0)
        0, 0,        // BND.PORT (0)
    ];
    stream.write_all(&reply).await?;
    Ok(())
}
