//! WebSocket client handling

use crate::log_trace;
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{client_async, WebSocketStream};

/// Upgrade a TLS connection to WebSocket
pub async fn connect<S>(
    stream: S,
    url: &str,
) -> Result<WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    log_trace!("Initiating WebSocket upgrade to {}", url);

    let (ws_stream, _response) = client_async(url, stream).await?;

    log_trace!(
        "WebSocket upgrade complete, status: {}",
        _response.status()
    );

    Ok(ws_stream)
}
