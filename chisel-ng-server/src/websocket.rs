//! WebSocket handling for the server

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{accept_async, WebSocketStream};
use tracing::trace;

/// Accept a WebSocket connection from a TLS stream
pub async fn accept<S>(stream: S) -> Result<WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    trace!("Accepting WebSocket upgrade");

    let ws_stream = accept_async(stream).await?;

    trace!("WebSocket connection established");
    Ok(ws_stream)
}
