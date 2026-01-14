//! WebSocket stream adapter for russh
//!
//! Provides an AsyncRead + AsyncWrite wrapper around a WebSocket connection,
//! allowing russh to operate over WebSocket transport.

use bytes::{Buf, BytesMut};
use futures_util::{SinkExt, StreamExt};
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tungstenite::Message;
use tracing::{trace, debug, warn};

/// A WebSocket stream adapter that implements AsyncRead + AsyncWrite
///
/// This allows russh to communicate over a WebSocket connection by:
/// - Converting writes to WebSocket binary messages
/// - Buffering incoming WebSocket binary messages for reading
pub struct WsStream<S> {
    inner: S,
    read_buffer: BytesMut,
    closed: bool,
}

impl<S> WsStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            read_buffer: BytesMut::with_capacity(8192),
            closed: false,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: StreamExt<Item = Result<Message, tungstenite::Error>> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have buffered data, return it first
        if !self.read_buffer.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer[..to_copy]);
            self.read_buffer.advance(to_copy);
            trace!(bytes = to_copy, remaining = self.read_buffer.len(), "read from buffer");
            return Poll::Ready(Ok(()));
        }

        if self.closed {
            return Poll::Ready(Ok(()));
        }

        // Try to receive more data from the WebSocket
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                match msg {
                    Message::Binary(data) => {
                        trace!(bytes = data.len(), "received binary ws message");
                        if data.is_empty() {
                            // Empty message, try again
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }

                        let to_copy = std::cmp::min(buf.remaining(), data.len());
                        buf.put_slice(&data[..to_copy]);

                        // Buffer any remaining data
                        if to_copy < data.len() {
                            self.read_buffer.extend_from_slice(&data[to_copy..]);
                        }

                        Poll::Ready(Ok(()))
                    }
                    Message::Close(frame) => {
                        debug!(?frame, "received close frame");
                        self.closed = true;
                        Poll::Ready(Ok(()))
                    }
                    Message::Ping(_data) => {
                        trace!("received ping, will pong on next write");
                        // Pong is handled by tungstenite automatically in most cases
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Message::Pong(_) => {
                        trace!("received pong");
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Message::Text(text) => {
                        // Ignore text messages, SSH is binary
                        warn!(len = text.len(), "ignoring text message");
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Message::Frame(_) => {
                        // Raw frames shouldn't appear here
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => {
                warn!(error = %e, "websocket error");
                Poll::Ready(Err(io::Error::new(ErrorKind::Other, e)))
            }
            Poll::Ready(None) => {
                debug!("websocket stream ended");
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: SinkExt<Message, Error = tungstenite::Error> + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "websocket closed",
            )));
        }

        // First, ensure the sink is ready
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::new(ErrorKind::Other, e)));
            }
            Poll::Pending => return Poll::Pending,
        }

        // Send the data as a binary message
        let msg = Message::Binary(buf.to_vec());
        trace!(bytes = buf.len(), "sending binary ws message");

        match Pin::new(&mut self.inner).start_send(msg) {
            Ok(()) => {
                // Also flush to ensure data is sent immediately
                match Pin::new(&mut self.inner).poll_flush(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(ErrorKind::Other, e))),
                    Poll::Pending => {
                        // Data is queued, flush will complete later
                        // Return success since the write itself succeeded
                        Poll::Ready(Ok(buf.len()))
                    }
                }
            }
            Err(e) => Poll::Ready(Err(io::Error::new(ErrorKind::Other, e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
