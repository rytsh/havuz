//! A socket that may or may not have been upgraded to TLS.
//!
//! Postgres negotiates TLS in-band: the client sends an `SSLRequest`, the
//! server answers with a single byte, and only then does the handshake begin.
//! That means the concrete stream type is not known until runtime, on both the
//! client and the backend side.
//!
//! An enum is used rather than `Box<dyn AsyncRead + AsyncWrite>` because this
//! sits directly on the data path: every relayed byte goes through these `poll_`
//! methods, and a static dispatch that the optimiser can see through is worth
//! more here than the flexibility of a trait object.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream};

pub enum MaybeTls {
    Plain(TcpStream),
    /// havuz acting as a TLS client, i.e. a backend connection.
    ClientTls(Box<ClientTlsStream<TcpStream>>),
    /// havuz acting as a TLS server, i.e. a client connection.
    ServerTls(Box<ServerTlsStream<TcpStream>>),
}

impl MaybeTls {
    pub fn is_encrypted(&self) -> bool {
        !matches!(self, MaybeTls::Plain(_))
    }

    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self {
            MaybeTls::Plain(s) => s.peer_addr(),
            MaybeTls::ClientTls(s) => s.get_ref().0.peer_addr(),
            MaybeTls::ServerTls(s) => s.get_ref().0.peer_addr(),
        }
    }

    /// Disable Nagle's algorithm.
    ///
    /// A pooler relays small request/response messages; waiting to coalesce
    /// them adds up to 40 ms of latency for no benefit.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            MaybeTls::Plain(s) => s.set_nodelay(nodelay),
            MaybeTls::ClientTls(s) => s.get_ref().0.set_nodelay(nodelay),
            MaybeTls::ServerTls(s) => s.get_ref().0.set_nodelay(nodelay),
        }
    }
}

impl std::fmt::Debug for MaybeTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            MaybeTls::Plain(_) => "plain",
            MaybeTls::ClientTls(_) => "client-tls",
            MaybeTls::ServerTls(_) => "server-tls",
        };
        f.debug_struct("MaybeTls").field("kind", &kind).finish()
    }
}

macro_rules! delegate {
    ($self:ident, $inner:ident => $body:expr) => {
        match &mut *$self {
            MaybeTls::Plain($inner) => $body,
            MaybeTls::ClientTls($inner) => $body,
            MaybeTls::ServerTls($inner) => $body,
        }
    };
}

impl AsyncRead for MaybeTls {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        delegate!(self, s => Pin::new(s).poll_read(cx, buf))
    }
}

impl AsyncWrite for MaybeTls {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        delegate!(self, s => Pin::new(s).poll_write(cx, buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, s => Pin::new(s).poll_flush(cx))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, s => Pin::new(s).poll_shutdown(cx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn plain_streams_read_and_write_transparently() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(b"world").await.unwrap();
            buf
        });

        let mut stream = MaybeTls::Plain(TcpStream::connect(addr).await.unwrap());
        assert!(!stream.is_encrypted());
        stream.set_nodelay(true).unwrap();

        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf, b"world");
        assert_eq!(&server.await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn peer_addr_is_available_before_any_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let stream = MaybeTls::Plain(TcpStream::connect(addr).await.unwrap());
        assert_eq!(stream.peer_addr().unwrap(), addr);
        drop(accept.await.unwrap());
    }
}
