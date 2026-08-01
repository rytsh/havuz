//! Session relay.
//!
//! The obvious implementation — `tokio::io::copy_bidirectional` — is wrong for
//! a pooler, and wrong in a way that silently destroys the entire value
//! proposition.
//!
//! When a client disconnects it sends `Terminate` ('X'). A blind byte copy
//! forwards that to the backend, the backend closes, and the connection can
//! never be reused. Measured against a real PostgreSQL: 21 client sessions
//! produced 21 backend connections instead of one. The pool looked healthy the
//! whole time.
//!
//! So the client-to-backend direction has to know where messages begin. It does
//! not parse them — it only tracks boundaries and watches for a single tag,
//! copying everything else in whole chunks.

use std::collections::{HashMap, VecDeque};
use std::io;

use bytes::{Buf, Bytes, BytesMut};
use havuz_control::{KickSignal, TraceContext, TraceSpan, TraceStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::Message;
use crate::stream::MaybeTls;
use crate::trace::PgTraceSpan;

const BUF_SIZE: usize = 16 * 1024;

/// `Terminate`. The only message a pooler must swallow rather than forward.
const TAG_TERMINATE: u8 = b'X';

/// Header size: one tag byte plus a four byte length.
const HEADER_LEN: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayStats {
    pub to_client: u64,
    pub to_backend: u64,
    /// The client said goodbye properly, so the backend is at a clean message
    /// boundary and can be recycled.
    pub client_terminated: bool,
    /// The backend hung up. Whatever the reason, it cannot go back in the pool.
    pub backend_closed: bool,
    /// An operator ended this session. The relay stopped wherever it was, so
    /// the backend's framing position is unknown and it must not be recycled.
    pub kicked: bool,
}

/// Shovel bytes between a client and its backend until either side is done.
pub async fn session_relay(client: &mut MaybeTls, backend: &mut MaybeTls) -> io::Result<RelayStats> {
    session_relay_inner(client, backend, None, KickSignal::never()).await
}

pub async fn session_relay_traced(
    client: &mut MaybeTls,
    backend: &mut MaybeTls,
    traces: &std::sync::Arc<TraceStore>,
    context: &TraceContext,
    target: String,
    backend_pid: Option<u32>,
    kick: KickSignal,
) -> io::Result<RelayStats> {
    session_relay_inner(
        client,
        backend,
        Some(SessionTrace::new(traces.clone(), context.clone(), target, backend_pid)),
        kick,
    )
    .await
}

async fn session_relay_inner(
    client: &mut MaybeTls,
    backend: &mut MaybeTls,
    mut trace: Option<SessionTrace>,
    mut kick: KickSignal,
) -> io::Result<RelayStats> {
    // Split so the two directions can be driven concurrently without aliasing
    // the same stream.
    let (mut client_rx, mut client_tx) = tokio::io::split(&mut *client);
    let (mut backend_rx, mut backend_tx) = tokio::io::split(&mut *backend);

    let mut from_client = vec![0u8; BUF_SIZE];
    let mut from_backend = vec![0u8; BUF_SIZE];
    let mut scanner = FrameScanner::default();
    let mut stats = RelayStats::default();

    loop {
        tokio::select! {
            // Session mode has no statement boundaries to wait for: this is a
            // byte shovel, and the backend may be mid-response at any instant.
            // So a kick here cannot leave the connection reusable, and the
            // caller discards it. That is the price of ending a session that
            // owns its backend outright — one reconnect, not a poisoned pool.
            _ = kick.kicked() => {
                stats.kicked = true;
                break;
            }

            // `read` is cancel-safe, so losing this branch to the other one
            // cannot drop bytes. The writes happen inside the branch body,
            // where nothing can cancel them.
            result = client_rx.read(&mut from_client) => {
                let n = result?;
                if n == 0 {
                    // Client vanished without a Terminate. The backend is
                    // still fine, but it may be mid-transaction; the reset on
                    // release deals with that.
                    break;
                }

                match scanner.scan(&from_client[..n]) {
                    Some(offset) => {
                        // Forward everything before the goodbye, then stop.
                        if offset > 0 {
                            if let Some(trace) = trace.as_mut() {
                                trace.observe_client(&from_client[..offset]);
                            }
                            backend_tx.write_all(&from_client[..offset]).await?;
                            backend_tx.flush().await?;
                            stats.to_backend += offset as u64;
                        }
                        stats.client_terminated = true;
                        break;
                    }
                    None => {
                        if let Some(trace) = trace.as_mut() {
                            trace.observe_client(&from_client[..n]);
                        }
                        backend_tx.write_all(&from_client[..n]).await?;
                        backend_tx.flush().await?;
                        stats.to_backend += n as u64;
                    }
                }
            }

            result = backend_rx.read(&mut from_backend) => {
                let n = result?;
                if n == 0 {
                    stats.backend_closed = true;
                    break;
                }
                if let Some(trace) = trace.as_mut() {
                    trace.observe_backend(&from_backend[..n]);
                }
                client_tx.write_all(&from_backend[..n]).await?;
                client_tx.flush().await?;
                stats.to_client += n as u64;
            }
        }
    }

    Ok(stats)
}

struct SessionTrace {
    store: std::sync::Arc<TraceStore>,
    context: TraceContext,
    target: String,
    backend_pid: Option<u32>,
    client_frames: FrameObserver,
    backend_frames: FrameObserver,
    pending: VecDeque<TraceSpan>,
    statements: HashMap<String, String>,
    extended_open: bool,
}

impl SessionTrace {
    fn new(store: std::sync::Arc<TraceStore>, context: TraceContext, target: String, backend_pid: Option<u32>) -> Self {
        Self {
            store,
            context,
            target,
            backend_pid,
            client_frames: FrameObserver::default(),
            backend_frames: FrameObserver::default(),
            pending: VecDeque::new(),
            statements: HashMap::new(),
            extended_open: false,
        }
    }

    fn observe_client(&mut self, bytes: &[u8]) {
        for message in self.client_frames.feed(bytes) {
            match message.tag {
                b'Q' => {
                    if let Some(sql) = first_cstring(&message.body) {
                        self.start(sql);
                    }
                    self.extended_open = false;
                }
                b'P' => {
                    let mut parts = message.body.splitn(3, |byte| *byte == 0);
                    let name = parts.next().map(|value| String::from_utf8_lossy(value).into_owned());
                    let sql = parts.next().map(|value| String::from_utf8_lossy(value).into_owned());
                    if let (Some(name), Some(sql)) = (name, sql) {
                        if !name.is_empty() {
                            self.statements.insert(name, sql.clone());
                        }
                        if !self.extended_open {
                            self.start(sql);
                        }
                        self.extended_open = true;
                    }
                }
                b'B' if !self.extended_open => {
                    let mut parts = message.body.splitn(3, |byte| *byte == 0);
                    parts.next();
                    if let Some(name) = parts.next().map(|value| String::from_utf8_lossy(value)) {
                        if let Some(sql) = self.statements.get(name.as_ref()).cloned() {
                            self.start(sql);
                        }
                    }
                    self.extended_open = true;
                }
                b'S' => self.extended_open = false,
                _ => {}
            }
        }
    }

    fn observe_backend(&mut self, bytes: &[u8]) {
        for message in self.backend_frames.feed(bytes) {
            if let Some(span) = self.pending.front_mut() {
                span.observe(&message);
            }
            if message.tag == b'Z' {
                if let Some(span) = self.pending.pop_front() {
                    span.succeed();
                }
            }
        }
    }

    fn start(&mut self, sql: String) {
        let mut span = self.store.begin(&self.context, sql);
        span.assign(self.target.clone(), self.backend_pid);
        self.pending.push_back(span);
    }
}

#[derive(Default)]
struct FrameObserver {
    buffered: BytesMut,
}

impl FrameObserver {
    fn feed(&mut self, bytes: &[u8]) -> Vec<Message> {
        self.buffered.extend_from_slice(bytes);
        let mut messages = Vec::new();
        loop {
            if self.buffered.len() < HEADER_LEN {
                break;
            }
            let declared = i32::from_be_bytes([self.buffered[1], self.buffered[2], self.buffered[3], self.buffered[4]]);
            if !(4..=16 * 1024 * 1024).contains(&declared) {
                self.buffered.clear();
                break;
            }
            let frame_len = 1 + declared as usize;
            if self.buffered.len() < frame_len {
                break;
            }
            let mut frame = self.buffered.split_to(frame_len).freeze();
            let tag = frame.get_u8();
            frame.advance(4);
            messages.push(Message::new(tag, Bytes::copy_from_slice(&frame)));
        }
        messages
    }
}

fn first_cstring(body: &[u8]) -> Option<String> {
    let end = body.iter().position(|byte| *byte == 0).unwrap_or(body.len());
    Some(String::from_utf8_lossy(body.get(..end)?).into_owned())
}

/// Tracks message boundaries in the client-to-backend byte stream.
///
/// Deliberately not a parser: it reads five header bytes per message and skips
/// the body without looking at it, so a large `Bind` or `CopyData` costs one
/// arithmetic operation rather than a decode.
#[derive(Debug, Default)]
struct FrameScanner {
    /// Body bytes still to be skipped in the message being traversed.
    remaining: usize,
    /// Header bytes carried over when a chunk ended mid-header.
    partial: [u8; HEADER_LEN],
    partial_len: usize,
}

impl FrameScanner {
    /// Feed a chunk; return the offset at which a `Terminate` message starts.
    fn scan(&mut self, buf: &[u8]) -> Option<usize> {
        let mut pos = 0;

        while pos < buf.len() {
            if self.remaining > 0 {
                let skip = self.remaining.min(buf.len() - pos);
                self.remaining -= skip;
                pos += skip;
                continue;
            }

            // Complete a header that straddled the previous chunk.
            if self.partial_len > 0 {
                let want = HEADER_LEN - self.partial_len;
                let take = want.min(buf.len() - pos);
                self.partial[self.partial_len..self.partial_len + take].copy_from_slice(&buf[pos..pos + take]);
                self.partial_len += take;
                pos += take;

                if self.partial_len < HEADER_LEN {
                    return None;
                }
                let header = self.partial;
                self.partial_len = 0;
                if header[0] == TAG_TERMINATE {
                    // The tag arrived in an earlier chunk, so the message does
                    // not start inside this one. Nothing here belongs to the
                    // backend.
                    return Some(0);
                }
                self.remaining = body_len(&header);
                continue;
            }

            if buf[pos] == TAG_TERMINATE {
                return Some(pos);
            }

            if buf.len() - pos < HEADER_LEN {
                let take = buf.len() - pos;
                self.partial[..take].copy_from_slice(&buf[pos..]);
                self.partial_len = take;
                return None;
            }

            let header: [u8; HEADER_LEN] = buf[pos..pos + HEADER_LEN].try_into().expect("checked length");
            self.remaining = body_len(&header);
            pos += HEADER_LEN;
        }

        None
    }
}

fn body_len(header: &[u8; HEADER_LEN]) -> usize {
    // The declared length covers itself but not the tag. A malformed value
    // cannot make us skip backwards or overflow.
    let declared = i32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    declared.saturating_sub(4).max(0) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Message;
    use bytes::Bytes;
    use tokio::net::{TcpListener, TcpStream};

    fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
        Message::new(tag, Bytes::copy_from_slice(body)).encode().to_vec()
    }

    #[test]
    fn a_plain_query_stream_contains_no_terminate() {
        let mut scanner = FrameScanner::default();
        let mut stream = Vec::new();
        stream.extend_from_slice(&msg(b'Q', b"SELECT 1\0"));
        stream.extend_from_slice(&msg(b'Q', b"SELECT 2\0"));
        assert_eq!(scanner.scan(&stream), None);
    }

    #[test]
    fn terminate_is_found_at_its_offset() {
        let mut scanner = FrameScanner::default();
        let query = msg(b'Q', b"SELECT 1\0");
        let mut stream = query.clone();
        stream.extend_from_slice(&msg(TAG_TERMINATE, b""));

        assert_eq!(scanner.scan(&stream), Some(query.len()), "everything before the goodbye is still forwarded");
    }

    #[test]
    fn a_query_body_that_looks_like_terminate_is_not_mistaken_for_one() {
        // This is the bug a naive `buf.contains(&b'X')` would have. The body of
        // this query contains the byte 'X' several times.
        let mut scanner = FrameScanner::default();
        let stream = msg(b'Q', b"SELECT 'XXXX' FROM t WHERE c = 'X'\0");
        assert_eq!(scanner.scan(&stream), None, "message bodies must never be interpreted");
    }

    #[test]
    fn a_length_prefix_containing_the_terminate_byte_is_handled() {
        // The declared length covers itself, so an 84-byte body makes the
        // length field read 88, which is the byte 'X'.
        let mut scanner = FrameScanner::default();
        let stream = msg(b'd', &[0u8; 84]);
        assert_eq!(stream[4], TAG_TERMINATE, "precondition: length byte really is 'X'");
        assert_eq!(scanner.scan(&stream), None);
    }

    #[test]
    fn messages_split_across_chunks_are_tracked() {
        let mut scanner = FrameScanner::default();
        let mut stream = msg(b'Q', b"SELECT 1\0");
        stream.extend_from_slice(&msg(TAG_TERMINATE, b""));

        // Feed one byte at a time; the boundary tracking must survive.
        let mut found = None;
        for (i, byte) in stream.iter().enumerate() {
            if let Some(offset) = scanner.scan(&[*byte]) {
                found = Some(i + offset);
                break;
            }
        }
        assert_eq!(found, Some(stream.len() - 5), "Terminate must be found even byte by byte");
    }

    #[test]
    fn a_header_split_across_chunks_is_reassembled() {
        let mut scanner = FrameScanner::default();
        let stream = msg(b'Q', b"SELECT 1\0");

        // Cut in the middle of the five byte header.
        assert_eq!(scanner.scan(&stream[..3]), None);
        assert_eq!(scanner.scan(&stream[3..]), None);

        // The scanner must now be back at a boundary and still spot a goodbye.
        assert_eq!(scanner.scan(&msg(TAG_TERMINATE, b"")), Some(0));
    }

    #[test]
    fn a_terminate_whose_tag_arrived_in_a_previous_chunk_is_still_caught() {
        let mut scanner = FrameScanner::default();
        let stream = msg(b'Q', b"SELECT 1\0");
        scanner.scan(&stream);

        let terminate = msg(TAG_TERMINATE, b"");
        // Tag alone, then the rest of the header.
        assert_eq!(scanner.scan(&terminate[..1]), Some(0), "the tag is recognised immediately");
    }

    #[test]
    fn a_bogus_length_cannot_make_the_scanner_run_backwards() {
        let mut scanner = FrameScanner::default();
        // Declared length of 0, which is below the four byte minimum.
        let stream = [b'Q', 0, 0, 0, 0, b'X', 0, 0, 0, 4];
        // The malformed message consumes no body, so the following 'X' is seen.
        assert_eq!(scanner.scan(&stream), Some(5));
    }

    #[test]
    fn a_huge_declared_length_just_skips_the_rest_of_the_chunk() {
        let mut scanner = FrameScanner::default();
        let mut stream = vec![b'd'];
        stream.extend_from_slice(&i32::MAX.to_be_bytes());
        stream.extend_from_slice(&[0u8; 100]);

        assert_eq!(scanner.scan(&stream), None);
        assert!(scanner.remaining > 0, "the oversized body is skipped, not decoded");
    }

    #[test]
    fn an_empty_chunk_changes_nothing() {
        let mut scanner = FrameScanner::default();
        assert_eq!(scanner.scan(&[]), None);
    }

    /// End-to-end: a fake client and a fake backend joined by the relay.
    #[tokio::test]
    async fn the_relay_swallows_terminate_and_leaves_the_backend_alive() {
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();

        // The backend records what it received and stays open afterwards.
        let backend = tokio::spawn(async move {
            let (mut socket, _) = backend_listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match socket.read(&mut buf).await.unwrap() {
                    0 => break,
                    n => {
                        seen.extend_from_slice(&buf[..n]);
                        socket.write_all(&msg(b'Z', b"I")).await.unwrap();
                    }
                }
            }
            seen
        });

        let relay = tokio::spawn(async move {
            let (client_socket, _) = client_listener.accept().await.unwrap();
            let backend_socket = TcpStream::connect(backend_addr).await.unwrap();
            let mut client = MaybeTls::Plain(client_socket);
            let mut backend = MaybeTls::Plain(backend_socket);
            session_relay(&mut client, &mut backend).await.unwrap()
        });

        let mut client = TcpStream::connect(client_addr).await.unwrap();
        client.write_all(&msg(b'Q', b"SELECT 1\0")).await.unwrap();
        let mut reply = [0u8; 6];
        client.read_exact(&mut reply).await.unwrap();
        client.write_all(&msg(TAG_TERMINATE, b"")).await.unwrap();
        drop(client);

        let stats = relay.await.unwrap();
        assert!(stats.client_terminated, "the goodbye must be recognised");
        assert!(!stats.backend_closed, "the backend must survive the client leaving");
        assert_eq!(stats.to_backend, msg(b'Q', b"SELECT 1\0").len() as u64);

        let seen = tokio::time::timeout(std::time::Duration::from_secs(2), backend).await.unwrap().unwrap();
        assert_eq!(seen, msg(b'Q', b"SELECT 1\0"), "Terminate must never reach the backend");
    }

    #[tokio::test]
    async fn a_backend_that_hangs_up_is_reported() {
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = backend_listener.accept().await.unwrap();
            drop(socket);
        });

        let relay = tokio::spawn(async move {
            let (client_socket, _) = client_listener.accept().await.unwrap();
            let backend_socket = TcpStream::connect(backend_addr).await.unwrap();
            let mut client = MaybeTls::Plain(client_socket);
            let mut backend = MaybeTls::Plain(backend_socket);
            session_relay(&mut client, &mut backend).await.unwrap()
        });

        let _client = TcpStream::connect(client_addr).await.unwrap();
        let stats = relay.await.unwrap();
        assert!(stats.backend_closed, "a dead backend must be flagged so it is discarded");
    }
}
