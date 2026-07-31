//! Transaction-mode relay.
//!
//! This is where a pool of three backends actually serves a hundred clients.
//! The rule is simple to state and easy to get subtly wrong: hold a backend
//! only from the moment a client asks for work until the server reports
//! `ReadyForQuery` with no transaction open.
//!
//! Three decisions carry most of the weight.
//!
//! **Transaction state comes from the wire, not from SQL.** `ReadyForQuery`
//! carries a status byte — `I`, `T` or `E` — that PostgreSQL computes itself.
//! Inferring transaction boundaries by looking for `BEGIN` and `COMMIT` means
//! reimplementing the server's own rules about implicit transactions, aborted
//! blocks and savepoints, and being wrong occasionally. We read the byte.
//!
//! **No reset between transactions.** Recycling with `DISCARD ALL` after every
//! transaction would add a round trip to every single one and undo most of the
//! benefit. It is unnecessary because anything that dirties a connection —
//! `SET`, `LISTEN`, temp tables, advisory locks — is classified as a pin, and a
//! pinned connection is never shared. The reset happens once, when the client
//! finally goes away.
//!
//! **A backend is only borrowed when there is work.** An idle client holds
//! nothing. That is the entire source of the fan-in.

use havuz_pool::Checkout;
use havuz_proto::{BackendConn, FlowEvent, PinReason, ProtoError, ProtoResult, SessionState};
use tokio::io::AsyncWriteExt;

use crate::backend::PgConnector;
use crate::classify::{classify, route_intent, ClientIntent, RouteIntent};
use crate::group::PoolGroup;
use crate::prepared::{ClientStatements, Rewrite};
use crate::protocol::{sqlstate, Message, TransactionStatus};
use crate::relay::RelayStats;
use crate::routing::{PrimaryReason, Route, SessionRouting};
use crate::stream::MaybeTls;
use crate::trace::{TraceContext, TraceSpan, TraceStore};

/// Outcome of a transaction-mode session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnOutcome {
    pub stats: RelayStats,
    /// Transactions (or standalone statements) relayed.
    pub exchanges: u64,
    /// Why this session stopped being shareable, if it did.
    pub pinned: Option<PinReason>,
    /// Distinct times a backend was borrowed. With a well-behaved client this
    /// equals `exchanges`; with a pinned one it is 1.
    pub checkouts: u64,
    /// Exchanges a replica handled.
    pub to_replica: u64,
}

/// Relay a client session in transaction mode.
pub async fn transaction_relay(
    client: &mut MaybeTls,
    group: &PoolGroup,
    state: &mut SessionState,
) -> ProtoResult<TxnOutcome> {
    transaction_relay_inner(client, group, state, None).await
}

pub async fn transaction_relay_traced(
    client: &mut MaybeTls,
    group: &PoolGroup,
    state: &mut SessionState,
    traces: &std::sync::Arc<TraceStore>,
    context: &TraceContext,
) -> ProtoResult<TxnOutcome> {
    transaction_relay_inner(client, group, state, Some((traces, context))).await
}

async fn transaction_relay_inner(
    client: &mut MaybeTls,
    group: &PoolGroup,
    state: &mut SessionState,
    tracing: Option<(&std::sync::Arc<TraceStore>, &TraceContext)>,
) -> ProtoResult<TxnOutcome> {
    let mut held: Option<Checkout<PgConnector>> = None;
    let mut stats = RelayStats::default();
    let mut exchanges = 0u64;
    let mut checkouts = 0u64;
    let mut to_replica = 0u64;
    let mut statements = ClientStatements::new();
    let mut routing = SessionRouting::new();
    let mut current_route = Route::Primary(PrimaryReason::SplitDisabled);
    // Original client messages forwarded since the last sync point.
    //
    // Kept so a replica that dies mid-exchange can be retried on the primary.
    // We buffer the *client's* messages rather than the rewritten ones, because
    // the retry has to re-derive prepared statement state against whichever
    // backend it lands on.
    let mut exchange: Vec<Message> = Vec::new();
    let mut trace_span: Option<TraceSpan> = None;

    loop {
        // Read one client message. While this is pending we hold no backend
        // unless a transaction is open or the session is pinned.
        let msg = match Message::read(client).await {
            Ok(msg) => msg,
            Err(_) => break,
        };

        let intent = classify(&msg);

        if intent == ClientIntent::Terminate {
            stats.client_terminated = true;
            break;
        }

        if let ClientIntent::Pins(reason) = intent {
            state.observe(FlowEvent::MustPin(reason));
        }

        if trace_span.is_none() {
            if let (Some(sql), Some((traces, context))) = (trace_sql(&msg, &statements), tracing) {
                let mut span = traces.begin(context, sql);
                if let Some(checkout) = held.as_ref() {
                    span.assign(group.target_label(current_route), checkout.backend_pid());
                }
                trace_span = Some(span);
            }
        }

        exchange.push(msg.clone());

        // Borrow a backend if we do not already have one.
        if held.is_none() {
            // The route is decided once per checkout, from the first message
            // that carries SQL. Deciding per message would let a transaction
            // span two servers and see two different snapshots.
            let intent = message_intent(&msg, &statements);
            current_route = group.router().choose(intent, &mut routing);

            let mut acquired = group.pool_for(current_route).acquire().await;

            // A replica that cannot be reached must not fail the client. The
            // primary can always serve the statement, and the breaker will take
            // the replica out of rotation after a few of these. Failing here
            // instead would turn one sick replica into a full outage.
            if acquired.is_err() {
                if let Route::Replica(_) = current_route {
                    tracing::debug!(
                        pool = %group.name(),
                        "replica unavailable, falling back to the primary"
                    );
                    group.router().record_result(current_route, false);
                    current_route = Route::Primary(PrimaryReason::NoReplicaAvailable);
                    acquired = group.primary().acquire().await;
                }
            }

            match acquired {
                Ok(checkout) => {
                    checkouts += 1;
                    if matches!(current_route, Route::Replica(_)) {
                        to_replica += 1;
                    }
                    if let Some(span) = trace_span.as_mut() {
                        span.assign(group.target_label(current_route), checkout.backend_pid());
                    }
                    held = Some(checkout);
                }
                Err(e) => {
                    group.router().record_result(current_route, false);
                    let code = match &e {
                        havuz_pool::PoolError::Timeout { .. } => sqlstate::TOO_MANY_CONNECTIONS,
                        _ => sqlstate::CANNOT_CONNECT_NOW,
                    };
                    if let Some(span) = trace_span.take() {
                        span.fail(code, e.to_string());
                    }
                    let _ = Message::fatal(code, &e.to_string()).write(client).await;
                    return Err(ProtoError::backend(e.to_string()));
                }
            }
        }

        let checkout = held.as_mut().expect("just acquired");

        // Prepared statements are the reason transaction mode is usually
        // unusable with real drivers: a Bind can land on a backend that never
        // saw the Parse. Rewrite names to a global form and replay the Parse
        // wherever it is missing.
        let outgoing = match rewrite_prepared(&msg, &mut statements, checkout) {
            Ok(Rewrite::Unchanged) => msg.clone(),
            Ok(Rewrite::Replace(rewritten)) => rewritten,

            Ok(Rewrite::Parse { global_name, message }) => {
                // PostgreSQL rejects a second Parse under a name it already
                // holds, and two clients running the same SQL derive the same
                // global name. Free the old one first so the client's Parse
                // still gets exactly one ParseComplete, in the right order.
                if checkout.statements().has(&global_name) {
                    if let Err(e) = close_statement(checkout, &global_name).await {
                        checkout.discard();
                        return Err(e);
                    }
                    checkout.statements_mut().remove(&global_name);
                }
                if let Some(evicted) = checkout.statements_mut().insert(&global_name) {
                    let _ = close_statement(checkout, &evicted).await;
                }
                message
            }

            Ok(Rewrite::CloseStatement { global_name, client_name, message }) => {
                checkout.statements_mut().remove(&global_name);
                statements.forget(&client_name);
                message
            }

            Ok(Rewrite::ReplayThen { parse, global_name, message }) => {
                if let Err(e) = replay_parse(checkout, &parse, &global_name).await {
                    checkout.discard();
                    let _ = Message::fatal(sqlstate::PROTOCOL_VIOLATION, &e.to_string()).write(client).await;
                    return Err(e);
                }
                message
            }
            Err(e) => {
                // The client referenced a statement we never saw. Answering
                // with an error is the only safe option: forwarding the name
                // unchanged could bind it to another client's statement.
                let _ =
                    Message::error_response("ERROR", sqlstate::PROTOCOL_VIOLATION, &e.to_string()).write(client).await;
                let _ = Message::ready_for_query(TransactionStatus::Failed).write(client).await;
                if let Some(span) = trace_span.take() {
                    span.fail(sqlstate::PROTOCOL_VIOLATION, e.to_string());
                }
                continue;
            }
        };

        // Forward the client message.
        if let Err(e) = checkout.stream_mut().write_all(&outgoing.encode()).await {
            checkout.discard();
            held = None;
            group.router().record_result(current_route, false);

            // A write that never left our side of a dead replica connection is
            // safe to retry; the next iteration re-acquires and the buffered
            // exchange is replayed.
            if matches!(current_route, Route::Replica(_)) {
                tracing::debug!(pool = %group.name(), error = %e, "replica write failed, retrying");
                continue;
            }
            let _ = Message::fatal(sqlstate::CANNOT_CONNECT_NOW, "backend connection lost").write(client).await;
            return Err(ProtoError::backend(format!("forwarding to backend: {e}")));
        }
        stats.to_backend += outgoing.wire_len() as u64;

        // Only a sync point produces a ReadyForQuery. Pipelined messages are
        // buffered and answered together, so flushing early would just add
        // syscalls.
        let expects_reply =
            matches!(intent, ClientIntent::SyncPoint) || matches!(intent, ClientIntent::Pins(_)) && msg.tag == b'Q';

        if !expects_reply {
            continue;
        }

        if let Err(e) = checkout.stream_mut().flush().await {
            checkout.discard();
            return Err(ProtoError::backend(format!("flushing to backend: {e}")));
        }

        // Pump the answer through until the server says it is ready again.
        let client_bytes_before = stats.to_client;
        match pump_until_ready(client, checkout, &mut stats, trace_span.as_mut()).await {
            Ok(status) => {
                exchanges += 1;
                group.router().record_result(current_route, true);
                match status {
                    TransactionStatus::Idle => {
                        state.observe(FlowEvent::Idle);
                        routing.end_transaction();
                    }
                    _ => {
                        state.observe(FlowEvent::InTransaction);
                        // Pin the rest of the transaction to this target.
                        routing.begin_transaction(current_route);
                    }
                }
                if let Some(span) = trace_span.take() {
                    span.succeed();
                }
            }
            Err(e) => {
                group.router().record_result(current_route, false);
                checkout.discard();
                // The dead checkout is dropped here; every path below either
                // installs a replacement or returns.
                held = None;
                let _ = &held;

                // A replica that died is not the client's problem. Nothing has
                // been written back yet, so the exchange can be replayed on the
                // primary and the client never learns anything happened.
                //
                // The guard on `to_client` is essential: once part of a
                // response has gone out, replaying would duplicate it.
                let retryable = matches!(current_route, Route::Replica(_)) && stats.to_client == client_bytes_before;

                if retryable {
                    tracing::debug!(
                        pool = %group.name(),
                        error = %e,
                        "replica failed mid-exchange, replaying on the primary"
                    );
                    current_route = Route::Primary(PrimaryReason::NoReplicaAvailable);

                    let mut checkout = match group.primary().acquire().await {
                        Ok(checkout) => checkout,
                        Err(e) => {
                            let _ = Message::fatal(sqlstate::CANNOT_CONNECT_NOW, &e.to_string()).write(client).await;
                            return Err(ProtoError::backend(e.to_string()));
                        }
                    };
                    checkouts += 1;
                    if let Some(span) = trace_span.as_mut() {
                        span.assign(group.target_label(current_route), checkout.backend_pid());
                    }

                    for buffered in &exchange {
                        let outgoing = match rewrite_prepared(buffered, &mut statements, &checkout) {
                            Ok(Rewrite::Unchanged) => buffered.clone(),
                            Ok(Rewrite::Replace(m)) => m,
                            Ok(Rewrite::Parse { global_name, message }) => {
                                if checkout.statements().has(&global_name) {
                                    close_statement(&mut checkout, &global_name).await?;
                                    checkout.statements_mut().remove(&global_name);
                                }
                                checkout.statements_mut().insert(&global_name);
                                message
                            }
                            Ok(Rewrite::CloseStatement { global_name, client_name, message }) => {
                                checkout.statements_mut().remove(&global_name);
                                statements.forget(&client_name);
                                message
                            }
                            Ok(Rewrite::ReplayThen { parse, global_name, message }) => {
                                replay_parse(&mut checkout, &parse, &global_name).await?;
                                message
                            }
                            Err(e) => return Err(e),
                        };
                        checkout
                            .stream_mut()
                            .write_all(&outgoing.encode())
                            .await
                            .map_err(|e| ProtoError::backend(format!("replaying exchange: {e}")))?;
                    }
                    checkout
                        .stream_mut()
                        .flush()
                        .await
                        .map_err(|e| ProtoError::backend(format!("replaying exchange: {e}")))?;

                    match pump_until_ready(client, &mut checkout, &mut stats, trace_span.as_mut()).await {
                        Ok(status) => {
                            exchanges += 1;
                            group.router().record_result(current_route, true);
                            match status {
                                TransactionStatus::Idle => {
                                    state.observe(FlowEvent::Idle);
                                    routing.end_transaction();
                                }
                                _ => {
                                    state.observe(FlowEvent::InTransaction);
                                    routing.begin_transaction(current_route);
                                }
                            }
                            if let Some(span) = trace_span.take() {
                                span.succeed();
                            }
                            exchange.clear();
                            held = Some(checkout);
                            if state.is_releasable() {
                                state.released();
                                held = None;
                            }
                            continue;
                        }
                        Err(e) => {
                            checkout.discard();
                            stats.backend_closed = true;
                            let _ = Message::fatal(sqlstate::CANNOT_CONNECT_NOW, "backend connection lost")
                                .write(client)
                                .await;
                            return Err(e);
                        }
                    }
                }

                stats.backend_closed = true;
                let _ = Message::fatal(sqlstate::CANNOT_CONNECT_NOW, "backend connection lost").write(client).await;
                return Err(e);
            }
        }

        exchange.clear();

        // The moment that makes the whole thing worthwhile.
        if state.is_releasable() {
            state.released();
            held = None;
        }
    }

    // Return the backend, cleaning it only if it was pinned. An unpinned
    // connection is clean by construction.
    if let Some(mut checkout) = held.take() {
        if state.pin().is_some() || state.in_transaction() {
            use havuz_proto::{BackendConn, ResetOutcome};
            if matches!(checkout.reset().await, Ok(ResetOutcome::Discard) | Err(_)) {
                checkout.discard();
            }
        }
    }

    Ok(TxnOutcome { stats, exchanges, pinned: state.pin(), checkouts, to_replica })
}

/// Where the statement carried by this message may run.
///
/// A message with no SQL tells us nothing, and "nothing" must mean the primary:
/// a `Bind` to a statement we have somehow lost track of could be anything.
fn message_intent(msg: &Message, statements: &ClientStatements) -> RouteIntent {
    match msg.tag {
        b'Q' => {
            let end = msg.body.iter().position(|b| *b == 0).unwrap_or(msg.body.len());
            route_intent(&String::from_utf8_lossy(&msg.body[..end]))
        }
        b'P' => {
            let mut parts = msg.body.splitn(3, |b| *b == 0);
            match (parts.next(), parts.next()) {
                (Some(_name), Some(sql)) => route_intent(&String::from_utf8_lossy(sql)),
                _ => RouteIntent::Write,
            }
        }
        // A Bind names a statement we already parsed, so its text is known.
        b'B' => {
            let mut parts = msg.body.splitn(3, |b| *b == 0);
            let _portal = parts.next();
            match parts.next() {
                Some(name) => {
                    let name = String::from_utf8_lossy(name);
                    statements.get(&name).map(|s| route_intent(&s.sql)).unwrap_or(RouteIntent::Write)
                }
                None => RouteIntent::Write,
            }
        }
        _ => RouteIntent::Write,
    }
}

fn trace_sql(msg: &Message, statements: &ClientStatements) -> Option<String> {
    match msg.tag {
        b'Q' => {
            let end = msg.body.iter().position(|byte| *byte == 0).unwrap_or(msg.body.len());
            Some(String::from_utf8_lossy(&msg.body[..end]).into_owned())
        }
        b'P' => {
            let mut parts = msg.body.splitn(3, |byte| *byte == 0);
            parts.next()?;
            Some(String::from_utf8_lossy(parts.next()?).into_owned())
        }
        b'B' => {
            let mut parts = msg.body.splitn(3, |byte| *byte == 0);
            parts.next()?;
            let statement = String::from_utf8_lossy(parts.next()?);
            statements.get(&statement).map(|prepared| prepared.sql.clone())
        }
        _ => None,
    }
}

/// Apply prepared-statement rewriting to a client message.
fn rewrite_prepared(
    msg: &Message,
    statements: &mut ClientStatements,
    checkout: &Checkout<PgConnector>,
) -> Result<Rewrite, ProtoError> {
    let result = match msg.tag {
        b'P' => statements.on_parse(msg),
        b'B' => statements.on_bind(msg, checkout.statements()),
        b'D' | b'C' => statements.on_describe_or_close(msg, checkout.statements()),
        _ => return Ok(Rewrite::Unchanged),
    };
    result.map_err(|e| ProtoError::protocol(e.to_string()))
}

/// Teach a backend a statement it has not seen.
///
/// `Flush` rather than `Sync` on purpose: `Sync` would produce a
/// `ReadyForQuery` that the client is not expecting and would close an implicit
/// transaction the client may have open. `Flush` just makes the server answer.
async fn replay_parse(
    checkout: &mut Checkout<PgConnector>,
    parse: &bytes::Bytes,
    global_name: &str,
) -> ProtoResult<()> {
    let stream = checkout.stream_mut();
    stream
        .write_all(&Message::new(b'P', parse.clone()).encode())
        .await
        .map_err(|e| ProtoError::backend(format!("replaying Parse: {e}")))?;
    stream
        .write_all(&Message::new(b'H', bytes::Bytes::new()).encode())
        .await
        .map_err(|e| ProtoError::backend(format!("flushing Parse: {e}")))?;
    stream.flush().await.map_err(|e| ProtoError::backend(format!("flushing Parse: {e}")))?;

    // The reply is consumed here rather than forwarded: the client never asked
    // for this Parse and would be confused by the extra ParseComplete.
    loop {
        let reply = Message::read(checkout.stream_mut())
            .await
            .map_err(|e| ProtoError::backend(format!("reading Parse reply: {e}")))?;
        match reply.tag {
            // ParseComplete.
            b'1' => break,
            b'E' => {
                let detail = reply
                    .error_fields()
                    .into_iter()
                    .find(|(f, _)| *f == b'M')
                    .map(|(_, v)| v)
                    .unwrap_or_else(|| "prepare failed".into());
                return Err(ProtoError::protocol(format!("backend rejected replayed statement: {detail}")));
            }
            // NoticeResponse and ParameterStatus can arrive at any time.
            _ => continue,
        }
    }

    if let Some(evicted) = checkout.statements_mut().insert(global_name) {
        // The cache is full. Free the server-side plan we just displaced,
        // otherwise the backend accumulates statements forever.
        close_statement(checkout, &evicted).await?;
    }

    Ok(())
}

/// Deallocate a statement on the backend, out of band from the client's stream.
///
/// `Close` on a name the server does not hold succeeds silently, so this is
/// safe to call speculatively.
async fn close_statement(checkout: &mut Checkout<PgConnector>, global_name: &str) -> ProtoResult<()> {
    let mut body = bytes::BytesMut::new();
    bytes::BufMut::put_u8(&mut body, b'S');
    bytes::BufMut::put_slice(&mut body, global_name.as_bytes());
    bytes::BufMut::put_u8(&mut body, 0);

    let stream = checkout.stream_mut();
    stream
        .write_all(&Message::new(b'C', body.freeze()).encode())
        .await
        .map_err(|e| ProtoError::backend(format!("closing statement: {e}")))?;
    stream
        .write_all(&Message::new(b'H', bytes::Bytes::new()).encode())
        .await
        .map_err(|e| ProtoError::backend(format!("closing statement: {e}")))?;
    stream.flush().await.map_err(|e| ProtoError::backend(format!("closing statement: {e}")))?;

    // The client did not ask for this, so its reply must not reach them.
    loop {
        match Message::read(checkout.stream_mut()).await {
            // CloseComplete, or an error we can safely ignore.
            Ok(m) if m.tag == b'3' || m.tag == b'E' => return Ok(()),
            Ok(_) => continue,
            Err(e) => return Err(ProtoError::backend(format!("closing statement: {e}"))),
        }
    }
}

/// Copy backend output to the client until `ReadyForQuery`.
async fn pump_until_ready(
    client: &mut MaybeTls,
    checkout: &mut Checkout<PgConnector>,
    stats: &mut RelayStats,
    mut trace: Option<&mut TraceSpan>,
) -> ProtoResult<TransactionStatus> {
    loop {
        let msg = Message::read(checkout.stream_mut())
            .await
            .map_err(|e| ProtoError::backend(format!("reading from backend: {e}")))?;

        let status = msg.transaction_status();
        if let Some(span) = trace.as_mut() {
            span.observe(&msg);
        }

        client
            .write_all(&msg.encode())
            .await
            .map_err(|e| ProtoError::Io(std::io::Error::other(format!("writing to client: {e}"))))?;
        stats.to_client += msg.wire_len() as u64;

        if let Some(status) = status {
            client.flush().await.map_err(ProtoError::Io)?;
            return Ok(status);
        }

        // `CopyInResponse` and `CopyBothResponse` hand the connection over to a
        // streaming sub-protocol that has no ReadyForQuery until it ends. The
        // classifier already pinned the session, so returning here is safe: the
        // backend will not be shared.
        if matches!(msg.tag, b'G' | b'W') {
            client.flush().await.map_err(ProtoError::Io)?;
            return Ok(TransactionStatus::InTransaction);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendConfig;
    use crate::group::PoolGroup;
    use bytes::Bytes;
    use havuz_core::{PoolLimits, SslMode};
    use havuz_proto::PoolMode;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    /// A stand-in PostgreSQL that speaks just enough of the protocol.
    ///
    /// It answers every sync point with `CommandComplete` + `ReadyForQuery`,
    /// tracking transaction state from the SQL it is told to expect. Crucially
    /// it counts how many connections were ever opened, which is the number the
    /// whole feature is judged on.
    struct FakeServer {
        addr: std::net::SocketAddr,
        connections: Arc<AtomicUsize>,
        /// Statements this server actually executed. The only way to prove a
        /// read reached a replica rather than the primary.
        queries: Arc<AtomicUsize>,
    }

    impl FakeServer {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let connections = Arc::new(AtomicUsize::new(0));
            let queries = Arc::new(AtomicUsize::new(0));
            let counter = connections.clone();
            let query_counter = queries.clone();

            tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else { return };
                    counter.fetch_add(1, Ordering::Relaxed);
                    let query_counter = query_counter.clone();

                    tokio::spawn(async move {
                        // Startup: read the packet, answer AuthenticationOk and
                        // a minimal parameter set.
                        let mut len = [0u8; 4];
                        if socket.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let n = i32::from_be_bytes(len) as usize - 4;
                        let mut body = vec![0u8; n];
                        if socket.read_exact(&mut body).await.is_err() {
                            return;
                        }

                        let mut out = Vec::new();
                        out.extend_from_slice(&Message::authentication_ok().encode());
                        out.extend_from_slice(&Message::parameter_status("server_version", "16.2").encode());
                        out.extend_from_slice(&Message::backend_key_data(4242, 7).encode());
                        out.extend_from_slice(&Message::ready_for_query(TransactionStatus::Idle).encode());
                        if socket.write_all(&out).await.is_err() {
                            return;
                        }

                        let mut in_txn = false;
                        loop {
                            let Ok(msg) = Message::read(&mut socket).await else { return };
                            match msg.tag {
                                b'X' => return,
                                b'Q' => {
                                    let sql = String::from_utf8_lossy(&msg.body).to_uppercase();
                                    query_counter.fetch_add(1, Ordering::Relaxed);
                                    if sql.starts_with("BEGIN") {
                                        in_txn = true;
                                    } else if sql.starts_with("COMMIT") || sql.starts_with("ROLLBACK") {
                                        in_txn = false;
                                    }
                                    let status =
                                        if in_txn { TransactionStatus::InTransaction } else { TransactionStatus::Idle };
                                    let mut out = Vec::new();
                                    out.extend_from_slice(
                                        &Message::new(b'C', Bytes::from_static(b"SELECT 1\0")).encode(),
                                    );
                                    out.extend_from_slice(&Message::ready_for_query(status).encode());
                                    if socket.write_all(&out).await.is_err() {
                                        return;
                                    }
                                }
                                b'S' => {
                                    let status =
                                        if in_txn { TransactionStatus::InTransaction } else { TransactionStatus::Idle };
                                    if socket.write_all(&Message::ready_for_query(status).encode()).await.is_err() {
                                        return;
                                    }
                                }
                                _ => continue,
                            }
                        }
                    });
                }
            });

            Self { addr, connections, queries }
        }

        fn opened(&self) -> usize {
            self.connections.load(Ordering::Relaxed)
        }

        fn queries(&self) -> usize {
            self.queries.load(Ordering::Relaxed)
        }

        fn pool(&self, max_size: u32) -> Arc<PoolGroup> {
            group_at(self.addr, max_size)
        }
    }

    /// Build a single-primary group pointing at `addr`.
    fn group_at(addr: std::net::SocketAddr, max_size: u32) -> Arc<PoolGroup> {
        group_with(addr, max_size, &[], false)
    }

    /// Build a group with a primary and optional replicas.
    fn group_with(
        primary: std::net::SocketAddr,
        max_size: u32,
        replicas: &[std::net::SocketAddr],
        split: bool,
    ) -> Arc<PoolGroup> {
        use havuz_core::state::{PoolConfig, RoutingConfig, Target, TargetRole};

        let mut targets = vec![Target::new(primary.ip().to_string(), primary.port())];
        for replica in replicas {
            targets.push(Target {
                host: replica.ip().to_string(),
                port: replica.port(),
                role: TargetRole::Replica,
                weight: 1,
            });
        }

        let config = PoolConfig {
            family: "postgres".into(),
            profile: None,
            mode: PoolMode::Transaction,
            targets,
            backend_user: "app".into(),
            database: "appdb".into(),
            limits: PoolLimits { max_size, queue_timeout: Duration::from_secs(5), ..PoolLimits::default() },
            settings: Default::default(),
            routing: RoutingConfig {
                read_write_split: split,
                // The fakes are always caught up; disabling the lag gate keeps
                // these tests about routing rather than about health probing.
                max_replica_lag: None,
                sticky_after_write: Duration::from_millis(50),
                ..RoutingConfig::default()
            },
            disabled: false,
            description: None,
        };

        PoolGroup::build("app_main", &config, |target| {
            Ok(PgConnector::new(BackendConfig {
                host: target.host.clone(),
                port: target.port,
                database: "appdb".into(),
                user: "app".into(),
                password: String::new(),
                ssl_mode: SslMode::Disable,
                tls: None,
                application_name: "havuz/test".into(),
                supports_discard_all: true,
            }))
        })
        .unwrap()
    }

    /// Drive a client session against the relay and return its outcome.
    async fn run_session(group: Arc<PoolGroup>, script: Vec<Message>) -> (TxnOutcome, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let relay = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut client = MaybeTls::Plain(socket);
            let mut state = SessionState::new(PoolMode::Transaction);
            transaction_relay(&mut client, &group, &mut state).await.unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut received = Vec::new();

        for msg in script {
            let is_terminate = msg.tag == b'X';
            client.write_all(&msg.encode()).await.unwrap();
            if is_terminate {
                break;
            }
            // Read whatever came back, up to ReadyForQuery.
            loop {
                let reply = Message::read(&mut client).await.unwrap();
                received.push(reply.tag);
                if reply.tag == b'Z' {
                    break;
                }
            }
        }
        drop(client);

        (relay.await.unwrap(), received)
    }

    fn query(sql: &str) -> Message {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        Message::new(b'Q', Bytes::from(body))
    }

    #[tokio::test]
    async fn a_backend_is_returned_after_every_transaction() {
        let server = FakeServer::start().await;
        let pool = server.pool(3);

        let (outcome, _) = run_session(
            pool.clone(),
            vec![query("SELECT 1"), query("SELECT 2"), query("SELECT 3"), Message::terminate()],
        )
        .await;

        assert_eq!(outcome.exchanges, 3);
        assert_eq!(outcome.checkouts, 3, "each statement borrows and returns a backend");
        assert_eq!(outcome.pinned, None);
        assert_eq!(server.opened(), 1, "one physical connection served all three");
        assert_eq!(pool.combined_pool_snapshot().idle, 1, "the backend is back on the shelf");
    }

    #[tokio::test]
    async fn a_backend_is_held_for_the_whole_transaction() {
        let server = FakeServer::start().await;
        let pool = server.pool(3);

        let (outcome, _) = run_session(
            pool.clone(),
            vec![query("BEGIN"), query("SELECT 1"), query("SELECT 2"), query("COMMIT"), Message::terminate()],
        )
        .await;

        assert_eq!(outcome.exchanges, 4);
        assert_eq!(
            outcome.checkouts, 1,
            "the backend must not be released mid-transaction, however many statements run"
        );
        assert_eq!(server.opened(), 1);
    }

    #[tokio::test]
    async fn this_is_the_headline_many_clients_one_backend() {
        // Ten sequential clients, each running a transaction, over a pool of
        // one. Session mode would need ten connections.
        let server = FakeServer::start().await;
        let pool = server.pool(1);

        for _ in 0..10 {
            let (outcome, _) = run_session(
                pool.clone(),
                vec![query("BEGIN"), query("SELECT 1"), query("COMMIT"), Message::terminate()],
            )
            .await;
            assert_eq!(outcome.pinned, None);
        }

        assert_eq!(server.opened(), 1, "ten client sessions, one database connection");
        assert_eq!(pool.combined_pool_snapshot().checkout_total, 10);
    }

    #[tokio::test]
    async fn concurrent_clients_share_a_smaller_pool() {
        let server = FakeServer::start().await;
        let pool = server.pool(2);

        let mut tasks = Vec::new();
        for _ in 0..12 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                run_session(pool, vec![query("SELECT 1"), query("SELECT 2"), Message::terminate()]).await
            }));
        }
        for task in tasks {
            let (outcome, _) = task.await.unwrap();
            assert_eq!(outcome.exchanges, 2);
        }

        assert!(server.opened() <= 2, "12 clients opened {} backends, limit is 2", server.opened());
    }

    #[tokio::test]
    async fn a_set_statement_pins_the_session_for_good() {
        let server = FakeServer::start().await;
        let pool = server.pool(3);

        let (outcome, _) = run_session(
            pool.clone(),
            vec![
                query("SET application_name = 'orders-api'"),
                query("SELECT 1"),
                query("SELECT 2"),
                Message::terminate(),
            ],
        )
        .await;

        assert_eq!(outcome.pinned, Some(PinReason::SessionParameter));
        assert_eq!(outcome.checkouts, 1, "once pinned the backend is never given back, so later statements reuse it");
        assert_eq!(outcome.exchanges, 3);
    }

    #[tokio::test]
    async fn a_pinned_session_is_cleaned_before_the_backend_is_reused() {
        let server = FakeServer::start().await;
        let pool = server.pool(3);

        let (outcome, _) = run_session(pool.clone(), vec![query("LISTEN chan"), Message::terminate()]).await;
        assert_eq!(outcome.pinned, Some(PinReason::Listen));

        // Give the reset a moment, then confirm the connection was recycled
        // rather than thrown away.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let snapshot = pool.combined_pool_snapshot();
        assert_eq!(snapshot.idle + snapshot.discarded_total, 1);
    }

    #[tokio::test]
    async fn an_unfinished_transaction_does_not_leak_to_the_next_client() {
        let server = FakeServer::start().await;
        let pool = server.pool(3);

        // Client opens a transaction and vanishes without committing.
        let (outcome, _) = run_session(pool.clone(), vec![query("BEGIN")]).await;
        assert!(outcome.pinned.is_none());

        tokio::time::sleep(Duration::from_millis(50)).await;
        // The connection must have been reset or discarded, never pooled with
        // an open transaction.
        let snapshot = pool.combined_pool_snapshot();
        assert_eq!(snapshot.active, 0, "nothing may still be checked out");
    }

    #[tokio::test]
    async fn extended_protocol_only_releases_at_sync() {
        let server = FakeServer::start().await;
        let pool = server.pool(3);

        let parse = {
            let mut body = Vec::new();
            body.extend_from_slice(b"\0"); // unnamed statement
            body.extend_from_slice(b"SELECT $1\0");
            body.extend_from_slice(&0i16.to_be_bytes());
            Message::new(b'P', Bytes::from(body))
        };
        let bind = Message::new(b'B', Bytes::from_static(b"\0\0\0\0\0\0\0\0"));
        let execute = Message::new(b'E', Bytes::from_static(b"\0\0\0\0\0"));
        let sync = Message::new(b'S', Bytes::new());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut client = MaybeTls::Plain(socket);
            let mut state = SessionState::new(PoolMode::Transaction);
            transaction_relay(&mut client, &pool, &mut state).await.unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        for msg in [parse, bind, execute, sync] {
            client.write_all(&msg.encode()).await.unwrap();
        }
        let reply = Message::read(&mut client).await.unwrap();
        assert_eq!(reply.tag, b'Z', "the whole pipeline is answered at Sync");
        client.write_all(&Message::terminate().encode()).await.unwrap();
        drop(client);

        let outcome = relay.await.unwrap();
        assert_eq!(outcome.exchanges, 1, "one Sync is one exchange, not four messages");
        assert_eq!(outcome.checkouts, 1);
    }

    /// A stricter fake that models what really breaks transaction-mode pooling:
    /// prepared statements are per-connection, and binding to one the
    /// connection never parsed is an error.
    struct StrictServer {
        addr: std::net::SocketAddr,
        connections: Arc<AtomicUsize>,
        /// Binds that were rejected because the backend had not parsed the
        /// statement. Must stay at zero.
        rejected: Arc<AtomicUsize>,
    }

    impl StrictServer {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let connections = Arc::new(AtomicUsize::new(0));
            let rejected = Arc::new(AtomicUsize::new(0));
            let (counter, rejects) = (connections.clone(), rejected.clone());

            tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else { return };
                    counter.fetch_add(1, Ordering::Relaxed);
                    let rejects = rejects.clone();

                    tokio::spawn(async move {
                        let mut len = [0u8; 4];
                        if socket.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let n = i32::from_be_bytes(len) as usize - 4;
                        let mut body = vec![0u8; n];
                        if socket.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let mut out = Vec::new();
                        out.extend_from_slice(&Message::authentication_ok().encode());
                        out.extend_from_slice(&Message::ready_for_query(TransactionStatus::Idle).encode());
                        if socket.write_all(&out).await.is_err() {
                            return;
                        }

                        // Prepared statements belong to this connection alone.
                        let mut parsed: std::collections::HashSet<String> = Default::default();
                        let mut pending: Vec<u8> = Vec::new();

                        loop {
                            let Ok(msg) = Message::read(&mut socket).await else { return };
                            match msg.tag {
                                b'X' => return,
                                b'P' => {
                                    let name = msg
                                        .body
                                        .split(|b| *b == 0)
                                        .next()
                                        .map(|n| String::from_utf8_lossy(n).into_owned())
                                        .unwrap_or_default();
                                    parsed.insert(name);
                                    pending.extend_from_slice(&Message::new(b'1', Bytes::new()).encode());
                                }
                                b'B' => {
                                    let mut parts = msg.body.splitn(3, |b| *b == 0);
                                    let _portal = parts.next();
                                    let stmt = parts
                                        .next()
                                        .map(|n| String::from_utf8_lossy(n).into_owned())
                                        .unwrap_or_default();
                                    if !stmt.is_empty() && !parsed.contains(&stmt) {
                                        rejects.fetch_add(1, Ordering::Relaxed);
                                        pending.extend_from_slice(
                                            &Message::error_response(
                                                "ERROR",
                                                "26000",
                                                &format!("prepared statement \"{stmt}\" does not exist"),
                                            )
                                            .encode(),
                                        );
                                    } else {
                                        pending.extend_from_slice(&Message::new(b'2', Bytes::new()).encode());
                                    }
                                }
                                b'C' => pending.extend_from_slice(&Message::new(b'3', Bytes::new()).encode()),
                                b'E' => pending
                                    .extend_from_slice(&Message::new(b'C', Bytes::from_static(b"SELECT 1\0")).encode()),
                                b'D' => pending.extend_from_slice(&Message::new(b'n', Bytes::new()).encode()),
                                b'H' => {
                                    if socket.write_all(&pending).await.is_err() {
                                        return;
                                    }
                                    pending.clear();
                                }
                                b'S' => {
                                    pending
                                        .extend_from_slice(&Message::ready_for_query(TransactionStatus::Idle).encode());
                                    if socket.write_all(&pending).await.is_err() {
                                        return;
                                    }
                                    pending.clear();
                                }
                                _ => continue,
                            }
                        }
                    });
                }
            });

            Self { addr, connections, rejected }
        }

        fn pool(&self, max_size: u32) -> Arc<PoolGroup> {
            group_at(self.addr, max_size)
        }
    }

    fn parse(name: &str, sql: &str) -> Message {
        let mut body = Vec::new();
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(sql.as_bytes());
        body.push(0);
        body.extend_from_slice(&0i16.to_be_bytes());
        Message::new(b'P', Bytes::from(body))
    }

    fn bind(statement: &str) -> Message {
        let mut body = Vec::new();
        body.push(0); // unnamed portal
        body.extend_from_slice(statement.as_bytes());
        body.push(0);
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        Message::new(b'B', Bytes::from(body))
    }

    #[tokio::test]
    async fn a_named_statement_follows_the_client_onto_every_backend() {
        // The scenario that makes transaction-mode pooling unusable without
        // rewriting: parse once, then bind on whichever backend the pool hands
        // out next. Two backends, so the second bind is guaranteed to land on a
        // connection that never saw the Parse.
        let server = StrictServer::start().await;
        let pool = server.pool(2);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay_pool = pool.clone();
        let relay = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut client = MaybeTls::Plain(socket);
            let mut state = SessionState::new(PoolMode::Transaction);
            transaction_relay(&mut client, &relay_pool, &mut state).await.unwrap()
        });

        // Occupy one backend so the next checkout is forced onto a second one.
        let hog = pool.primary().acquire().await.unwrap();

        let mut client = TcpStream::connect(addr).await.unwrap();
        let sync = Message::new(b'S', Bytes::new());
        let execute = Message::new(b'E', Bytes::from_static(b"\0\0\0\0\0"));

        // Exchange 1: parse and use the statement.
        for msg in [parse("s1", "SELECT $1"), bind("s1"), execute.clone(), sync.clone()] {
            client.write_all(&msg.encode()).await.unwrap();
        }
        let mut saw_error = false;
        loop {
            let reply = Message::read(&mut client).await.unwrap();
            if reply.tag == b'E' {
                saw_error = true;
            }
            if reply.tag == b'Z' {
                break;
            }
        }
        assert!(!saw_error, "the first exchange must succeed");

        // Release the hog so the pool now has two usable backends, then run a
        // second exchange that binds without re-parsing.
        drop(hog);
        for msg in [bind("s1"), execute, sync] {
            client.write_all(&msg.encode()).await.unwrap();
        }
        loop {
            let reply = Message::read(&mut client).await.unwrap();
            if reply.tag == b'E' {
                saw_error = true;
            }
            if reply.tag == b'Z' {
                break;
            }
        }

        client.write_all(&Message::terminate().encode()).await.unwrap();
        drop(client);
        let outcome = relay.await.unwrap();

        assert!(!saw_error, "binding after a backend switch must not fail");
        assert_eq!(
            server.rejected.load(Ordering::Relaxed),
            0,
            "no backend should ever see a bind for a statement it did not parse"
        );
        assert_eq!(outcome.pinned, None, "named statements must not cost multiplexing");
        assert!(server.connections.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn binding_to_a_statement_that_was_never_parsed_is_refused() {
        // Forwarding this blindly could bind the client to another client's
        // statement under the same name.
        let server = StrictServer::start().await;
        let pool = server.pool(2);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut client = MaybeTls::Plain(socket);
            let mut state = SessionState::new(PoolMode::Transaction);
            transaction_relay(&mut client, &pool, &mut state).await.unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&bind("never_parsed").encode()).await.unwrap();

        let mut tags = Vec::new();
        loop {
            let reply = Message::read(&mut client).await.unwrap();
            tags.push(reply.tag);
            if reply.tag == b'Z' {
                break;
            }
        }
        assert!(tags.contains(&b'E'), "the client must get an error, got {tags:?}");
        assert_eq!(server.rejected.load(Ordering::Relaxed), 0, "the bogus name never reached a backend");

        client.write_all(&Message::terminate().encode()).await.unwrap();
        drop(client);
        relay.await.unwrap();
    }

    #[tokio::test]
    async fn terminate_never_reaches_the_backend() {
        let server = FakeServer::start().await;
        let pool = server.pool(3);

        let (outcome, _) = run_session(pool.clone(), vec![query("SELECT 1"), Message::terminate()]).await;
        assert!(outcome.stats.client_terminated);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pool.combined_pool_snapshot().idle, 1, "the backend survived the client leaving");
        assert_eq!(server.opened(), 1);

        // And it really is reusable.
        let (outcome, _) = run_session(pool.clone(), vec![query("SELECT 2"), Message::terminate()]).await;
        assert_eq!(outcome.exchanges, 1);
        assert_eq!(server.opened(), 1, "the second session reused the first connection");
    }

    // --- read/write split ---

    #[tokio::test]
    async fn reads_reach_the_replica_and_writes_reach_the_primary() {
        let primary = FakeServer::start().await;
        let replica = FakeServer::start().await;
        let group = group_with(primary.addr, 3, &[replica.addr], true);

        let (outcome, _) = run_session(group, vec![query("SELECT 1"), query("SELECT 2"), Message::terminate()]).await;

        assert_eq!(outcome.to_replica, 2, "both reads should have been routed to the replica");
        assert_eq!(replica.queries(), 2);
        assert_eq!(primary.queries(), 0, "no read should have touched the primary");
    }

    #[tokio::test]
    async fn a_read_after_a_write_goes_to_the_primary() {
        // The failure this prevents: insert a row, read it back, and get
        // nothing because the replica has not caught up. No error is raised
        // anywhere, which is what makes it dangerous.
        let primary = FakeServer::start().await;
        let replica = FakeServer::start().await;
        let group = group_with(primary.addr, 3, &[replica.addr], true);

        let (outcome, _) =
            run_session(group, vec![query("INSERT INTO t VALUES (1)"), query("SELECT * FROM t"), Message::terminate()])
                .await;

        assert_eq!(outcome.to_replica, 0, "the read must follow its own write");
        assert_eq!(primary.queries(), 2);
        assert_eq!(replica.queries(), 0);
    }

    #[tokio::test]
    async fn the_sticky_window_releases_reads_back_to_the_replica() {
        let primary = FakeServer::start().await;
        let replica = FakeServer::start().await;
        let group = group_with(primary.addr, 3, &[replica.addr], true);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut client = MaybeTls::Plain(socket);
            let mut state = SessionState::new(PoolMode::Transaction);
            transaction_relay(&mut client, &group, &mut state).await.unwrap()
        });

        async fn exchange(c: &mut TcpStream, m: Message) {
            c.write_all(&m.encode()).await.unwrap();
            loop {
                if Message::read(c).await.unwrap().tag == b'Z' {
                    break;
                }
            }
        }

        let mut client = TcpStream::connect(addr).await.unwrap();
        exchange(&mut client, query("UPDATE t SET x = 1")).await;
        exchange(&mut client, query("SELECT 1")).await;
        assert_eq!(replica.queries(), 0, "still inside the sticky window");

        // Sticky window is 50ms in these tests.
        tokio::time::sleep(Duration::from_millis(80)).await;
        exchange(&mut client, query("SELECT 2")).await;

        client.write_all(&Message::terminate().encode()).await.unwrap();
        drop(client);
        let outcome = relay.await.unwrap();

        assert_eq!(replica.queries(), 1, "once the window expires reads go back to the replica");
        assert_eq!(outcome.to_replica, 1);
    }

    #[tokio::test]
    async fn a_transaction_stays_on_one_target() {
        let primary = FakeServer::start().await;
        let replica = FakeServer::start().await;
        let group = group_with(primary.addr, 3, &[replica.addr], true);

        let (outcome, _) = run_session(
            group,
            vec![query("BEGIN"), query("SELECT 1"), query("SELECT 2"), query("COMMIT"), Message::terminate()],
        )
        .await;

        // A plain BEGIN is a write as far as we can tell, so the whole
        // transaction belongs to the primary. Splitting it would give the
        // reads a different snapshot from the transaction they are inside.
        assert_eq!(outcome.to_replica, 0);
        assert_eq!(replica.queries(), 0);
        assert_eq!(primary.queries(), 4);
    }

    #[tokio::test]
    async fn with_split_disabled_the_replica_is_never_used() {
        let primary = FakeServer::start().await;
        let replica = FakeServer::start().await;
        let group = group_with(primary.addr, 3, &[replica.addr], false);

        let (outcome, _) = run_session(group, vec![query("SELECT 1"), Message::terminate()]).await;

        assert_eq!(outcome.to_replica, 0);
        assert_eq!(replica.opened(), 0, "an unused replica should not even be connected to");
        assert_eq!(primary.queries(), 1);
    }

    #[tokio::test]
    async fn a_dead_replica_falls_back_to_the_primary_without_failing_the_client() {
        let primary = FakeServer::start().await;
        // A port nothing listens on.
        let dead: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let group = group_with(primary.addr, 3, &[dead], true);

        let (outcome, _) = run_session(
            group.clone(),
            vec![query("SELECT 1"), query("SELECT 2"), query("SELECT 3"), Message::terminate()],
        )
        .await;

        assert_eq!(outcome.exchanges, 3, "the client must still be served");
        assert!(primary.queries() >= 1, "traffic fell back to the primary");

        // And the breaker noticed.
        let snapshot = group.snapshot();
        assert!(
            snapshot.replicas[0].routing.breaker.failures_total > 0,
            "connection failures must be recorded against the replica"
        );
    }
}
