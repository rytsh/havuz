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
//! `LISTEN`, temp tables, advisory locks — is classified as a pin, and a pinned
//! connection is never shared. The reset happens once, when the client finally
//! goes away.
//!
//! **Session parameters move with the client, not with the backend.** `SET` is
//! the exception to the rule above, and it is the exception that decides
//! whether transaction mode works at all: every driver sends two or three on
//! connect, so pinning on them meant a pool of two backends was permanently
//! owned by the first two clients. Instead each client carries the parameters
//! it asked for, each backend remembers the ones it has, and a checkout that
//! finds a difference sends the delta first. See [`crate::params`].
//!
//! **A backend is only borrowed when there is work.** An idle client holds
//! nothing. That is the entire source of the fan-in.

use havuz_control::{HolderHandle, KickSignal, PrimaryReason, TraceContext, TraceSpan, TraceStore};
use havuz_pool::Checkout;
use havuz_proto::{BackendConn, FlowEvent, PinReason, ProtoError, ProtoResult, SessionState};
use tokio::io::AsyncWriteExt;

use crate::backend::PgConnector;
use crate::cancel::CancelScope;
use crate::classify::{classify, route_intent, ClientIntent, RouteIntent};
use crate::group::PoolGroup;
use crate::params::{self, ClientParams, SetAction};
use crate::prepared::{ClientStatements, Rewrite};
use crate::protocol::{sqlstate, Message, TransactionStatus};
use crate::relay::RelayStats;
use crate::routing::{Route, SessionRouting};
use crate::stream::MaybeTls;
use crate::trace::PgTraceSpan;

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
    /// Checkouts that had to carry session parameters over to a backend that
    /// did not already have them. This is what replacing the pin costs, so it
    /// is worth being able to see.
    pub param_syncs: u64,
}

/// How a session is allowed to behave, beyond what its statements ask for.
#[derive(Debug, Clone, Default)]
pub struct SessionPolicy {
    /// Refuse anything that would let this session write. The writes
    /// themselves are refused by PostgreSQL; this only closes the statements
    /// that would turn the setting back off.
    pub read_only: bool,
    /// Resolves when an operator ends this session.
    pub kick: KickSignal,
    /// This session's slot in the cancellation registry, retargeted as it
    /// borrows and returns backends.
    ///
    /// `None` outside a served session — the relay is testable without one, and
    /// a session with no slot simply cannot be cancelled.
    pub cancel: Option<CancelScope>,
}

/// Relay a client session in transaction mode.
pub async fn transaction_relay(
    client: &mut MaybeTls,
    group: &PoolGroup,
    state: &mut SessionState,
    params: &mut ClientParams,
) -> ProtoResult<TxnOutcome> {
    transaction_relay_inner(client, group, state, params, SessionPolicy::default(), None, None).await
}

#[allow(clippy::too_many_arguments)]
pub async fn transaction_relay_traced(
    client: &mut MaybeTls,
    group: &PoolGroup,
    state: &mut SessionState,
    params: &mut ClientParams,
    policy: SessionPolicy,
    traces: &std::sync::Arc<TraceStore>,
    context: &TraceContext,
    holder: &HolderHandle,
) -> ProtoResult<TxnOutcome> {
    transaction_relay_inner(client, group, state, params, policy, Some((traces, context)), Some(holder)).await
}

async fn transaction_relay_inner(
    client: &mut MaybeTls,
    group: &PoolGroup,
    state: &mut SessionState,
    params: &mut ClientParams,
    mut policy: SessionPolicy,
    tracing: Option<(&std::sync::Arc<TraceStore>, &TraceContext)>,
    holder: Option<&HolderHandle>,
) -> ProtoResult<TxnOutcome> {
    let mut held: Option<Checkout<PgConnector>> = None;
    let mut stats = RelayStats::default();
    let mut exchanges = 0u64;
    let mut checkouts = 0u64;
    let mut to_replica = 0u64;
    let mut param_syncs = 0u64;
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
        //
        // This is also the one place a kick may take effect. Anywhere else the
        // backend could be halfway through a response, and dropping the relay
        // there would return a connection with unread bytes to the pool — the
        // next client would receive the tail of this one's result set. Waiting
        // until the client is between statements costs an operator the time of
        // one query and keeps the pool intact.
        let msg = tokio::select! {
            biased;
            _ = policy.kick.kicked() => {
                let _ = Message::fatal(
                    sqlstate::ADMIN_SHUTDOWN,
                    "terminating connection due to administrator command",
                )
                .write(client)
                .await;
                break;
            }
            read = Message::read(client) => match read {
                Ok(msg) => msg,
                Err(_) => break,
            },
        };

        let intent = classify(&msg);

        // A read-only user gets `default_transaction_read_only`, and PostgreSQL
        // does the actual refusing. That only holds while the client cannot
        // turn the setting back off, so the statements that would are answered
        // here and never forwarded.
        if policy.read_only {
            if let Some(sql) = param_sql(&msg) {
                if params::defeats_read_only(&sql) {
                    let detail = "this user is read-only; the session cannot be made writable";
                    let _ = Message::error_response("ERROR", sqlstate::READ_ONLY_SQL_TRANSACTION, detail)
                        .write(client)
                        .await;
                    let _ = Message::ready_for_query(if state.in_transaction() {
                        TransactionStatus::Failed
                    } else {
                        TransactionStatus::Idle
                    })
                    .write(client)
                    .await;
                    if let Some((traces, context)) = tracing {
                        traces.record_failure(
                            context,
                            &sql,
                            std::time::Duration::ZERO,
                            sqlstate::READ_ONLY_SQL_TRANSACTION,
                            detail,
                        );
                    }
                    continue;
                }
            }
        }

        if intent == ClientIntent::Terminate {
            stats.client_terminated = true;
            break;
        }

        if held.is_some() {
            if let Some(holder) = holder {
                holder.clear();
            }
        }

        if let ClientIntent::Pins(reason) = intent {
            state.observe(FlowEvent::MustPin(reason));
        }

        // Note what this message would do to the session's parameters. Staged
        // rather than applied: the server has not seen it yet, and a statement
        // that errors changes nothing.
        if let Some(sql) = param_sql(&msg) {
            stage_params(params, state, &sql);
        }

        if trace_span.is_none() {
            if let (Some(sql), Some((traces, context))) = (trace_sql(&msg, &statements), tracing) {
                let mut span = traces.begin(context, sql);
                // Armed with the session's slot rather than a fixed target, so
                // an operator pressing cancel hits whatever backend the client
                // holds at that instant — and nothing at all once the query is
                // over and the span has gone.
                if let Some(scope) = policy.cancel.clone() {
                    span.arm_cancel(std::sync::Arc::new(scope));
                }
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
                Ok(mut checkout) => {
                    checkouts += 1;
                    if matches!(current_route, Route::Replica(_)) {
                        to_replica += 1;
                    }
                    if let Some(span) = trace_span.as_mut() {
                        span.assign(group.target_label(current_route), checkout.backend_pid());
                    }

                    // This backend may have been someone else's a microsecond
                    // ago. Carry the client's session parameters over before
                    // its statement runs against the wrong search_path.
                    match sync_params(&mut checkout, params).await {
                        Ok(ParamSync::Unchanged) => {}
                        Ok(ParamSync::Applied) => param_syncs += 1,
                        Ok(ParamSync::Refused(detail)) => {
                            // The delta is a multi-statement simple query, so
                            // an implicit transaction rolled all of it back.
                            // The backend is clean and goes back to the pool;
                            // it is the request that cannot be honoured.
                            let message = format!("cannot apply session parameters: {detail}");
                            if let Some(span) = trace_span.take() {
                                span.fail(sqlstate::INVALID_PARAMETER_VALUE, &message);
                            }
                            let _ = Message::fatal(sqlstate::INVALID_PARAMETER_VALUE, &message).write(client).await;
                            return Err(ProtoError::backend(message));
                        }
                        Err(e) => {
                            // An I/O failure leaves the framing position
                            // unknown, so this connection cannot be reused.
                            checkout.discard();
                            group.router().record_result(current_route, false);
                            let _ = Message::fatal(sqlstate::CANNOT_CONNECT_NOW, &e.to_string()).write(client).await;
                            return Err(e);
                        }
                    }

                    held = Some(checkout);
                    retarget_cancel(policy.cancel.as_ref(), held.as_ref());
                }
                Err(e) => {
                    group.router().record_result(current_route, false);
                    let code = match &e {
                        havuz_pool::PoolError::Timeout { .. } => sqlstate::TOO_MANY_CONNECTIONS,
                        _ => sqlstate::CANNOT_CONNECT_NOW,
                    };
                    let message = if matches!(e, havuz_pool::PoolError::Timeout { .. }) {
                        format!("{e}; {}", holder.map(HolderHandle::timeout_hint).unwrap_or_default())
                    } else {
                        e.to_string()
                    };
                    if let Some(span) = trace_span.take() {
                        span.fail(code, &message);
                    }
                    let _ = Message::fatal(code, &message).write(client).await;
                    return Err(ProtoError::backend(message));
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
            retarget_cancel(policy.cancel.as_ref(), None);
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
            Ok(end) => {
                exchanges += 1;
                group.router().record_result(current_route, true);
                match end.status {
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
                settle_params(params, checkout, end.errored);
                update_holder(holder, state, group, current_route, checkout);
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
                retarget_cancel(policy.cancel.as_ref(), None);

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
                    // The replay runs on this backend even though `held` will
                    // not be set until it succeeds, and it is a replay of the
                    // statement the client is still waiting on — so it has to
                    // stay cancellable throughout.
                    retarget_cancel(policy.cancel.as_ref(), Some(&checkout));

                    // The replay lands on a different backend, so it needs the
                    // client's parameters just as much as the original did.
                    match sync_params(&mut checkout, params).await {
                        Ok(ParamSync::Unchanged) => {}
                        Ok(ParamSync::Applied) => param_syncs += 1,
                        Ok(ParamSync::Refused(detail)) => {
                            let message = format!("cannot apply session parameters: {detail}");
                            let _ = Message::fatal(sqlstate::INVALID_PARAMETER_VALUE, &message).write(client).await;
                            return Err(ProtoError::backend(message));
                        }
                        Err(e) => {
                            checkout.discard();
                            let _ = Message::fatal(sqlstate::CANNOT_CONNECT_NOW, &e.to_string()).write(client).await;
                            return Err(e);
                        }
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
                        Ok(end) => {
                            exchanges += 1;
                            group.router().record_result(current_route, true);
                            match end.status {
                                TransactionStatus::Idle => {
                                    state.observe(FlowEvent::Idle);
                                    routing.end_transaction();
                                }
                                _ => {
                                    state.observe(FlowEvent::InTransaction);
                                    routing.begin_transaction(current_route);
                                }
                            }
                            settle_params(params, &mut checkout, end.errored);
                            update_holder(holder, state, group, current_route, &checkout);
                            if let Some(span) = trace_span.take() {
                                span.succeed();
                            }
                            exchange.clear();
                            held = Some(checkout);
                            if state.is_releasable() {
                                state.released();
                                held = None;
                            }
                            retarget_cancel(policy.cancel.as_ref(), held.as_ref());
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
        retarget_cancel(policy.cancel.as_ref(), held.as_ref());
    }

    retarget_cancel(policy.cancel.as_ref(), None);

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

    Ok(TxnOutcome { stats, exchanges, pinned: state.pin(), checkouts, to_replica, param_syncs })
}

/// Everything one client message would do to the session's parameters.
///
/// Only `Query` and `Parse` carry statement text. A `Bind` names a statement
/// whose `Parse` was already staged, so reading it again would count the same
/// `SET` twice.
fn param_sql(msg: &Message) -> Option<String> {
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
        _ => None,
    }
}

/// Stage what a statement would do, without believing it yet.
fn stage_params(params: &mut ClientParams, state: &mut SessionState, sql: &str) {
    let actions = params::actions_for_sql(sql);
    if actions.is_empty() {
        return;
    }

    // A `SET` inside an explicit transaction may be undone by a `ROLLBACK` we
    // cannot see coming, and nothing on the wire distinguishes a transaction
    // that committed from one that did not. Rather than guess, pin: `SET LOCAL`
    // is the idiom for changing a parameter inside a transaction anyway, and it
    // is free.
    if state.in_transaction() {
        state.observe(FlowEvent::MustPin(PinReason::SessionParameter));
        return;
    }

    for action in actions {
        // `classify` has already turned an unreplayable statement into a pin;
        // staging it here would only double-count the observation.
        if !matches!(action, SetAction::Pin(_)) {
            params.stage(action);
        }
    }
}

/// Believe — or forget — the staged parameter changes now that the server has
/// answered.
fn settle_params(params: &mut ClientParams, checkout: &mut Checkout<PgConnector>, errored: bool) {
    if !params.has_pending() {
        return;
    }
    if errored {
        // A single statement that fails applies nothing, and a batch is an
        // implicit transaction, so a failure anywhere in it rolls all of it
        // back. Either way the client's parameters are what they were.
        params.discard_pending();
        return;
    }
    params.commit_pending();
    // The client's own `SET` reached this backend directly, so it is now in
    // step with the client without us having replayed anything.
    checkout.set_applied_params(params.desired().clone());
}

/// Outcome of bringing a backend in line with a client's session parameters.
pub(crate) enum ParamSync {
    /// The backend already matched. The common case once a client settles onto
    /// a pool, and the reason this is not a round trip per transaction.
    Unchanged,
    /// The delta was applied.
    Applied,
    /// The server refused it. Nothing was applied, so the backend is still
    /// clean; it is the client's request that cannot be honoured.
    Refused(String),
}

/// Carry a client's session parameters onto the backend it just borrowed.
///
/// Sent as one simple query, so a delta of any size costs a single round trip,
/// and only when there is a delta at all.
///
/// The replies are consumed rather than forwarded. The client did not ask for
/// these statements, and the `ParameterStatus` messages they produce describe
/// changes it never made — including the resets that undo the *previous*
/// client's parameters.
pub(crate) async fn sync_params(checkout: &mut Checkout<PgConnector>, params: &ClientParams) -> ProtoResult<ParamSync> {
    let statements = params.delta(checkout.applied_params());
    if statements.is_empty() {
        return Ok(ParamSync::Unchanged);
    }

    let sql = statements.join("; ");
    let mut body = Vec::with_capacity(sql.len() + 1);
    body.extend_from_slice(sql.as_bytes());
    body.push(0);

    let stream = checkout.stream_mut();
    stream
        .write_all(&Message::new(b'Q', bytes::Bytes::from(body)).encode())
        .await
        .map_err(|e| ProtoError::backend(format!("applying session parameters: {e}")))?;
    stream.flush().await.map_err(|e| ProtoError::backend(format!("applying session parameters: {e}")))?;

    let mut failure = None;
    loop {
        let reply = Message::read(checkout.stream_mut())
            .await
            .map_err(|e| ProtoError::backend(format!("applying session parameters: {e}")))?;
        match reply.tag {
            // ReadyForQuery: the whole batch has been answered.
            b'Z' => break,
            b'E' => {
                failure = reply
                    .error_fields()
                    .into_iter()
                    .find(|(field, _)| *field == b'M')
                    .map(|(_, text)| text)
                    .or_else(|| Some("backend rejected the parameter".into()));
            }
            _ => continue,
        }
    }

    if let Some(detail) = failure {
        return Ok(ParamSync::Refused(format!("{detail} (while running: {sql})")));
    }

    checkout.set_applied_params(params.desired().clone());
    Ok(ParamSync::Applied)
}

fn update_holder(
    holder: Option<&HolderHandle>,
    state: &SessionState,
    group: &PoolGroup,
    route: Route,
    checkout: &Checkout<PgConnector>,
) {
    let Some(holder) = holder else { return };
    let target = group.target_label(route);
    if let Some(reason) = state.pin() {
        holder.pinned(reason, target, checkout.backend_pid());
    } else if state.in_transaction() {
        holder.idle_in_transaction(target, checkout.backend_pid());
    } else {
        holder.clear();
    }
}

/// Point this session's cancellation key at the backend it is holding.
///
/// Called after every change to `held`, and that is the whole contract: a key
/// that lagged behind would let a `Ctrl-C` land on a backend this client had
/// already given back, cancelling a query belonging to whoever borrowed it
/// next. Passing `None` is not a failure — it is the normal state of a
/// transaction-mode client between statements, and it means a cancellation
/// arriving now correctly does nothing.
fn retarget_cancel(scope: Option<&CancelScope>, held: Option<&Checkout<PgConnector>>) {
    if let Some(scope) = scope {
        scope.retarget(held.and_then(|checkout| checkout.cancel_target()));
    }
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

/// How an exchange ended.
struct ExchangeEnd {
    status: TransactionStatus,
    /// The server reported an error. Since a lone statement that fails applies
    /// nothing, and a batch is an implicit transaction that rolls back as a
    /// unit, this means the exchange changed no session state.
    errored: bool,
}

/// Copy backend output to the client until `ReadyForQuery`.
async fn pump_until_ready(
    client: &mut MaybeTls,
    checkout: &mut Checkout<PgConnector>,
    stats: &mut RelayStats,
    mut trace: Option<&mut TraceSpan>,
) -> ProtoResult<ExchangeEnd> {
    let mut errored = false;

    loop {
        let msg = Message::read(checkout.stream_mut())
            .await
            .map_err(|e| ProtoError::backend(format!("reading from backend: {e}")))?;

        let status = msg.transaction_status();
        errored |= msg.tag == b'E';
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
            return Ok(ExchangeEnd { status, errored });
        }

        // `CopyInResponse` and `CopyBothResponse` hand the connection over to a
        // streaming sub-protocol that has no ReadyForQuery until it ends. The
        // classifier already pinned the session, so returning here is safe: the
        // backend will not be shared.
        if matches!(msg.tag, b'G' | b'W') {
            client.flush().await.map_err(ProtoError::Io)?;
            return Ok(ExchangeEnd { status: TransactionStatus::InTransaction, errored });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendConfig;
    use crate::group::PoolGroup;
    use bytes::Bytes;
    use havuz_control::CancelHook;
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
        /// The text of those statements, per backend connection. Session
        /// parameters are only really carried over if the replay lands on the
        /// backend that did not have them, and this is what shows that.
        log: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl FakeServer {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let connections = Arc::new(AtomicUsize::new(0));
            let queries = Arc::new(AtomicUsize::new(0));
            let log = Arc::new(std::sync::Mutex::new(Vec::new()));
            let counter = connections.clone();
            let query_counter = queries.clone();
            let query_log = log.clone();

            tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else { return };
                    counter.fetch_add(1, Ordering::Relaxed);
                    let query_counter = query_counter.clone();
                    let query_log = query_log.clone();

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
                                    let text = String::from_utf8_lossy(&msg.body).trim_end_matches('\0').to_string();
                                    let sql = text.to_uppercase();
                                    query_counter.fetch_add(1, Ordering::Relaxed);
                                    query_log.lock().unwrap().push(text);
                                    if sql.starts_with("BEGIN") {
                                        in_txn = true;
                                    } else if sql.starts_with("COMMIT") || sql.starts_with("ROLLBACK") {
                                        in_txn = false;
                                    }
                                    let status =
                                        if in_txn { TransactionStatus::InTransaction } else { TransactionStatus::Idle };
                                    let mut out = Vec::new();
                                    // A statement the fake is told to reject, so
                                    // the failure paths can be exercised without
                                    // a real server.
                                    if sql.contains("BOOM") {
                                        out.extend_from_slice(
                                            &Message::error_response("ERROR", "42601", "syntax error at or near boom")
                                                .encode(),
                                        );
                                    } else {
                                        out.extend_from_slice(
                                            &Message::new(b'C', Bytes::from_static(b"SELECT 1\0")).encode(),
                                        );
                                    }
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

            Self { addr, connections, queries, log }
        }

        fn opened(&self) -> usize {
            self.connections.load(Ordering::Relaxed)
        }

        fn queries(&self) -> usize {
            self.queries.load(Ordering::Relaxed)
        }

        /// Every statement this server ran, in order.
        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
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
            listen_port: 6432,
            aliases: Vec::new(),
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
            backend_auth: Default::default(),
            allow_password_without_tls: false,
            trace: Default::default(),
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
        run_session_with(group, ClientParams::new(), script).await
    }

    /// Drive a client session that arrived with startup parameters.
    async fn run_session_with(
        group: Arc<PoolGroup>,
        mut params: ClientParams,
        script: Vec<Message>,
    ) -> (TxnOutcome, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let relay = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut client = MaybeTls::Plain(socket);
            let mut state = SessionState::new(PoolMode::Transaction);
            transaction_relay(&mut client, &group, &mut state, &mut params).await.unwrap()
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
    async fn a_set_statement_does_not_cost_the_backend() {
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

        assert_eq!(outcome.pinned, None, "a session parameter has a name, so it can travel instead of pinning");
        assert_eq!(outcome.checkouts, 3, "the backend goes back after every statement, SET included");
        assert_eq!(outcome.exchanges, 3);
    }

    #[tokio::test]
    async fn the_scenario_this_was_built_for_a_driver_preamble_over_a_tiny_pool() {
        // Every driver sends two or three SETs on connect. While those pinned,
        // a pool of two was owned forever by the first two clients and every
        // other client timed out — the pooler was unusable in exactly the
        // configuration it exists for.
        let server = FakeServer::start().await;
        let pool = server.pool(2);

        let mut tasks = Vec::new();
        for i in 0..20 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                run_session(
                    pool,
                    vec![
                        query(&format!("SET application_name = 'client-{i}'")),
                        query("SET extra_float_digits = 3"),
                        query("SELECT 1"),
                        Message::terminate(),
                    ],
                )
                .await
            }));
        }

        for task in tasks {
            let (outcome, _) = task.await.unwrap();
            assert_eq!(outcome.pinned, None);
            assert_eq!(outcome.exchanges, 3);
        }

        assert!(server.opened() <= 2, "20 clients with a driver preamble opened {} backends", server.opened());
    }

    #[tokio::test]
    async fn a_session_parameter_follows_the_client_onto_the_next_backend() {
        let server = FakeServer::start().await;
        let pool = server.pool(2);

        // Two clients, each holding a backend, so the second session is
        // guaranteed to land on a connection that never saw the first one's
        // SET. Without replay its SELECT would run under the wrong search_path.
        let (first, _) =
            run_session(pool.clone(), vec![query("SET search_path TO app"), query("SELECT 1"), Message::terminate()])
                .await;
        assert_eq!(first.pinned, None);

        let (second, _) =
            run_session(pool.clone(), vec![query("SET search_path TO other"), query("SELECT 2"), Message::terminate()])
                .await;
        assert_eq!(second.pinned, None);

        let log = server.log();
        assert!(
            log.iter().any(|sql| sql == "SET search_path TO app"),
            "the client's own statement reaches the backend: {log:?}"
        );
        assert!(
            log.iter().filter(|sql| sql.contains("search_path")).count() >= 2,
            "each client's search_path must be in force for its own SELECT: {log:?}"
        );
    }

    #[tokio::test]
    async fn one_client_never_inherits_another_clients_parameters() {
        let server = FakeServer::start().await;
        // A single backend, so the second client is certain to get the one the
        // first client left its search_path on.
        let pool = server.pool(1);

        run_session(pool.clone(), vec![query("SET search_path TO app"), Message::terminate()]).await;
        let (second, _) = run_session(pool.clone(), vec![query("SELECT 1"), Message::terminate()]).await;

        assert_eq!(second.param_syncs, 1, "the second client asked for nothing, so the first one's SET must be undone");
        assert!(
            server.log().iter().any(|sql| sql == "RESET search_path"),
            "leaking a search_path between clients is a correctness bug, not a performance one: {:?}",
            server.log()
        );
    }

    #[tokio::test]
    async fn a_backend_that_already_matches_costs_no_round_trip() {
        let server = FakeServer::start().await;
        let pool = server.pool(1);

        let (outcome, _) = run_session(
            pool.clone(),
            vec![
                query("SET search_path TO app"),
                query("SELECT 1"),
                query("SELECT 2"),
                query("SELECT 3"),
                Message::terminate(),
            ],
        )
        .await;

        assert_eq!(outcome.checkouts, 4);
        assert_eq!(
            outcome.param_syncs, 0,
            "the client keeps landing on the backend it just used, so there is nothing to carry over"
        );
    }

    #[tokio::test]
    async fn startup_parameters_reach_the_backend() {
        // Previously read during the handshake and thrown away, which is why a
        // connection string that set search_path silently did nothing.
        let server = FakeServer::start().await;
        let pool = server.pool(1);

        let params = ClientParams::from_startup(&[
            ("user".into(), "svc_orders".into()),
            ("options".into(), "-c search_path=app".into()),
        ]);
        let (outcome, _) = run_session_with(pool.clone(), params, vec![query("SELECT 1"), Message::terminate()]).await;

        assert_eq!(outcome.param_syncs, 1);
        assert!(server.log().iter().any(|sql| sql == "SET search_path = 'app'"), "got {:?}", server.log());
    }

    #[tokio::test]
    async fn a_set_that_the_server_rejects_is_never_replayed() {
        // Believing a SET before the server accepts it would leave us
        // reapplying a value the client does not have — and failing every
        // checkout from then on.
        let server = FakeServer::start().await;
        let pool = server.pool(1);

        let (outcome, _) =
            run_session(pool.clone(), vec![query("SET search_path TO boom"), query("SELECT 1"), Message::terminate()])
                .await;

        assert_eq!(outcome.pinned, None);
        assert_eq!(outcome.param_syncs, 0, "a failed SET changed nothing, so there is nothing to carry");
        assert!(!server.log().iter().any(|sql| sql.starts_with("RESET")), "and nothing to undo either");
    }

    #[tokio::test]
    async fn a_set_inside_an_open_transaction_still_pins() {
        // A ROLLBACK would undo it, and nothing on the wire distinguishes a
        // transaction that committed from one that did not. SET LOCAL is the
        // idiom here and it is free.
        let server = FakeServer::start().await;
        let pool = server.pool(3);

        let (outcome, _) = run_session(
            pool.clone(),
            vec![query("BEGIN"), query("SET search_path TO app"), query("ROLLBACK"), Message::terminate()],
        )
        .await;

        assert_eq!(outcome.pinned, Some(PinReason::SessionParameter));
    }

    // --- read-only users and kicks ---

    /// Drive a session under a policy, returning the client socket so the test
    /// can keep talking after the script.
    async fn open_policy_session(
        group: Arc<PoolGroup>,
        policy: SessionPolicy,
    ) -> (TcpStream, tokio::task::JoinHandle<ProtoResult<TxnOutcome>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let relay = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut client = MaybeTls::Plain(socket);
            let mut state = SessionState::new(PoolMode::Transaction);
            let mut params = ClientParams::new();
            if policy.read_only {
                params.enforce_read_only();
            }
            transaction_relay_inner(&mut client, &group, &mut state, &mut params, policy, None, None).await
        });

        (TcpStream::connect(addr).await.unwrap(), relay)
    }

    /// Send one simple query and collect reply tags up to ReadyForQuery.
    async fn exchange(client: &mut TcpStream, sql: &str) -> Vec<u8> {
        client.write_all(&query(sql).encode()).await.unwrap();
        let mut tags = Vec::new();
        loop {
            let reply = Message::read(client).await.unwrap();
            tags.push(reply.tag);
            if reply.tag == b'Z' {
                return tags;
            }
        }
    }

    #[tokio::test]
    async fn a_read_only_user_gets_the_guc_and_postgres_does_the_refusing() {
        // havuz does not decide what a write is. It sets the parameter and lets
        // the server apply its own rules, which is the only way a write hidden
        // inside a function is caught.
        let server = FakeServer::start().await;
        let pool = server.pool(2);

        let (mut client, relay) = open_policy_session(
            pool.clone(),
            SessionPolicy { read_only: true, kick: KickSignal::never(), cancel: None },
        )
        .await;

        exchange(&mut client, "SELECT 1").await;
        drop(client);
        relay.await.unwrap().unwrap();

        assert!(
            server.log().iter().any(|sql| sql == "SET default_transaction_read_only = 'on'"),
            "the backend must be told before the client's statement runs: {:?}",
            server.log()
        );
    }

    #[tokio::test]
    async fn a_read_only_user_cannot_make_its_session_writable() {
        // The setting is only a default, so every statement that would override
        // it has to be answered by havuz and never forwarded.
        let server = FakeServer::start().await;
        let pool = server.pool(2);

        let (mut client, relay) = open_policy_session(
            pool.clone(),
            SessionPolicy { read_only: true, kick: KickSignal::never(), cancel: None },
        )
        .await;

        for escape in [
            "SET default_transaction_read_only = off",
            "RESET ALL",
            "BEGIN READ WRITE",
            "SET TRANSACTION READ WRITE",
            "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
        ] {
            let tags = exchange(&mut client, escape).await;
            assert_eq!(tags, vec![b'E', b'Z'], "{escape:?} must be refused, got {tags:?}");
        }

        // An ordinary read is untouched.
        assert_eq!(exchange(&mut client, "SELECT 1").await, vec![b'C', b'Z']);
        drop(client);
        relay.await.unwrap().unwrap();

        let log = server.log();
        assert!(
            !log.iter().any(|sql| sql.to_uppercase().contains("READ WRITE")),
            "no escape attempt may reach the backend: {log:?}"
        );
        assert!(!log.iter().any(|sql| sql == "RESET ALL"), "RESET ALL would clear the setting: {log:?}");
    }

    #[tokio::test]
    async fn an_idle_session_is_kicked_as_soon_as_it_is_signalled() {
        let server = FakeServer::start().await;
        let pool = server.pool(2);
        let registry = havuz_control::SessionRegistry::new();
        let session = registry.register("svc_orders", "app_main", None, "127.0.0.1:5000", 0).unwrap();

        let (mut client, relay) =
            open_policy_session(pool.clone(), SessionPolicy { read_only: false, kick: session.signal(), cancel: None })
                .await;

        // Establish that the session is working before ending it.
        assert_eq!(exchange(&mut client, "SELECT 1").await, vec![b'C', b'Z']);

        assert_eq!(registry.kick_user("svc_orders"), 1);

        // The client learns why it was disconnected rather than seeing the
        // socket simply vanish.
        let goodbye = tokio::time::timeout(Duration::from_secs(2), Message::read(&mut client))
            .await
            .expect("a kicked client must be told promptly")
            .expect("and told, not dropped");
        let fields = goodbye.error_fields();
        assert_eq!(goodbye.tag, b'E');
        assert!(fields.iter().any(|(f, v)| *f == b'C' && v == "57P01"), "got {fields:?}");
        assert!(fields.iter().any(|(f, v)| *f == b'M' && v.contains("administrator command")), "got {fields:?}");

        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_kick_never_returns_a_half_read_backend_to_the_pool() {
        // The whole reason a kick is graceful. If it aborted mid-response, the
        // Checkout would go back on the shelf with unread bytes and the next
        // client would receive the tail of this one's result set.
        let server = FakeServer::start().await;
        let pool = server.pool(1);
        let registry = havuz_control::SessionRegistry::new();
        let session = registry.register("svc_orders", "app_main", None, "127.0.0.1:5000", 0).unwrap();

        let (mut client, relay) =
            open_policy_session(pool.clone(), SessionPolicy { read_only: false, kick: session.signal(), cancel: None })
                .await;
        exchange(&mut client, "SELECT 1").await;

        registry.kick_user("svc_orders");
        let _ = Message::read(&mut client).await;
        relay.await.unwrap().unwrap();

        // The single backend survived, so a later client reuses it rather than
        // paying for a reconnect against a connection we poisoned.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let snapshot = pool.combined_pool_snapshot();
        assert_eq!(snapshot.discarded_total, 0, "the backend was at a message boundary and stayed usable");
        assert_eq!(snapshot.idle, 1);

        let (outcome, _) = run_session(pool.clone(), vec![query("SELECT 2"), Message::terminate()]).await;
        assert_eq!(outcome.exchanges, 1);
        assert_eq!(server.opened(), 1, "the kick cost nobody a reconnect");
    }

    #[tokio::test]
    async fn a_session_kicked_before_it_speaks_still_goes() {
        // The flag is latched, so a kick that lands while the client is silent
        // is not lost.
        let server = FakeServer::start().await;
        let pool = server.pool(1);
        let registry = havuz_control::SessionRegistry::new();
        let session = registry.register("svc_orders", "app_main", None, "127.0.0.1:5000", 0).unwrap();
        registry.kick_user("svc_orders");

        let (mut client, relay) =
            open_policy_session(pool.clone(), SessionPolicy { read_only: false, kick: session.signal(), cancel: None })
                .await;

        let goodbye = tokio::time::timeout(Duration::from_secs(2), Message::read(&mut client))
            .await
            .expect("an already-kicked session must not wait for input")
            .unwrap();
        assert_eq!(goodbye.tag, b'E');
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_unkicked_session_is_never_disturbed() {
        let server = FakeServer::start().await;
        let pool = server.pool(2);
        let registry = havuz_control::SessionRegistry::new();
        let mine = registry.register("svc_orders", "app_main", None, "a", 0).unwrap();
        let _theirs = registry.register("svc_reports", "app_main", None, "b", 0).unwrap();

        let (mut client, relay) =
            open_policy_session(pool.clone(), SessionPolicy { read_only: false, kick: mine.signal(), cancel: None })
                .await;

        // Kicking a different user must leave this session alone.
        assert_eq!(registry.kick_user("svc_reports"), 1);
        assert_eq!(exchange(&mut client, "SELECT 1").await, vec![b'C', b'Z']);
        assert_eq!(exchange(&mut client, "SELECT 2").await, vec![b'C', b'Z']);

        drop(client);
        let outcome = relay.await.unwrap().unwrap();
        assert_eq!(outcome.exchanges, 2);
    }

    // --- cancellation ---

    #[tokio::test]
    async fn the_cancel_key_points_at_the_backend_the_client_is_actually_holding() {
        // The transaction-mode hazard in one test. A key fixed at startup would
        // still name a backend after the client gave it back, so `Ctrl-C` a
        // second later would cancel whatever the next client was running on it.
        let server = FakeServer::start().await;
        let pool = server.pool(2);
        let registry = Arc::new(crate::cancel::CancelRegistry::new());
        let scope = registry.scope();

        let (mut client, relay) = open_policy_session(
            pool.clone(),
            SessionPolicy { read_only: false, kick: KickSignal::never(), cancel: Some(scope.clone()) },
        )
        .await;

        assert_eq!(exchange(&mut client, "SELECT 1").await, vec![b'C', b'Z']);
        assert_eq!(scope.target(), None, "a client between statements holds no backend to cancel");

        assert_eq!(exchange(&mut client, "BEGIN").await, vec![b'C', b'Z']);
        let target = scope.target().expect("an open transaction keeps the backend");
        assert_eq!(target.host, server.addr.ip().to_string(), "the backend's own address, not the pool's name");
        assert_eq!(target.port, server.addr.port(), "and its real port, not zero");
        assert_eq!(target.backend_pid, 4242, "the backend's key pair, as the server reported it");
        assert_eq!(target.backend_secret, 7);

        assert_eq!(exchange(&mut client, "COMMIT").await, vec![b'C', b'Z']);
        assert_eq!(scope.target(), None, "committing gives the backend back and the key must follow");

        drop(client);
        relay.await.unwrap().unwrap();
        assert_eq!(scope.target(), None, "and a finished session cancels nothing at all");
    }

    #[tokio::test]
    async fn a_cancellation_for_an_idle_client_is_dropped_rather_than_delivered() {
        // Doing nothing is the whole point: the alternative is dialling a
        // backend that has moved on.
        let server = FakeServer::start().await;
        let pool = server.pool(1);
        let registry = Arc::new(crate::cancel::CancelRegistry::new());
        let scope = registry.scope();

        let (mut client, relay) = open_policy_session(
            pool.clone(),
            SessionPolicy { read_only: false, kick: KickSignal::never(), cancel: Some(scope.clone()) },
        )
        .await;
        exchange(&mut client, "SELECT 1").await;

        let opened_before = server.opened();
        assert!(scope.cancel().await.is_err(), "there is nothing to cancel");
        assert_eq!(server.opened(), opened_before, "and nothing was dialled to find that out");

        drop(client);
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn changing_the_effective_role_still_pins() {
        let server = FakeServer::start().await;
        let pool = server.pool(3);

        let (outcome, _) =
            run_session(pool.clone(), vec![query("SET ROLE readonly"), query("SELECT 1"), Message::terminate()]).await;

        assert_eq!(
            outcome.pinned,
            Some(PinReason::SessionParameter),
            "replaying a permission change would make a replay bug a privilege leak"
        );
        assert_eq!(outcome.checkouts, 1);
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
            transaction_relay(&mut client, &pool, &mut state, &mut ClientParams::new()).await.unwrap()
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
            transaction_relay(&mut client, &relay_pool, &mut state, &mut ClientParams::new()).await.unwrap()
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
            transaction_relay(&mut client, &pool, &mut state, &mut ClientParams::new()).await.unwrap()
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
            transaction_relay(&mut client, &group, &mut state, &mut ClientParams::new()).await.unwrap()
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
