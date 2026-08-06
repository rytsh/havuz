//! Release decisions.
//!
//! The family inspects wire messages and emits [`FlowEvent`]s. [`SessionState`]
//! folds them into a single question the pool asks after every exchange: can
//! this backend go back on the shelf?

use havuz_registry::PoolMode;

// Defined in `havuz-registry` because the rules that produce one are static
// per-product data, and re-exported here because [`FlowEvent`] is the vocabulary
// families speak and a caller should not need two crates to say one thing.
pub use havuz_registry::PinReason;

/// What a family observed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEvent {
    /// The exchange completed and the server reports no open transaction.
    Idle,
    /// A transaction is open. Includes aborted transactions: the client still
    /// owes us a `ROLLBACK`.
    InTransaction,
    /// Session state was mutated in a way that outlives the transaction.
    MustPin(PinReason),
    /// The connection has entered a streaming mode and message-level
    /// inspection no longer applies.
    Streaming(PinReason),
    /// The backend is unusable and must be discarded rather than recycled.
    Broken,
}

/// Folds [`FlowEvent`]s into a release decision.
///
/// Deliberately tiny and allocation-free: one of these lives per client
/// connection and is touched on every message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    mode: PoolMode,
    in_transaction: bool,
    pin: Option<PinReason>,
    broken: bool,
    /// Statements observed since the last release. Feeds the statistics layer.
    exchanges: u64,
}

impl SessionState {
    pub fn new(mode: PoolMode) -> Self {
        Self { mode, in_transaction: false, pin: None, broken: false, exchanges: 0 }
    }

    pub fn mode(&self) -> PoolMode {
        self.mode
    }

    pub fn in_transaction(&self) -> bool {
        self.in_transaction
    }

    pub fn pin(&self) -> Option<PinReason> {
        self.pin
    }

    pub fn is_broken(&self) -> bool {
        self.broken
    }

    pub fn exchanges(&self) -> u64 {
        self.exchanges
    }

    /// Record an observation.
    pub fn observe(&mut self, event: FlowEvent) {
        self.exchanges = self.exchanges.saturating_add(1);
        match event {
            FlowEvent::Idle => self.in_transaction = false,
            FlowEvent::InTransaction => self.in_transaction = true,
            FlowEvent::MustPin(reason) => {
                // The first reason is the interesting one: it is what actually
                // cost us the multiplexing opportunity. Later ones are noise.
                self.pin.get_or_insert(reason);
            }
            FlowEvent::Streaming(reason) => {
                self.pin.get_or_insert(reason);
            }
            FlowEvent::Broken => self.broken = true,
        }
    }

    /// Can the backend be handed to another client right now?
    pub fn is_releasable(&self) -> bool {
        if self.broken || self.pin.is_some() {
            return false;
        }
        match self.mode {
            // Session mode owns the backend until the client disconnects, so
            // there is never an intermediate release point.
            PoolMode::Session => false,
            PoolMode::Transaction => !self.in_transaction,
            // Statement mode rejects explicit transactions elsewhere; if one is
            // somehow open we still must not release mid-transaction.
            PoolMode::Statement => !self.in_transaction,
        }
    }

    /// Clear per-checkout bookkeeping after a successful release.
    ///
    /// Pins are intentionally *not* cleared: a pinned connection is never
    /// released in the first place, and the pin lasts for the client session.
    pub fn released(&mut self) {
        self.in_transaction = false;
        self.exchanges = 0;
    }

    /// Reset everything for a reused client session.
    pub fn reset(&mut self) {
        let mode = self.mode;
        *self = Self::new(mode);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_mode_never_releases_midstream() {
        let mut state = SessionState::new(PoolMode::Session);
        state.observe(FlowEvent::Idle);
        assert!(!state.is_releasable(), "session mode holds the backend for the whole client session");
    }

    #[test]
    fn transaction_mode_releases_between_transactions() {
        let mut state = SessionState::new(PoolMode::Transaction);

        state.observe(FlowEvent::Idle);
        assert!(state.is_releasable());

        state.observe(FlowEvent::InTransaction);
        assert!(!state.is_releasable(), "must not release mid-transaction");

        state.observe(FlowEvent::Idle);
        assert!(state.is_releasable(), "commit or rollback returns the backend");
    }

    #[test]
    fn a_pin_survives_subsequent_idle_events() {
        let mut state = SessionState::new(PoolMode::Transaction);
        state.observe(FlowEvent::MustPin(PinReason::SessionParameter));
        state.observe(FlowEvent::Idle);

        assert_eq!(state.pin(), Some(PinReason::SessionParameter));
        assert!(!state.is_releasable(), "SET outside a transaction poisons the connection for sharing");
    }

    #[test]
    fn the_first_pin_reason_is_the_one_reported() {
        let mut state = SessionState::new(PoolMode::Transaction);
        state.observe(FlowEvent::MustPin(PinReason::TempTable));
        state.observe(FlowEvent::MustPin(PinReason::Listen));
        assert_eq!(state.pin(), Some(PinReason::TempTable), "later pins do not overwrite the root cause");
    }

    #[test]
    fn broken_backends_are_never_releasable() {
        let mut state = SessionState::new(PoolMode::Transaction);
        state.observe(FlowEvent::Idle);
        assert!(state.is_releasable());

        state.observe(FlowEvent::Broken);
        assert!(!state.is_releasable(), "a broken backend must be discarded, not recycled");
        assert!(state.is_broken());
    }

    #[test]
    fn streaming_pins_for_the_rest_of_the_session() {
        let mut state = SessionState::new(PoolMode::Transaction);
        state.observe(FlowEvent::Streaming(PinReason::BulkTransfer));
        state.observe(FlowEvent::Idle);
        assert_eq!(state.pin(), Some(PinReason::BulkTransfer));
        assert!(!state.is_releasable());
    }

    #[test]
    fn release_clears_transaction_bookkeeping_but_not_the_pin() {
        let mut state = SessionState::new(PoolMode::Transaction);
        state.observe(FlowEvent::InTransaction);
        state.observe(FlowEvent::Idle);
        assert_eq!(state.exchanges(), 2);

        state.released();
        assert_eq!(state.exchanges(), 0);
        assert!(!state.in_transaction());

        state.observe(FlowEvent::MustPin(PinReason::Listen));
        state.released();
        assert_eq!(state.pin(), Some(PinReason::Listen), "a pin belongs to the client session, not the checkout");
    }

    #[test]
    fn reset_returns_a_fresh_state_with_the_same_mode() {
        let mut state = SessionState::new(PoolMode::Transaction);
        state.observe(FlowEvent::MustPin(PinReason::Listen));
        state.observe(FlowEvent::Broken);
        state.reset();

        assert_eq!(state, SessionState::new(PoolMode::Transaction));
        assert!(!state.is_broken());
        assert_eq!(state.pin(), None);
    }

    #[test]
    fn statement_mode_behaves_like_transaction_mode_when_a_transaction_leaks_through() {
        let mut state = SessionState::new(PoolMode::Statement);
        state.observe(FlowEvent::InTransaction);
        assert!(!state.is_releasable(), "never release mid-transaction, whatever the mode claims");
    }

    #[test]
    fn a_realistic_orm_session_stays_multiplexable() {
        // asyncpg-style: BEGIN, a couple of statements, COMMIT, repeat.
        let mut state = SessionState::new(PoolMode::Transaction);
        for _ in 0..3 {
            state.observe(FlowEvent::InTransaction);
            state.observe(FlowEvent::InTransaction);
            state.observe(FlowEvent::Idle);
            assert!(state.is_releasable(), "a well-behaved client releases after every transaction");
            state.released();
        }
        assert_eq!(state.pin(), None);
    }

    #[test]
    fn one_stray_set_costs_the_whole_session() {
        // The exact failure mode operators cannot currently diagnose: a pool
        // configured for transaction mode that behaves like session mode
        // because the driver issues `SET application_name` on connect.
        let mut state = SessionState::new(PoolMode::Transaction);
        state.observe(FlowEvent::MustPin(PinReason::SessionParameter));
        for _ in 0..10 {
            state.observe(FlowEvent::InTransaction);
            state.observe(FlowEvent::Idle);
            assert!(!state.is_releasable());
        }
        assert_eq!(state.pin(), Some(PinReason::SessionParameter));
    }
}
