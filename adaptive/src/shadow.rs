//! Follower-side client-latency observation for the `broadcast` client mode.
//!
//! In broadcast mode the client sends every transaction's 9-byte header (see
//! [`crate::ack::TX_TAG_SHADOW`]) to every non-leader front, so each replica
//! learns the true submission time of each transaction from its own clock.
//! The [`ShadowLog`] records those arrivals (and the arrivals of tracked real
//! transactions on the replica that ingests them); the commit path joins
//! committed transaction seqs against it to measure client-perceived latency
//! locally, with no dependence on the leader's cooperation past dissemination.
//!
//! Entries whose transaction never commits (shed under overload, or lost to a
//! faulty leader) are expired by [`ShadowLog::sweep`]; until then they are
//! visible through [`ShadowLog::oldest_age`], which is exactly the live
//! "how stale is the oldest unserved request" gauge a stall produces.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct ShadowLog {
    inner: Mutex<HashMap<u64, Instant>>,
}

impl Default for ShadowLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowLog {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Record the arrival of transaction `seq`. First arrival wins: a shadow
    /// copy racing the tracked real copy (or a duplicate frame) must not
    /// reset the clock.
    pub fn record(&self, seq: u64) {
        self.inner.lock().unwrap().entry(seq).or_insert_with(Instant::now);
    }

    /// Remove and return the arrival instant of a committed transaction.
    /// None if the transaction was never observed here or already taken.
    pub fn take(&self, seq: u64) -> Option<Instant> {
        self.inner.lock().unwrap().remove(&seq)
    }

    /// Age of the oldest still-pending transaction. None when empty.
    pub fn oldest_age(&self) -> Option<Duration> {
        let inner = self.inner.lock().unwrap();
        inner.values().map(|arrival| arrival.elapsed()).max()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// Drop entries older than `expiry` (transactions that will never
    /// commit); returns how many were dropped.
    pub fn sweep(&self, expiry: Duration) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.len();
        inner.retain(|_, arrival| arrival.elapsed() <= expiry);
        before - inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_take_roundtrip() {
        let log = ShadowLog::new();
        log.record(7);
        assert_eq!(log.len(), 1);
        assert!(log.take(7).is_some());
        assert!(log.take(7).is_none());
        assert!(log.is_empty());
    }

    #[test]
    fn first_arrival_wins() {
        let log = ShadowLog::new();
        log.record(1);
        let first = log.take(1).unwrap();
        log.record(1);
        std::thread::sleep(Duration::from_millis(5));
        log.record(1);
        let kept = log.take(1).unwrap();
        // The second record for the same seq must not move the clock.
        assert!(kept.elapsed() >= Duration::from_millis(5));
        let _ = first;
    }

    #[test]
    fn sweep_expires_only_old_entries() {
        let log = ShadowLog::new();
        log.record(1);
        std::thread::sleep(Duration::from_millis(10));
        log.record(2);
        assert_eq!(log.sweep(Duration::from_millis(5)), 1);
        assert!(log.take(1).is_none());
        assert!(log.take(2).is_some());
    }

    #[test]
    fn oldest_age_tracks_the_stalest_entry() {
        let log = ShadowLog::new();
        assert!(log.oldest_age().is_none());
        log.record(1);
        std::thread::sleep(Duration::from_millis(10));
        log.record(2);
        assert!(log.oldest_age().unwrap() >= Duration::from_millis(10));
    }
}
