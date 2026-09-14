//! Per-request bookkeeping for the `broadcast` client mode: client-latency
//! observation and replicas-reply-to-client acks.
//!
//! In broadcast mode the client sends every transaction to every front -
//! the full transaction tagged [`crate::ack::TX_TAG_TRACKED`] to the adopted
//! leader (sealed into payloads) and a 9-byte shadow header tagged
//! [`crate::ack::TX_TAG_SHADOW`] to every other front (recorded here, never
//! sealed). That first broadcast gives each replica, from its own clock and
//! its own client connection:
//!
//! - the true arrival time of every request (client-perceived latency and
//!   the oldest-pending stall gauge);
//! - the connection to ack the client on when the request commits, from any
//!   replica (replicas-reply-to-client).
//!
//! When a request stays unacked for the client's retry timeout, the client
//! re-broadcasts it, tagged [`crate::ack::TX_TAG_RETRY_REAL`] on the adopted
//! leader's copy (sealable, so a request the leader shed or never received
//! is re-delivered) and [`crate::ack::TX_TAG_RETRY_SHADOW`] elsewhere. A
//! retried real copy is sealed only if the request is not already in the
//! ordering pipeline anywhere; a retried shadow is recorded like a first
//! shadow when the request is unknown here and is otherwise a no-op.
//!
//! Entry lifecycle: recorded at ingest, resolved (removed) at commit, swept
//! when the entry outlives the expiry passed to [`ShadowLog::sweep`].

use crate::ack::ConnId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    conn: ConnId,
    arrival: Instant,
    /// This replica sealed the request into a payload (tracked real copy):
    /// duplicate ingests (a retry racing the original) are dropped.
    sealed_here: bool,
    /// Seen inside a sealed payload (own or disseminated): the request is in
    /// the ordering pipeline and any leader will propose it. Never cleared:
    /// payloads are stored durably and re-proposed across views.
    pipelined: bool,
}

pub struct ShadowLog {
    inner: Mutex<HashMap<u64, Entry>>,
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

    /// Record the ingest of a tracked real transaction (about to be sealed).
    /// Returns false if this replica already sealed this seq - the caller
    /// must drop the transaction (duplicate: a retry raced the original).
    /// The original arrival instant is kept when a shadow entry already
    /// exists, so latency stays measured from first knowledge.
    pub fn record_real(&self, seq: u64, conn: ConnId) -> bool {
        let mut map = self.inner.lock().unwrap();
        Self::seal_or_dedup(&mut map, seq, conn)
    }

    /// Record the arrival of a shadow copy, first or retried. First arrival
    /// wins; duplicates never reset the clock. A retried shadow for a
    /// request unknown here (its first copy was lost, or this front was
    /// dropped from shadowing) is recorded with the retry as its arrival.
    pub fn record_shadow(&self, seq: u64, conn: ConnId) {
        let mut map = self.inner.lock().unwrap();
        if !map.contains_key(&seq) {
            map.insert(seq, Self::fresh(conn, Instant::now()));
        }
    }

    /// Record a retried real transaction (the adopted leader's copy) and
    /// return whether the caller should seal it: false if this replica
    /// already sealed the seq or has seen it in any payload (it is in the
    /// pipeline; sealing it again would commit it twice).
    pub fn record_retry_real(&self, seq: u64, conn: ConnId) -> bool {
        let mut map = self.inner.lock().unwrap();
        if map.get(&seq).is_some_and(|entry| entry.pipelined) {
            return false;
        }
        Self::seal_or_dedup(&mut map, seq, conn)
    }

    fn fresh(conn: ConnId, arrival: Instant) -> Entry {
        Entry {
            conn,
            arrival,
            sealed_here: false,
            pipelined: false,
        }
    }

    /// Mark the seq sealed here, or report a duplicate.
    fn seal_or_dedup(map: &mut HashMap<u64, Entry>, seq: u64, conn: ConnId) -> bool {
        match map.get_mut(&seq) {
            Some(entry) if entry.sealed_here => false,
            Some(entry) => {
                entry.sealed_here = true;
                entry.conn = conn;
                true
            }
            None => {
                let mut entry = Self::fresh(conn, Instant::now());
                entry.sealed_here = true;
                map.insert(seq, entry);
                true
            }
        }
    }

    /// Mark a request as present in a sealed payload (own or disseminated):
    /// it is in the ordering pipeline, so a retry must not seal it again.
    pub fn mark_pipelined(&self, seq: u64) {
        if let Some(entry) = self.inner.lock().unwrap().get_mut(&seq) {
            entry.pipelined = true;
        }
    }

    /// Remove the entry for a request this replica shed before dissemination
    /// (its transactions will never commit from here); a retry can then be
    /// re-ingested as fresh.
    pub fn remove(&self, seq: u64) {
        self.inner.lock().unwrap().remove(&seq);
    }

    /// Resolve a committed transaction: returns the client connection to ack
    /// and the arrival instant for the latency sample. None if the seq was
    /// never observed here or already resolved.
    pub fn take(&self, seq: u64) -> Option<(ConnId, Instant)> {
        self.inner
            .lock()
            .unwrap()
            .remove(&seq)
            .map(|entry| (entry.conn, entry.arrival))
    }

    /// Age of the oldest pending request (stats gauge; 1Hz reporter only,
    /// so the full scan is fine).
    pub fn oldest_age(&self) -> Option<Duration> {
        let map = self.inner.lock().unwrap();
        map.values().map(|entry| entry.arrival.elapsed()).max()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// Drop entries older than `expiry` (their transactions will never
    /// commit); returns how many were dropped. Runs every few seconds from
    /// the reporter.
    pub fn sweep(&self, expiry: Duration) -> usize {
        let mut map = self.inner.lock().unwrap();
        let before = map.len();
        map.retain(|_, entry| entry.arrival.elapsed() <= expiry);
        before - map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_take_roundtrip() {
        let log = ShadowLog::new();
        log.record_shadow(7, 3);
        assert_eq!(log.len(), 1);
        let (conn, _) = log.take(7).unwrap();
        assert_eq!(conn, 3);
        assert!(log.take(7).is_none());
        assert!(log.is_empty());
    }

    #[test]
    fn first_arrival_wins() {
        let log = ShadowLog::new();
        log.record_shadow(1, 1);
        std::thread::sleep(Duration::from_millis(5));
        log.record_shadow(1, 2);
        let (conn, arrival) = log.take(1).unwrap();
        assert_eq!(conn, 1);
        assert!(arrival.elapsed() >= Duration::from_millis(5));
    }

    #[test]
    fn real_ingest_dedups_only_after_sealing() {
        let log = ShadowLog::new();
        assert!(log.record_real(1, 1));
        // The retry racing the original is dropped.
        assert!(!log.record_retry_real(1, 2));
        // A shadow-held entry upgrades to sealed exactly once.
        log.record_shadow(2, 3);
        assert!(log.record_retry_real(2, 4));
        assert!(!log.record_retry_real(2, 5));
        // After a shed, re-ingest is fresh again.
        log.remove(1);
        assert!(log.record_retry_real(1, 6));
    }

    #[test]
    fn pipelined_request_is_never_resealed() {
        let log = ShadowLog::new();
        log.record_shadow(1, 1);
        log.mark_pipelined(1);
        assert!(!log.record_retry_real(1, 2));
        // The entry stays pending for the latency sample and the ack.
        assert_eq!(log.take(1).map(|(conn, _)| conn), Some(1));
    }

    #[test]
    fn unknown_retry_is_recorded_from_the_retry() {
        let log = ShadowLog::new();
        log.record_shadow(9, 4);
        assert_eq!(log.len(), 1);
        assert_eq!(log.take(9).map(|(conn, _)| conn), Some(4));
    }

    #[test]
    fn sweep_drops_only_expired_entries() {
        let log = ShadowLog::new();
        log.record_shadow(1, 1);
        std::thread::sleep(Duration::from_millis(10));
        log.record_shadow(2, 1);
        assert_eq!(log.sweep(Duration::from_millis(5)), 1);
        assert_eq!(log.len(), 1);
        assert!(log.take(2).is_some());
    }
}
