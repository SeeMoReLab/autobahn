//! Commit-ack plumbing between the transaction-ingesting component (worker /
//! mempool front) and the benchmark client.
//!
//! Wire formats:
//! - A transaction is `[tag u8][seq u64 BE][padding...]` (at least 9 bytes),
//!   the same layout the original artifact clients used. `seq` is unique per
//!   client connection.
//! - An ack frame (sent back on the same length-delimited TCP connection the
//!   client submits on) is a concatenation of the committed `seq` values, each
//!   u64 BE.
//!
//! The ingesting component assigns each inbound client connection a
//! [`ConnId`], registers its outbound half in the [`AckRouter`], parses the
//! seq out of each transaction, and records `(digest -> [(conn, seq)])` in the
//! [`AckIndex`] when it seals a batch. The commit path calls
//! [`AckIndex::take`] + [`AckRouter::ack`] for every committed batch digest.

use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use tokio::sync::mpsc;

pub type ConnId = u64;

/// Minimum transaction size: tag byte + u64 sequence.
pub const TX_HEADER_BYTES: usize = 9;

/// Parse the per-connection sequence number out of a transaction.
pub fn tx_seq(tx: &[u8]) -> Option<u64> {
    if tx.len() < TX_HEADER_BYTES {
        return None;
    }
    Some(u64::from_be_bytes(tx[1..9].try_into().unwrap()))
}

/// Encode a batch of acked seqs into one frame payload.
pub fn encode_ack_frame(seqs: &[u64]) -> Bytes {
    let mut buf = Vec::with_capacity(seqs.len() * 8);
    for seq in seqs {
        buf.extend_from_slice(&seq.to_be_bytes());
    }
    Bytes::from(buf)
}

/// Tag byte of a leader-hint frame. A hint frame is 17 bytes
/// (`[0xFF][view u64 BE][replica_id u64 BE]`), distinguishable from ack
/// frames, whose length is always a multiple of 8.
pub const LEADER_HINT_TAG: u8 = 0xFF;

/// Encode a leader hint: the sending replica's current view and the replica
/// id (client_targets.txt order) of that view's leader. Pushed on client
/// connections so a leader-targeting client can follow elections. Carrying
/// the view lets the client rank hints and ignore claims from replicas that
/// are behind.
pub fn encode_leader_hint(view: u64, replica_id: u64) -> Bytes {
    let mut buf = Vec::with_capacity(17);
    buf.push(LEADER_HINT_TAG);
    buf.extend_from_slice(&view.to_be_bytes());
    buf.extend_from_slice(&replica_id.to_be_bytes());
    Bytes::from(buf)
}

/// Decode a leader hint into `(view, replica_id)`; None if the frame is not
/// hint-shaped.
pub fn decode_leader_hint(frame: &[u8]) -> Option<(u64, u64)> {
    if frame.len() == 17 && frame[0] == LEADER_HINT_TAG {
        let view = u64::from_be_bytes(frame[1..9].try_into().unwrap());
        let replica = u64::from_be_bytes(frame[9..17].try_into().unwrap());
        Some((view, replica))
    } else {
        None
    }
}

/// Decode an ack frame back into seqs. Errors on a malformed length.
pub fn decode_ack_frame(frame: &[u8]) -> Result<Vec<u64>, String> {
    if frame.len() % 8 != 0 {
        return Err(format!("ack frame length {} not a multiple of 8", frame.len()));
    }
    Ok(frame
        .chunks_exact(8)
        .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
        .collect())
}

/// Batch digest -> the client txs it contains. Bounded: when more than
/// `capacity` digests are pending (batches created but never observed as
/// committed), the oldest entries are dropped; their txs then surface as
/// client-side timeouts, which is the correct signal for a batch that never
/// committed.
pub struct AckIndex {
    capacity: usize,
    inner: Mutex<AckIndexInner>,
}

struct AckIndexInner {
    by_digest: HashMap<[u8; 32], Vec<(ConnId, u64)>>,
    order: VecDeque<[u8; 32]>,
}

impl AckIndex {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "AckIndex capacity must be positive");
        Self {
            capacity,
            inner: Mutex::new(AckIndexInner {
                by_digest: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    pub fn register(&self, digest: [u8; 32], txs: Vec<(ConnId, u64)>) {
        if txs.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if inner.by_digest.insert(digest, txs).is_none() {
            inner.order.push_back(digest);
        }
        while inner.order.len() > self.capacity {
            let evicted = inner.order.pop_front().unwrap();
            inner.by_digest.remove(&evicted);
            log::warn!(
                "AckIndex over capacity; dropped pending batch {} (its txs will time out client-side)",
                hex_prefix(&evicted)
            );
        }
    }

    /// Remove and return the txs for a committed digest. None if the digest
    /// is unknown (not locally created, already taken, or evicted).
    pub fn take(&self, digest: &[u8; 32]) -> Option<Vec<(ConnId, u64)>> {
        let mut inner = self.inner.lock().unwrap();
        let txs = inner.by_digest.remove(digest)?;
        // Lazy removal from `order`: entries already taken are skipped during
        // eviction; keeping them costs 32 bytes each until they age out.
        Some(txs)
    }
}

fn hex_prefix(digest: &[u8; 32]) -> String {
    digest[..8].iter().map(|b| format!("{:02x}", b)).collect()
}

/// Registry of live client connections' outbound ack senders.
#[derive(Default)]
pub struct AckRouter {
    conns: Mutex<HashMap<ConnId, mpsc::UnboundedSender<Bytes>>>,
}

impl AckRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, conn: ConnId, sender: mpsc::UnboundedSender<Bytes>) {
        self.conns.lock().unwrap().insert(conn, sender);
    }

    pub fn deregister(&self, conn: ConnId) {
        self.conns.lock().unwrap().remove(&conn);
    }

    /// Push one frame to every live client connection (leader hints).
    pub fn broadcast(&self, frame: Bytes) {
        let conns = self.conns.lock().unwrap();
        for sender in conns.values() {
            let _ = sender.send(frame.clone());
        }
    }

    /// Route acks for one committed batch, grouped per connection. Acks to
    /// closed connections are dropped silently (the client is gone).
    pub fn ack(&self, txs: &[(ConnId, u64)]) {
        let mut per_conn: HashMap<ConnId, Vec<u64>> = HashMap::new();
        for (conn, seq) in txs {
            per_conn.entry(*conn).or_default().push(*seq);
        }
        let conns = self.conns.lock().unwrap();
        for (conn, seqs) in per_conn {
            if let Some(sender) = conns.get(&conn) {
                let _ = sender.send(encode_ack_frame(&seqs));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_seq_roundtrip() {
        let mut tx = vec![1u8];
        tx.extend_from_slice(&42u64.to_be_bytes());
        tx.resize(64, 0);
        assert_eq!(tx_seq(&tx), Some(42));
        assert_eq!(tx_seq(&[0u8; 8]), None);
    }

    #[test]
    fn leader_hint_roundtrip() {
        let frame = encode_leader_hint(15, 2);
        assert_eq!(decode_leader_hint(&frame), Some((15, 2)));
        // Ack frames (multiples of 8 bytes) must never parse as hints.
        assert_eq!(decode_leader_hint(&encode_ack_frame(&[1, 2])), None);
        assert_eq!(decode_leader_hint(&frame[..9]), None);
    }

    #[test]
    fn ack_frame_roundtrip() {
        let seqs = vec![1u64, 7, u64::MAX];
        let frame = encode_ack_frame(&seqs);
        assert_eq!(decode_ack_frame(&frame).unwrap(), seqs);
        assert!(decode_ack_frame(&frame[..frame.len() - 1]).is_err());
    }

    #[test]
    fn index_take_and_eviction() {
        let index = AckIndex::new(2);
        index.register([1u8; 32], vec![(1, 1)]);
        index.register([2u8; 32], vec![(1, 2)]);
        index.register([3u8; 32], vec![(1, 3)]); // evicts digest [1;32]
        assert!(index.take(&[1u8; 32]).is_none());
        assert_eq!(index.take(&[2u8; 32]), Some(vec![(1, 2)]));
        assert!(index.take(&[2u8; 32]).is_none());
        assert_eq!(index.take(&[3u8; 32]), Some(vec![(1, 3)]));
    }

    #[test]
    fn router_groups_by_connection() {
        let router = AckRouter::new();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        router.register(1, tx1);
        router.register(2, tx2);
        router.ack(&[(1, 10), (2, 20), (1, 11), (3, 30)]);
        let frame1 = rx1.try_recv().unwrap();
        let mut seqs1 = decode_ack_frame(&frame1).unwrap();
        seqs1.sort_unstable();
        assert_eq!(seqs1, vec![10, 11]);
        let frame2 = rx2.try_recv().unwrap();
        assert_eq!(decode_ack_frame(&frame2).unwrap(), vec![20]);
    }
}
