//! The mempool <-> consensus interface. The mempool is generic over the
//! consensus block type so protocols with different blocks can share it: consensus
//! asks for payload digests to propose (`Get`), asks whether a block's
//! payloads are locally available (`Verify`, with missing payloads synced in
//! the background and the block looped back on arrival), and reports
//! committed digests (`Cleanup`).

use crypto::{Digest, PublicKey};
use tokio::sync::oneshot;

/// What the mempool needs to know about a consensus block.
pub trait MempoolBlock: std::fmt::Debug + Send + Sync + 'static {
    fn digest(&self) -> Digest;
    fn author(&self) -> PublicKey;
    /// Round/sequence number, used only for garbage-collecting pending sync
    /// requests.
    fn round(&self) -> u64;
    fn payload(&self) -> &[Digest];
}

#[derive(Debug)]
pub enum PayloadStatus {
    Accept,
    Reject,
    Wait,
}

#[derive(Debug)]
pub enum ConsensusMempoolMessage<B> {
    Get(usize, oneshot::Sender<Vec<Digest>>),
    Verify(Box<B>, oneshot::Sender<PayloadStatus>),
    Cleanup(Vec<Digest>, u64),
}
