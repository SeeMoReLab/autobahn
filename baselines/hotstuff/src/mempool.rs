use crate::core::{ConsensusMessage, RoundNumber};
use crate::messages::Block;
use ::mempool::{ConsensusMempoolMessage, MempoolBlock, PayloadStatus};
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, warn};
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;

impl MempoolBlock for Block {
    fn digest(&self) -> Digest {
        crypto::Hash::digest(self)
    }

    fn author(&self) -> PublicKey {
        self.author
    }

    fn round(&self) -> u64 {
        self.round
    }

    fn payload(&self) -> &[Digest] {
        &self.payload
    }
}

/// Mediates the core's requests to the mempool. The core's event loop must
/// never park waiting for a mempool reply: under overload the mempool can be
/// momentarily blocked on channels that only the core drains, so an inline
/// wait closes a deadlock cycle across tasks. Every round trip here is
/// therefore waited on by a spawned task that feeds the result back through
/// the core's own message loop.
/// A completed payload fetch for a proposal: (round requested for, the TC
/// justifying the proposal if any, payload digests). Delivered on a channel
/// internal to the consensus task set - never on the wire - so a remote peer
/// cannot inject one.
pub type ProposalPayload = (RoundNumber, Option<crate::messages::TC>, Vec<Digest>);

pub struct MempoolDriver {
    mempool_channel: Sender<ConsensusMempoolMessage<Block>>,
    core_channel: Sender<ConsensusMessage>,
    payload_channel: Sender<ProposalPayload>,
}

impl MempoolDriver {
    pub fn new(
        mempool_channel: Sender<ConsensusMempoolMessage<Block>>,
        core_channel: Sender<ConsensusMessage>,
        payload_channel: Sender<ProposalPayload>,
    ) -> Self {
        Self {
            mempool_channel,
            core_channel,
            payload_channel,
        }
    }

    /// Ask the mempool for payload digests to propose; the reply reaches the
    /// core on its internal proposal-payload channel.
    pub fn get(&mut self, max: usize, round: RoundNumber, tc: Option<crate::messages::TC>) {
        let mempool_channel = self.mempool_channel.clone();
        let payload_channel = self.payload_channel.clone();
        tokio::spawn(async move {
            let (sender, receiver) = oneshot::channel();
            let payload = if mempool_channel
                .send(ConsensusMempoolMessage::Get(max, sender))
                .await
                .is_err()
            {
                Vec::new()
            } else {
                receiver.await.unwrap_or_default()
            };
            let _ = payload_channel.send((round, tc, payload)).await;
        });
    }

    /// Check payload availability for a proposed block. Always defers: on
    /// Accept the block re-enters the core as a LoopBack (same path the
    /// mempool synchronizer uses after syncing missing payloads on Wait).
    pub fn verify(&mut self, block: Block) {
        let mempool_channel = self.mempool_channel.clone();
        let core_channel = self.core_channel.clone();
        tokio::spawn(async move {
            let (sender, receiver) = oneshot::channel();
            let message = ConsensusMempoolMessage::Verify(Box::new(block.clone()), sender);
            if mempool_channel.send(message).await.is_err() {
                return;
            }
            match receiver.await {
                Ok(PayloadStatus::Accept) => {
                    let _ = core_channel.send(ConsensusMessage::LoopBack(block)).await;
                }
                Ok(PayloadStatus::Wait) => {
                    debug!(
                        "Processing of block round {} suspended: missing payload",
                        block.round
                    );
                }
                Ok(PayloadStatus::Reject) => warn!("Rejected payload for {:?}", block),
                Err(_) => (),
            }
        });
    }

    pub async fn cleanup(&mut self, b0: &Block, b1: &Block, b2: &Block, block: &Block) {
        let digests = b0
            .payload
            .iter()
            .cloned()
            .chain(b1.payload.iter().cloned())
            .chain(b2.payload.iter().cloned())
            .chain(block.payload.iter().cloned())
            .collect();
        let message = ConsensusMempoolMessage::Cleanup(digests, block.round);
        self.mempool_channel
            .send(message)
            .await
            .expect("Failed to send message to mempool");
    }
}
