use adaptive::ack::tx_seq;
use adaptive::shadow::ShadowLog;
use std::sync::Arc;
use crate::config::{Committee, Parameters};
use crate::error::{MempoolError, MempoolResult};
use crate::messages::Payload;
use crate::payload::PayloadMaker;
use crate::interface::{ConsensusMempoolMessage, MempoolBlock, PayloadStatus};
use crate::synchronizer::Synchronizer;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
#[cfg(feature = "benchmark")]
use log::info;
use log::{error, warn};
use network::NetMessage;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
#[cfg(feature = "benchmark")]
use std::convert::TryInto as _;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

#[derive(Deserialize, Serialize, Debug)]
pub enum MempoolMessage {
    OwnPayload(Payload),
    Payload(Payload),
    PayloadRequest(Vec<Digest>, PublicKey),
}

pub struct Core<B: MempoolBlock> {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    store: Store,
    synchronizer: Synchronizer<B>,
    payload_maker: PayloadMaker,
    core_channel: Receiver<MempoolMessage>,
    consensus_channel: Receiver<ConsensusMempoolMessage<B>>,
    network_channel: Sender<NetMessage>,
    /// Sealed payloads awaiting inclusion: digest -> (transaction count,
    /// arrival instant).
    queued: HashMap<Digest, (usize, Instant)>,
    /// Arrival order for fair, oldest-first inclusion. Entries whose digest
    /// is no longer in `queued` (committed or already proposed) are skipped
    /// lazily.
    order: VecDeque<Digest>,
    /// Total transactions across `queued`, for the intake bound.
    queued_transactions: usize,
    /// Broadcast-mode request bookkeeping: every stored payload marks its
    /// requests pipelined (a client retry must not seal them again), and
    /// shed own payloads drop their entries (a retry re-ingests them).
    shadow_log: Arc<ShadowLog>,
}

impl<B: MempoolBlock> Core<B> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        store: Store,
        synchronizer: Synchronizer<B>,
        payload_maker: PayloadMaker,
        core_channel: Receiver<MempoolMessage>,
        consensus_channel: Receiver<ConsensusMempoolMessage<B>>,
        network_channel: Sender<NetMessage>,
        shadow_log: Arc<ShadowLog>,
    ) -> Self {
        Self {
            name,
            committee,
            parameters,
            store,
            synchronizer,
            core_channel,
            consensus_channel,
            network_channel,
            queued: HashMap::new(),
            order: VecDeque::new(),
            queued_transactions: 0,
            payload_maker,
            shadow_log,
        }
    }

    /// Mark a stored payload's requests as in the ordering pipeline.
    fn mark_pipelined(&self, payload: &Payload) {
        for tx in &payload.transactions {
            if let Some(seq) = tx_seq(tx) {
                self.shadow_log.mark_pipelined(seq);
            }
        }
    }

    fn queue_insert(&mut self, digest: Digest, transactions: usize) {
        if self
            .queued
            .insert(digest.clone(), (transactions, Instant::now()))
            .is_none()
        {
            self.order.push_back(digest);
            self.queued_transactions += transactions;
        }
    }

    fn queue_remove(&mut self, digest: &Digest) {
        if let Some((transactions, _)) = self.queued.remove(digest) {
            self.queued_transactions -= transactions;
        }
    }

    /// Age of the oldest pending payload (pruning dead order entries).
    fn queue_age(&mut self) -> Duration {
        while let Some(front) = self.order.front() {
            match self.queued.get(front) {
                Some((_, queued_at)) => return queued_at.elapsed(),
                None => {
                    self.order.pop_front();
                }
            }
        }
        Duration::ZERO
    }

    async fn store_payload(&mut self, key: Vec<u8>, payload: &Payload) {
        let value = bincode::serialize(payload).expect("Failed to serialize payload");
        self.store.write(key, value).await;
    }

    async fn transmit(
        &mut self,
        message: &MempoolMessage,
        to: Option<&PublicKey>,
    ) -> MempoolResult<()> {
        crate::synchronizer::transmit(
            message,
            &self.name,
            to,
            &self.committee,
            &self.network_channel,
        )
        .await
    }

    async fn process_own_payload(
        &mut self,
        digest: &Digest,
        payload: Payload,
    ) -> MempoolResult<()> {
        #[cfg(feature = "benchmark")]
        // NOTE: This log entry is used to compute performance.
        info!("Payload {:?} contains {} B", digest, payload.size());

        #[cfg(feature = "benchmark")]
        for tx in &payload.transactions {
            // Look for sample txs (they all start with 0) and gather their
            // txs id (the next 8 bytes).
            if tx[0] == 0u8 && tx.len() > 8 {
                if let Ok(id) = tx[1..9].try_into() {
                    // NOTE: This log entry is used to compute performance.
                    info!(
                        "Payload {:?} contains sample tx {}",
                        digest,
                        u64::from_be_bytes(id)
                    );
                }
            }
        }

        // Store the payload.
        self.store_payload(digest.to_vec(), &payload).await;

        // Share the payload with all other nodes.
        let message = MempoolMessage::Payload(payload);
        self.transmit(&message, None).await
    }

    async fn handle_own_payload(&mut self, payload: Payload) -> MempoolResult<()> {
        // Shed our own intake when the pending backlog is too large. This
        // bounds the queueing delay committed transactions experience under
        // overload and avoids broadcasting payloads that could not commit
        // before the clients' request timeout anyway. The payload is
        // dropped before it is stored or broadcast; peers' payloads are
        // never shed here.
        // The age bound is the load-independent one: whatever we add now
        // waits at least as long as the current oldest payload has.
        let shed = self.queued_transactions >= self.parameters.max_queued_transactions
            || self.queue_age() > Duration::from_millis(self.parameters.max_queue_delay);
        if shed {
            // The shed transactions will never commit from here: drop their
            // entries so the client's retry is re-ingested as fresh instead
            // of deduplicated, and the pending gauge stays honest.
            for tx in &payload.transactions {
                if let Some(seq) = tx_seq(tx) {
                    self.shadow_log.remove(seq);
                }
            }
            return Err(MempoolError::MempoolFull);
        }

        let transactions = payload.transactions.len();
        let digest = payload.digest();
        self.mark_pipelined(&payload);
        self.process_own_payload(&digest, payload).await?;
        self.queue_insert(digest, transactions);
        Ok(())
    }

    async fn handle_others_payload(&mut self, payload: Payload) -> MempoolResult<()> {
        // Ensure the author of the payload is in the committee.
        let author = payload.author;
        ensure!(
            self.committee.exists(&author),
            MempoolError::UnknownAuthority(author)
        );

        // Verify that the payload does not exceed the maximum size.
        ensure!(
            payload.size() <= self.parameters.max_payload_size,
            MempoolError::PayloadTooBig
        );

        // Verify that the payload is correctly signed.
        let digest = payload.digest();
        payload.signature.verify(&digest, &author)?;

        // Store payload.
        // TODO [issue #18]: A bad node may make us store a lot of junk. There is no
        // limit to how many payloads they can send us, and we will store them all.
        let transactions = payload.transactions.len();
        self.store_payload(digest.to_vec(), &payload).await;
        self.mark_pipelined(&payload);

        // Add the payload to the queue.
        self.queue_insert(digest, transactions);
        Ok(())
    }

    async fn handle_request(
        &mut self,
        digests: Vec<Digest>,
        requestor: PublicKey,
    ) -> MempoolResult<()> {
        for digest in &digests {
            if let Some(bytes) = self.store.read(digest.to_vec()).await? {
                let payload = bincode::deserialize(&bytes)?;
                let message = MempoolMessage::Payload(payload);
                self.transmit(&message, Some(&requestor)).await?;
            }
        }
        Ok(())
    }

    async fn get_payload(&mut self, max: usize) -> MempoolResult<Vec<Digest>> {
        if self.queued.is_empty() {
            if let Some(payload) = self.payload_maker.make().await {
                let digest = payload.digest();
                self.process_own_payload(&digest, payload).await?;
                Ok(vec![digest])
            } else {
                Ok(Vec::new())
            }
        } else {
            // Oldest first, so no payload can starve behind newer ones.
            let digest_len = Digest::default().size();
            let limit = max / digest_len;
            let mut digests = Vec::new();
            while digests.len() < limit {
                let Some(digest) = self.order.pop_front() else {
                    break;
                };
                if let Some((transactions, _)) = self.queued.remove(&digest) {
                    self.queued_transactions -= transactions;
                    digests.push(digest);
                }
            }
            Ok(digests)
        }
    }

    async fn verify_payload(&mut self, block: Box<B>) -> MempoolResult<bool> {
        self.synchronizer.verify_payload(*block).await
    }

    async fn cleanup(&mut self, digests: Vec<Digest>, round: u64) {
        self.synchronizer.cleanup(round).await;
        for x in &digests {
            self.queue_remove(x);
        }
        // Compact the lazily-pruned order list if it accumulated too many
        // dead entries.
        if self.order.len() > 2 * self.queued.len() + 1000 {
            let queued = &self.queued;
            self.order.retain(|digest| queued.contains_key(digest));
        }
    }

    pub async fn run(&mut self) {
        let log = |result: Result<&(), &MempoolError>| match result {
            Ok(()) => (),
            Err(MempoolError::StoreError(e)) => error!("{}", e),
            Err(MempoolError::SerializationError(e)) => error!("Store corrupted. {}", e),
            Err(e) => warn!("{}", e),
        };

        loop {
            let result = tokio::select! {
                Some(message) = self.core_channel.recv() => {
                    match message {
                        MempoolMessage::OwnPayload(payload) => self.handle_own_payload(payload).await,
                        MempoolMessage::Payload(payload) => self.handle_others_payload(payload).await,
                        MempoolMessage::PayloadRequest(digest, sender) => self.handle_request(digest, sender).await,
                    }
                },
                Some(message) = self.consensus_channel.recv() => {
                    match message {
                        ConsensusMempoolMessage::Get(max, sender) => {
                            let result = self.get_payload(max).await;
                            log(result.as_ref().map(|_| &()));
                            let _ = sender.send(result.unwrap_or_default());
                        },
                        ConsensusMempoolMessage::Verify(block, sender) => {
                            let result = self.verify_payload(block).await;
                            log(result.as_ref().map(|_| &()));
                            let status = match result {
                                Ok(true) => PayloadStatus::Accept,
                                Ok(false) => PayloadStatus::Wait,
                                Err(_) => PayloadStatus::Reject,
                            };
                            let _ = sender.send(status);
                        },
                        ConsensusMempoolMessage::Cleanup(digests, round) => self.cleanup(digests, round).await,
                    }
                    Ok(())
                },
                else => break,
            };
            log(result.as_ref());
        }
    }
}
