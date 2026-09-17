use crate::aggregator::Aggregator;
use crate::config::{Committee, Parameters};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::{Block, Timeout, Vote, QC, TC};
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use adaptive::episode::LearningManager;
use adaptive::failure::FaultController;
use adaptive::timeouts::TimeoutCell;
use async_recursion::async_recursion;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::NetMessage;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub type RoundNumber = u64;

/// A committed block plus the local timing needed to compute consensus
/// latency in the application layer.
#[derive(Debug)]
pub struct CommittedBlock {
    pub block: Block,
    /// When this replica first processed the block's proposal (None if the
    /// block was only obtained during ancestor sync).
    pub first_seen: Option<Instant>,
    pub committed_at: Instant,
}

/// Adaptive-timer instrumentation for the consensus core: the runtime
/// timeout knob, learning-event recording, and protocol failure injection.
/// Replica ids are the harness's global 0-based ids (see the failure spec).
pub struct Instrumentation {
    pub timeout_cell: TimeoutCell,
    pub learning: Option<Arc<LearningManager>>,
    /// Protocol fault injection (proposal delays keyed by this replica's
    /// global id).
    pub faults: Arc<FaultController>,
    pub replica_id: u32,
    pub replica_of: HashMap<PublicKey, u32>,
}

impl Instrumentation {
    /// No learning, no failure injection; the timeout cell is fixed at
    /// `timeout_delay_ms`. Used by tests and non-adaptive runs.
    pub fn disabled(timeout_delay_ms: u64) -> Self {
        Self {
            timeout_cell: TimeoutCell::new(std::time::Duration::from_millis(timeout_delay_ms)),
            learning: None,
            faults: Arc::new(FaultController::disabled()),
            replica_id: 0,
            replica_of: HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ConsensusMessage {
    Propose(Block),
    Vote(Vote),
    Timeout(Timeout),
    TC(TC),
    LoopBack(Block),
    SyncRequest(Digest, PublicKey),
}

pub struct Core {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    store: Store,
    signature_service: SignatureService,
    leader_elector: LeaderElector,
    mempool_driver: MempoolDriver,
    synchronizer: Synchronizer,
    core_channel: Receiver<ConsensusMessage>,
    network_channel: Sender<NetMessage>,
    commit_channel: Sender<CommittedBlock>,
    round: RoundNumber,
    last_voted_round: RoundNumber,
    preferred_round: RoundNumber,
    last_committed_round: RoundNumber,
    high_qc: QC,
    timer: Timer,
    aggregator: Aggregator,
    instrumentation: Instrumentation,
    first_seen: HashMap<Digest, Instant>,
    commits_since_last_timeout: u64,
    /// Completed payload fetches for proposals, fed by MempoolDriver::get
    /// waiter tasks (never by the network).
    rx_payload: Receiver<crate::mempool::ProposalPayload>,
    /// The round a payload fetch is outstanding for, to avoid stacking. It
    /// stays set while an injected proposal delay is pending, so no second
    /// fetch (and no second block) is produced for that round.
    payload_inflight: Option<RoundNumber>,
    /// Fault injection: proposals whose injected delay has elapsed, fed back
    /// by the sleep tasks spawned in complete_proposal so the core never
    /// blocks and keeps voting while its own proposal is held.
    tx_delayed_proposal: Sender<crate::mempool::ProposalPayload>,
    rx_delayed_proposal: Receiver<crate::mempool::ProposalPayload>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        signature_service: SignatureService,
        store: Store,
        leader_elector: LeaderElector,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        core_channel: Receiver<ConsensusMessage>,
        rx_payload: Receiver<crate::mempool::ProposalPayload>,
        network_channel: Sender<NetMessage>,
        commit_channel: Sender<CommittedBlock>,
        instrumentation: Instrumentation,
    ) -> Self {
        let aggregator = Aggregator::new(committee.clone());
        let timer = Timer::new(parameters.timeout_delay);
        let (tx_delayed_proposal, rx_delayed_proposal) = tokio::sync::mpsc::channel(100);
        Self {
            name,
            committee,
            parameters,
            signature_service,
            store,
            leader_elector,
            mempool_driver,
            synchronizer,
            network_channel,
            commit_channel,
            core_channel,
            round: 1,
            last_voted_round: 0,
            preferred_round: 0,
            last_committed_round: 0,
            high_qc: QC::genesis(),
            timer,
            aggregator,
            instrumentation,
            first_seen: HashMap::new(),
            commits_since_last_timeout: 0,
            rx_payload,
            payload_inflight: None,
            tx_delayed_proposal,
            rx_delayed_proposal,
        }
    }

    fn reset_timer(&mut self) {
        let delay_ms = self.instrumentation.timeout_cell.get().as_millis() as u64;
        self.timer.reset_after(delay_ms);
    }

    async fn store_block(&mut self, block: &Block) {
        let key = block.digest().to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
    }

    // -- Start Safety Module --
    fn increase_last_voted_round(&mut self, target: RoundNumber) {
        self.last_voted_round = max(self.last_voted_round, target);
    }

    fn update_preferred_round(&mut self, target: RoundNumber) {
        self.preferred_round = max(self.preferred_round, target);
    }

    async fn make_vote(&mut self, block: &Block) -> Option<Vote> {
        // Check if we can vote for this block.
        let safety_rule_1 = block.round > self.last_voted_round;
        let safety_rule_2 = block.qc.round >= self.preferred_round;
        if !(safety_rule_1 && safety_rule_2) {
            return None;
        }

        // Ensure we won't vote for contradicting blocks.
        self.increase_last_voted_round(block.round);

        // TODO [issue #15]: Write to storage preferred_round and last_voted_round.

        Some(Vote::new(&block, self.name, self.signature_service.clone()).await)
    }

    async fn commit(&mut self, block: Block) -> ConsensusResult<()> {
        if self.last_committed_round >= block.round {
            return Ok(());
        }

        let mut to_commit = VecDeque::new();
        to_commit.push_back(block.clone());

        // Ensure we commit the entire chain. This is needed after view-change.
        let mut parent = block.clone();
        while self.last_committed_round + 1 < parent.round {
            let ancestor = self
                .synchronizer
                .get_parent_block(&parent)
                .await?
                .expect("We should have all the ancestors by now");
            to_commit.push_front(ancestor.clone());
            parent = ancestor;
        }

        // Save the last committed block.
        self.last_committed_round = block.round;

        // Send all the newly committed blocks to the node's application layer.
        while let Some(block) = to_commit.pop_back() {
            if !block.payload.is_empty() {
                info!("Committed {}", block);

                #[cfg(feature = "benchmark")]
                for x in &block.payload {
                    // NOTE: This log entry is used to compute performance.
                    info!("Committed B{}({})", block.round, base64::encode(x));
                }
            }
            debug!("Committed {:?}", block);
            self.commits_since_last_timeout += 1;
            let committed = CommittedBlock {
                first_seen: self.first_seen.remove(&block.digest()),
                block,
                committed_at: Instant::now(),
            };
            if let Err(e) = self.commit_channel.send(committed).await {
                warn!("Failed to send block through the commit channel: {}", e);
            }
        }
        Ok(())
    }
    // -- End Safety Module --

    // -- Start Pacemaker --
    fn update_high_qc(&mut self, qc: &QC) {
        if qc.round > self.high_qc.round {
            self.high_qc = qc.clone();
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        warn!("Timeout reached for round {}", self.round);
        if let Some(learning) = &self.instrumentation.learning {
            learning.record_view_change();
            if self.commits_since_last_timeout == 0 {
                learning.record_no_progress_view_change();
            }
        }
        self.commits_since_last_timeout = 0;
        // Prune first-seen entries for blocks that will never commit (forks
        // abandoned by a view change).
        self.first_seen
            .retain(|_, seen| seen.elapsed() < std::time::Duration::from_secs(600));
        self.increase_last_voted_round(self.round);
        let timeout = Timeout::new(
            self.high_qc.clone(),
            self.round,
            self.name,
            self.signature_service.clone(),
        )
        .await;
        debug!("Created {:?}", timeout);
        self.reset_timer();
        let message = ConsensusMessage::Timeout(timeout.clone());
        Synchronizer::transmit(
            &message,
            &self.name,
            None,
            &self.network_channel,
            &self.committee,
        )
        .await?;
        self.handle_timeout(&timeout).await
    }

    #[async_recursion]
    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {
        debug!("Processing {:?}", vote);
        if vote.round < self.round {
            return Ok(());
        }

        // Ensure the vote is well formed.
        vote.verify(&self.committee)?;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(qc) = self.aggregator.add_vote(vote.clone())? {
            debug!("Assembled {:?}", qc);

            // Process the QC.
            self.process_qc(&qc).await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(None).await?;
            }
        }
        Ok(())
    }

    async fn handle_timeout(&mut self, timeout: &Timeout) -> ConsensusResult<()> {
        debug!("Processing {:?}", timeout);
        if timeout.round < self.round {
            return Ok(());
        }

        // Ensure the timeout is well formed.
        timeout.verify(&self.committee)?;

        // Process the QC embedded in the timeout.
        self.process_qc(&timeout.high_qc).await;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(tc) = self.aggregator.add_timeout(timeout.clone())? {
            debug!("Assembled {:?}", tc);

            // Try to advance the round.
            self.advance_round(tc.round).await;

            // Broadcast the TC.
            let message = ConsensusMessage::TC(tc.clone());
            Synchronizer::transmit(
                &message,
                &self.name,
                None,
                &self.network_channel,
                &self.committee,
            )
            .await?;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(Some(tc)).await?;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn advance_round(&mut self, round: RoundNumber) {
        if round < self.round {
            return;
        }
        // Reset the timer and advance round.
        self.reset_timer();
        self.round = round + 1;
        debug!("Moved to round {}", self.round);

        // Cleanup the vote aggregator.
        self.aggregator.cleanup(&self.round);
    }
    // -- End Pacemaker --

    #[async_recursion]
    /// Start building a proposal for the current round. The payload fetch
    /// runs in a spawned task (the core must not park on the mempool, see
    /// MempoolDriver); the proposal completes in `complete_proposal` when
    /// the payload arrives.
    async fn generate_proposal(&mut self, tc: Option<TC>) -> ConsensusResult<()> {
        if self.payload_inflight == Some(self.round) {
            return Ok(());
        }
        self.payload_inflight = Some(self.round);
        self.mempool_driver
            .get(self.parameters.max_payload_size, self.round, tc);
        Ok(())
    }

    /// A payload fetch finished; build, broadcast, and process the block if
    /// we are still in the round it was requested for. `resumed` marks a
    /// payload coming back from an injected proposal delay.
    async fn complete_proposal(
        &mut self,
        round: RoundNumber,
        tc: Option<TC>,
        payload: Vec<Digest>,
        resumed: bool,
    ) -> ConsensusResult<()> {
        if round != self.round || self.name != self.leader_elector.get_leader(self.round) {
            self.payload_inflight = None;
            debug!("Discarding stale proposal payload for round {}", round);
            return Ok(());
        }

        // Protocol fault injection: a targeted leader delays its proposal.
        // The sleep runs off the core loop so this replica keeps voting and
        // timing out like everyone else; only its own proposal is late.
        // payload_inflight stays set meanwhile so the round is not proposed
        // twice.
        if !resumed {
            if let Some(fault) = self.instrumentation.faults.proposal_fault(self.instrumentation.replica_id) {
                let delay = fault.delay.resolve(self.instrumentation.timeout_cell.get());
                if delay > Duration::ZERO {
                    warn!(
                        "Injecting proposal delay of {} ms in round {}",
                        delay.as_millis(),
                        self.round
                    );
                    let tx = self.tx_delayed_proposal.clone();
                    tokio::spawn(async move {
                        sleep(delay).await;
                        let _ = tx.send((round, tc, payload)).await;
                    });
                    return Ok(());
                }
            }
        }
        self.payload_inflight = None;

        // Make a new block.
        let block = Block::new(
            self.high_qc.clone(),
            tc,
            self.name,
            self.round,
            payload,
            self.signature_service.clone(),
        )
        .await;
        if !block.payload.is_empty() {
            info!("Created {}", block);

            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                // NOTE: This log entry is used to compute performance.
                info!("Created B{}({})", block.round, base64::encode(x));
            }
        }
        debug!("Created {:?}", block);

        // Process our new block and broadcast it.
        let message = ConsensusMessage::Propose(block.clone());
        Synchronizer::transmit(
            &message,
            &self.name,
            None,
            &self.network_channel,
            &self.committee,
        )
        .await?;
        self.process_block(&block).await?;

        // Wait for the minimum block delay.
        sleep(Duration::from_millis(self.parameters.min_block_delay)).await;
        Ok(())
    }

    async fn process_qc(&mut self, qc: &QC) {
        self.advance_round(qc.round).await;
        self.update_high_qc(qc);
    }

    #[async_recursion]
    async fn process_block(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);
        // Track when we first saw this block, to compute consensus latency at
        // commit (which removes the entry). Entries for blocks that never
        // commit are pruned on local timeouts.
        self.first_seen
            .entry(block.digest())
            .or_insert_with(Instant::now);

        // Let's see if we have the last three ancestors of the block, that is:
        //      b0 <- |qc0; b1| <- |qc1; block|
        // If we don't, the synchronizer asks for them to other nodes. It will
        // then ensure we process all three ancestors in the correct order, and
        // finally make us resume processing this block.
        let (b0, b1, b2) = match self.synchronizer.get_ancestors(block).await? {
            Some(ancestors) => ancestors,
            None => {
                debug!("Processing of {} suspended: missing parent", block.digest());
                return Ok(());
            }
        };

        // Store the block only if we have already processed all its ancestors.
        self.store_block(block).await;

        // Check if we can commit the head of the 2-chain.
        // Note that we commit blocks only if we have all its ancestors.
        let mut commit_rule = b0.round + 1 == b1.round;
        commit_rule &= b1.round + 1 == b2.round;
        if commit_rule {
            self.commit(b0.clone()).await?;
        }
        self.update_preferred_round(b1.round);

        // Cleanup the mempool.
        self.mempool_driver.cleanup(&b0, &b1, &b2, &block).await;

        // Ensure the block's round is as expected.
        // This check is important: it prevents bad leaders from producing blocks
        // far in the future that may cause overflow on the round number.
        if block.round != self.round {
            return Ok(());
        }

        // See if we can vote for this block.
        if let Some(vote) = self.make_vote(block).await {
            debug!("Created {:?}", vote);
            let next_leader = self.leader_elector.get_leader(self.round + 1);
            if next_leader == self.name {
                self.handle_vote(&vote).await?;
            } else {
                let message = ConsensusMessage::Vote(vote);
                Synchronizer::transmit(
                    &message,
                    &self.name,
                    Some(&next_leader),
                    &self.network_channel,
                    &self.committee,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn handle_proposal(&mut self, block: &Block) -> ConsensusResult<()> {
        let digest = block.digest();

        // Ensure the block proposer is the right leader for the round.
        ensure!(
            block.author == self.leader_elector.get_leader(block.round),
            ConsensusError::WrongLeader {
                digest,
                leader: block.author,
                round: block.round
            }
        );

        // Check the block is correctly formed.
        block.verify(&self.committee)?;

        // Process the QC. This may allow us to advance round.
        self.process_qc(&block.qc).await;

        // Process the TC (if any). This may also allow us to advance round.
        if let Some(ref tc) = block.tc {
            self.advance_round(tc.round).await;
        }

        // Hand the block to the mempool for payload availability checks.
        // This always defers: when the payload is (or becomes) available,
        // the block re-enters the core as a LoopBack and is processed then.
        // Waiting for the answer inline would park the core on the mempool.
        self.mempool_driver.verify(block.clone());
        Ok(())
    }

    async fn handle_sync_request(
        &mut self,
        digest: Digest,
        sender: PublicKey,
    ) -> ConsensusResult<()> {
        if let Some(bytes) = self.store.read(digest.to_vec()).await? {
            let block = bincode::deserialize(&bytes)?;
            let message = ConsensusMessage::Propose(block);
            Synchronizer::transmit(
                &message,
                &self.name,
                Some(&sender),
                &self.network_channel,
                &self.committee,
            )
            .await?;
        }
        Ok(())
    }

    async fn handle_tc(&mut self, tc: TC) -> ConsensusResult<()> {
        self.advance_round(tc.round).await;
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(Some(tc)).await?;
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.reset_timer();
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(None)
                .await
                .expect("Failed to send the first block");
        }

        // This is the main loop: it processes incoming blocks and votes,
        // and receive timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.core_channel.recv() => {
                    match message {
                        ConsensusMessage::Propose(block) => self.handle_proposal(&block).await,
                        ConsensusMessage::Vote(vote) => self.handle_vote(&vote).await,
                        ConsensusMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                        ConsensusMessage::TC(tc) => self.handle_tc(tc).await,
                        ConsensusMessage::LoopBack(block) => self.process_block(&block).await,
                        ConsensusMessage::SyncRequest(digest, sender) => self.handle_sync_request(digest, sender).await
                    }
                },
                Some((round, tc, payload)) = self.rx_payload.recv() => {
                    self.complete_proposal(round, tc, payload, false).await
                },
                // A proposal whose injected delay has elapsed.
                Some((round, tc, payload)) = self.rx_delayed_proposal.recv() => {
                    self.complete_proposal(round, tc, payload, true).await
                },
                () = &mut self.timer => self.local_timeout_round().await,
                else => break,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
