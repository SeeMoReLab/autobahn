//! The tokio shell around the sans-IO SBFT state machine: networking,
//! signing, the election / slow-path / batch timers, mempool interaction,
//! failure injection, and learning-event recording. All protocol decisions
//! live in state.rs.

use crate::config::{Committee, Parameters};
use crate::error::SbftResult;
use crate::messages::{
    Batch, NewViewMsg, Phase, SbftMessage, Seq, View, ViewChangeMsg, Vote,
};
use crate::state::{Action, Event, Sbft};
use adaptive::episode::LearningManager;
use adaptive::failure::ProposalDelayController;
use adaptive::timeouts::SbftTimeoutCells;
use bytes::Bytes;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, info, warn};
use mempool::{ConsensusMempoolMessage, MempoolBlock, PayloadStatus};
use network::{MessageClass, NetMessage, NetReceiver, NetSender};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration, Instant as TokioInstant};

impl MempoolBlock for Batch {
    fn digest(&self) -> Digest {
        crypto::Hash::digest(self)
    }

    fn author(&self) -> PublicKey {
        self.author
    }

    fn round(&self) -> u64 {
        self.seq
    }

    fn payload(&self) -> &[Digest] {
        &self.payload
    }
}

/// A delivered sequence plus the local timing needed to compute consensus
/// latency in the application layer.
#[derive(Debug)]
pub struct CommittedBatch {
    pub seq: Seq,
    pub view: View,
    pub leader: PublicKey,
    pub payload: Vec<Digest>,
    pub first_seen: Option<Instant>,
    pub committed_at: Instant,
    /// The replica's view and leader at delivery time (not the delivered
    /// batch's), for leader hints: a replica replaying old batches during
    /// catch-up must not advertise long-gone leaders to clients.
    pub current_view: View,
    pub current_leader: PublicKey,
}

/// Adaptive-timer instrumentation, mirroring the pbft crate's but with the
/// three SBFT timeout knobs.
pub struct Instrumentation {
    pub timeout_cells: SbftTimeoutCells,
    pub learning: Option<Arc<LearningManager>>,
    pub proposal_delay: Arc<ProposalDelayController>,
    pub replica_id: u32,
    pub replica_of: HashMap<PublicKey, u32>,
}

impl Instrumentation {
    pub fn disabled(election_ms: u64, slow_path_ms: u64, batch_ms: u64) -> Self {
        Self {
            timeout_cells: SbftTimeoutCells::new(
                Duration::from_millis(election_ms),
                Duration::from_millis(slow_path_ms),
                Duration::from_millis(batch_ms),
            ),
            learning: None,
            proposal_delay: Arc::new(ProposalDelayController::disabled()),
            replica_id: 0,
            replica_of: HashMap::new(),
        }
    }
}

const FAR_FUTURE: Duration = Duration::from_secs(3600);

pub struct Consensus;

impl Consensus {
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        _store: Store,
        signature_service: SignatureService,
        tx_core: Sender<SbftMessage>,
        rx_core: Receiver<SbftMessage>,
        tx_consensus_mempool: Sender<ConsensusMempoolMessage<Batch>>,
        rx_mempool_loopback: Receiver<Batch>,
        tx_commit: Sender<CommittedBatch>,
        instrumentation: Instrumentation,
    ) -> SbftResult<()> {
        // NOTE: The following log entries are used to compute performance.
        info!(
            "Consensus timeout delay set to {} ms",
            instrumentation.timeout_cells.election.get().as_millis()
        );
        info!(
            "Consensus slow path timeout set to {} ms",
            instrumentation.timeout_cells.slow_path.get().as_millis()
        );
        info!(
            "Consensus batch timeout set to {} ms",
            instrumentation.timeout_cells.batch.get().as_millis()
        );
        info!(
            "Consensus max payload size set to {} B",
            parameters.max_payload_size
        );
        info!(
            "Consensus min block delay set to {} ms",
            parameters.min_block_delay
        );

        let (tx_network, rx_network) = channel(1000);

        let address = committee
            .address(&name)
            .map(|mut x| {
                x.set_ip("0.0.0.0".parse().unwrap());
                x
            })
            .expect("Our public key is not in the committee");
        let network_receiver = NetReceiver::new(address, tx_core.clone());
        tokio::spawn(async move {
            network_receiver.run().await;
        });
        let mut network_sender = NetSender::new(rx_network);
        tokio::spawn(async move {
            network_sender.run().await;
        });

        let (tx_self, rx_self) = channel(1000);
        let mut engine = Engine {
            name,
            committee: committee.clone(),
            parameters,
            signature_service,
            rx_core,
            rx_mempool_loopback,
            tx_network,
            tx_consensus_mempool,
            tx_commit,
            instrumentation,
            first_seen: HashMap::new(),
            pending_sync_events: Vec::new(),
            timer_deadline: TokioInstant::now() + FAR_FUTURE,
            timer_armed_view: 0,
            slow_timers: BinaryHeap::new(),
            propose_deadline: TokioInstant::now(),
            observed_view: u64::MAX,
            tx_self,
            rx_self,
            get_inflight: false,
        };
        tokio::spawn(async move {
            engine.run().await;
        });
        Ok(())
    }
}

/// Results of mempool round trips, fed back to the engine loop by spawned
/// waiter tasks. The engine must never await these replies inline: the
/// mempool can be momentarily parked on channels that only this engine
/// drains, so an inline wait closes a deadlock cycle under overload.
enum SelfEvent {
    /// The mempool accepted (and if needed synced) a batch's payload.
    Verified(Batch),
    /// The mempool answered a Get with payload digests to propose.
    PayloadFetched(Vec<Digest>),
}

struct Engine {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    signature_service: SignatureService,
    rx_core: Receiver<SbftMessage>,
    rx_mempool_loopback: Receiver<Batch>,
    tx_network: Sender<NetMessage>,
    tx_consensus_mempool: Sender<ConsensusMempoolMessage<Batch>>,
    tx_commit: Sender<CommittedBatch>,
    instrumentation: Instrumentation,
    /// seq -> when we first saw a pre-prepare for it, for commit latency.
    first_seen: HashMap<Seq, Instant>,
    /// Extra sync certificates queued behind the first one of a reply.
    pending_sync_events: Vec<Event>,
    timer_deadline: TokioInstant,
    timer_armed_view: View,
    /// Armed slow-path fallback timers, earliest deadline first.
    slow_timers: BinaryHeap<Reverse<(TokioInstant, View, Seq)>>,
    /// Next proposal (and empty-batch heartbeat) instant, paced by the
    /// adaptive batch timeout.
    propose_deadline: TokioInstant,
    observed_view: View,
    tx_self: Sender<SelfEvent>,
    rx_self: Receiver<SelfEvent>,
    /// A payload Get is outstanding (avoid stacking one per propose tick).
    get_inflight: bool,
}

impl Engine {
    async fn run(&mut self) {
        let (mut state, init_actions) = Sbft::new(
            self.name,
            self.committee.clone(),
            // Commit certificates must be retained well beyond the watermark
            // window: a laggard can trail the quorum by a full window while
            // still voting, and certificates garbage-collected below its
            // delivery point would wedge it permanently (seen live in the
            // pbft fork at 20k tps under combined faults).
            /* gc_depth */ 8 * crate::state::WATERMARK_WINDOW,
        );
        let mut queue: VecDeque<Event> = VecDeque::new();
        self.execute(&mut state, init_actions, &mut queue).await;
        self.observe_leader(&state);

        // Re-send the outstanding laggard sync request periodically: the
        // request or its reply can be lost (network shedding under load).
        let mut sync_retry_tick = tokio::time::interval(Duration::from_millis(
            self.parameters.sync_retry_delay.max(100),
        ));
        sync_retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let election_timer = sleep(FAR_FUTURE);
        tokio::pin!(election_timer);
        let slow_timer = sleep(FAR_FUTURE);
        tokio::pin!(slow_timer);
        let propose_timer = sleep(Duration::ZERO);
        tokio::pin!(propose_timer);

        loop {
            election_timer.as_mut().reset(self.timer_deadline);
            let slow_deadline = self
                .slow_timers
                .peek()
                .map(|Reverse((deadline, _, _))| *deadline)
                .unwrap_or_else(|| TokioInstant::now() + FAR_FUTURE);
            slow_timer.as_mut().reset(slow_deadline);
            propose_timer.as_mut().reset(self.propose_deadline);

            tokio::select! {
                Some(message) = self.rx_core.recv() => {
                    if let Some(event) = self.verify_message(message) {
                        queue.push_back(event);
                    }
                    queue.extend(self.pending_sync_events.drain(..));
                },
                Some(batch) = self.rx_mempool_loopback.recv() => {
                    queue.push_back(Event::PayloadReady(batch));
                },
                Some(event) = self.rx_self.recv() => match event {
                    SelfEvent::Verified(batch) => {
                        queue.push_back(Event::PayloadReady(batch));
                    }
                    SelfEvent::PayloadFetched(payload) => {
                        self.get_inflight = false;
                        if state.want_proposal() {
                            // Blocking the engine here is the point of the
                            // injected fault (a slow leader stalls whole).
                            self.inject_proposal_delay().await;
                            queue.push_back(Event::Propose { payload });
                        }
                    }
                },
                () = &mut election_timer => {
                    queue.push_back(Event::TimerFired { view: self.timer_armed_view });
                    // Prevent a hot loop until the state machine re-arms.
                    self.timer_deadline = TokioInstant::now() + FAR_FUTURE;
                },
                () = &mut slow_timer => {
                    let now = TokioInstant::now();
                    while let Some(Reverse((deadline, view, seq))) = self.slow_timers.peek() {
                        if *deadline > now {
                            break;
                        }
                        queue.push_back(Event::SlowTimerFired {
                            view: *view,
                            seq: *seq,
                        });
                        self.slow_timers.pop();
                    }
                },
                () = &mut propose_timer => {
                    if state.want_proposal() && !self.get_inflight {
                        self.get_inflight = true;
                        self.spawn_get_payload();
                    }
                    self.propose_deadline =
                        TokioInstant::now() + self.instrumentation.timeout_cells.batch.get();
                },
                _ = sync_retry_tick.tick() => {
                    queue.push_back(Event::SyncRetryTick);
                },
            }

            while let Some(event) = queue.pop_front() {
                self.track_first_seen(&event);
                let actions = state.handle(event);
                self.execute(&mut state, actions, &mut queue).await;
            }
            self.observe_leader(&state);
        }
    }

    fn track_first_seen(&mut self, event: &Event) {
        if let Event::PrePrepare(batch) = event {
            self.first_seen.entry(batch.seq).or_insert_with(Instant::now);
        }
    }

    /// Verify signatures and certificates before events reach the state
    /// machine.
    fn verify_message(&mut self, message: SbftMessage) -> Option<Event> {
        let check = |result: SbftResult<()>, what: &str| -> bool {
            match result {
                Ok(()) => true,
                Err(e) => {
                    warn!("Dropping invalid {}: {}", what, e);
                    false
                }
            }
        };
        match message {
            SbftMessage::PrePrepare(batch) => {
                check(batch.verify(&self.committee), "pre-prepare").then_some(Event::PrePrepare(batch))
            }
            SbftMessage::Vote(vote) => {
                check(vote.verify(&self.committee), "vote").then_some(Event::Vote(vote))
            }
            SbftMessage::FastCommit(cert) => {
                check(cert.verify(&self.committee), "commit proof")
                    .then_some(Event::FastCommit(cert))
            }
            SbftMessage::ViewChange(vc) => {
                check(vc.verify(&self.committee), "view-change").then_some(Event::ViewChange(vc))
            }
            SbftMessage::NewView(nv) => {
                check(nv.verify(&self.committee), "new-view").then_some(Event::NewView(nv))
            }
            SbftMessage::SyncRequest { from, to, requester } => Some(Event::SyncRequest {
                from,
                to,
                requester,
            }),
            SbftMessage::SyncReply(certs) => {
                // Feed each valid certificate separately; the state machine
                // applies them in order.
                let mut valid: Vec<_> = certs
                    .into_iter()
                    .filter(|cert| check(cert.verify(&self.committee), "commit certificate"))
                    .collect();
                valid.sort_by_key(|cert| cert.seq);
                let mut iter = valid.into_iter();
                let first = iter.next()?;
                // Queue the rest right behind the first.
                let rest: Vec<Event> = iter.map(Event::SyncCert).collect();
                if !rest.is_empty() {
                    self.pending_sync_events.extend(rest);
                }
                Some(Event::SyncCert(first))
            }
        }
    }

    /// Ask the mempool for payload digests without parking the engine loop;
    /// the reply comes back as SelfEvent::PayloadFetched.
    fn spawn_get_payload(&self) {
        let tx_mempool = self.tx_consensus_mempool.clone();
        let tx_self = self.tx_self.clone();
        let max = self.parameters.max_payload_size;
        tokio::spawn(async move {
            let (sender, receiver) = oneshot::channel();
            let payload = if tx_mempool
                .send(ConsensusMempoolMessage::Get(max, sender))
                .await
                .is_err()
            {
                Vec::new()
            } else {
                receiver.await.unwrap_or_default()
            };
            let _ = tx_self.send(SelfEvent::PayloadFetched(payload)).await;
        });
    }

    /// Protocol failure injection: a targeted leader delays its proposals.
    /// Blocking the whole engine here is the point of the fault.
    async fn inject_proposal_delay(&self) {
        let replica_ids: Vec<u32> = {
            let mut ids: Vec<u32> = self.instrumentation.replica_of.values().copied().collect();
            ids.sort_unstable();
            ids
        };
        let delay = self.instrumentation.proposal_delay.delay_for_proposal(
            self.instrumentation.replica_id,
            self.instrumentation.replica_id,
            &replica_ids,
        );
        if delay > Duration::ZERO {
            warn!("Injecting proposal delay of {} ms", delay.as_millis());
            sleep(delay).await;
        }
    }

    /// Keep the failure controller's leader window pinned to the current
    /// consensus leader.
    fn observe_leader(&mut self, state: &Sbft) {
        let view = state.view();
        if view == self.observed_view {
            return;
        }
        self.observed_view = view;
        let leader = state.current_leader();
        if let Some(leader_id) = self.instrumentation.replica_of.get(&leader) {
            let mut ids: Vec<u32> = self.instrumentation.replica_of.values().copied().collect();
            ids.sort_unstable();
            self.instrumentation
                .proposal_delay
                .observe_leader(*leader_id, &ids);
        }
    }

    async fn execute(&mut self, state: &mut Sbft, actions: Vec<Action>, queue: &mut VecDeque<Event>) {
        for action in actions {
            match action {
                Action::SignPrePrepare { view, seq, payload } => {
                    let batch =
                        Batch::new(view, seq, payload, self.name, &mut self.signature_service)
                            .await;
                    self.broadcast(SbftMessage::PrePrepare(batch.clone())).await;
                    queue.push_back(Event::PrePrepare(batch));
                }
                Action::SignShare { view, seq, digest } => {
                    let vote = Vote::new(
                        Phase::SignShare,
                        view,
                        seq,
                        digest,
                        self.name,
                        &mut self.signature_service,
                    )
                    .await;
                    let collector = self.committee.leader(view);
                    if collector != self.name {
                        self.send(collector, SbftMessage::Vote(vote.clone())).await;
                    }
                    queue.push_back(Event::Vote(vote));
                }
                Action::SignVote {
                    phase,
                    view,
                    seq,
                    digest,
                } => {
                    let vote = Vote::new(
                        phase,
                        view,
                        seq,
                        digest,
                        self.name,
                        &mut self.signature_service,
                    )
                    .await;
                    self.broadcast(SbftMessage::Vote(vote.clone())).await;
                    queue.push_back(Event::Vote(vote));
                }
                Action::BroadcastFastCommit(cert) => {
                    self.broadcast(SbftMessage::FastCommit(cert.clone())).await;
                    queue.push_back(Event::FastCommit(cert));
                }
                Action::SignViewChange {
                    view,
                    last_delivered,
                    prepared,
                    shares,
                } => {
                    let vc = ViewChangeMsg::new(
                        view,
                        last_delivered,
                        prepared,
                        shares,
                        self.name,
                        &mut self.signature_service,
                    )
                    .await;
                    self.broadcast(SbftMessage::ViewChange(vc.clone())).await;
                    queue.push_back(Event::ViewChange(vc));
                }
                Action::SignNewView {
                    view,
                    view_changes,
                    o_payloads,
                } => {
                    let mut pre_prepares = Vec::with_capacity(o_payloads.len());
                    for (seq, payload) in o_payloads {
                        pre_prepares.push(
                            Batch::new(view, seq, payload, self.name, &mut self.signature_service)
                                .await,
                        );
                    }
                    let nv = NewViewMsg::new(
                        view,
                        view_changes,
                        pre_prepares,
                        self.name,
                        &mut self.signature_service,
                    )
                    .await;
                    self.broadcast(SbftMessage::NewView(nv.clone())).await;
                    queue.push_back(Event::NewView(nv));
                }
                Action::VerifyPayload(batch) => {
                    // Waited on by a spawned task, never inline: see
                    // SelfEvent. On Wait the mempool syncs the payloads and
                    // delivers the batch via the loopback channel instead.
                    let tx_mempool = self.tx_consensus_mempool.clone();
                    let tx_self = self.tx_self.clone();
                    tokio::spawn(async move {
                        let (sender, receiver) = oneshot::channel();
                        let message =
                            ConsensusMempoolMessage::Verify(Box::new(batch.clone()), sender);
                        if tx_mempool.send(message).await.is_err() {
                            return;
                        }
                        match receiver.await {
                            Ok(PayloadStatus::Accept) => {
                                let _ = tx_self.send(SelfEvent::Verified(batch)).await;
                            }
                            Ok(PayloadStatus::Wait) => {
                                debug!("Batch n{} waiting for payload sync", batch.seq);
                            }
                            Ok(PayloadStatus::Reject) => {
                                warn!("Rejected payload for batch n{}", batch.seq)
                            }
                            Err(_) => (),
                        }
                    });
                }
                Action::Deliver {
                    seq,
                    view,
                    leader,
                    payload,
                } => {
                    let committed = CommittedBatch {
                        seq,
                        view,
                        leader,
                        payload,
                        first_seen: self.first_seen.remove(&seq),
                        committed_at: Instant::now(),
                        current_view: state.view(),
                        current_leader: state.current_leader(),
                    };
                    if self.tx_commit.send(committed).await.is_err() {
                        warn!("Failed to deliver committed batch: channel closed");
                    }
                }
                Action::CleanupMempool { digests, seq } => {
                    let _ = self
                        .tx_consensus_mempool
                        .send(ConsensusMempoolMessage::Cleanup(digests, seq))
                        .await;
                }
                Action::ArmTimer { view, factor } => {
                    let base = self.instrumentation.timeout_cells.election.get();
                    let duration = base.saturating_mul(1u32 << factor.min(6));
                    self.timer_armed_view = view;
                    self.timer_deadline = TokioInstant::now() + duration;
                }
                Action::ArmSlowTimer { view, seq } => {
                    let deadline =
                        TokioInstant::now() + self.instrumentation.timeout_cells.slow_path.get();
                    self.slow_timers.push(Reverse((deadline, view, seq)));
                }
                Action::RecordViewChange { no_progress } => {
                    if let Some(learning) = &self.instrumentation.learning {
                        learning.record_view_change();
                        if no_progress {
                            learning.record_no_progress_view_change();
                        }
                    }
                }
                Action::Send(to, message) => {
                    self.send(to, message).await;
                }
            }
        }
        // Prune first-seen entries no longer needed.
        if self.first_seen.len() > 4096 {
            let cutoff = state.last_delivered();
            self.first_seen.retain(|seq, _| *seq > cutoff);
        }
    }

    async fn send(&mut self, to: PublicKey, message: SbftMessage) {
        if let Some(address) = self.committee.address(&to) {
            let bytes = bincode::serialize(&message).expect("Failed to serialize message");
            let _ = self
                .tx_network
                .send(NetMessage(Bytes::from(bytes), vec![address], MessageClass::Control))
                .await;
        }
    }

    async fn broadcast(&mut self, message: SbftMessage) {
        let addresses = self.committee.broadcast_addresses(&self.name);
        if addresses.is_empty() {
            return;
        }
        let bytes = bincode::serialize(&message).expect("Failed to serialize message");
        let _ = self
            .tx_network
            .send(NetMessage(Bytes::from(bytes), addresses, MessageClass::Control))
            .await;
    }
}
