use crate::config::Export as _;
use crate::config::{
    Committee, Parameters, PbftCommittee, PbftParameters, SbftCommittee, SbftParameters, Secret,
};
use adaptive::ack::{encode_leader_hint, tx_seq, AckIndex, AckRouter};
use adaptive::shadow::ShadowLog;
use adaptive::episode::{
    hotstuff_hooks, pbft_hooks, sbft_hooks, LearningConfig, LearningManager, ProtocolHooks,
};
use adaptive::failure::{ProposalDelayController, ProtocolSection};
use adaptive::metrics::LearningSample;
use adaptive::timeouts::{SbftTimeoutCells, TimeoutCell};
use crypto::{Digest, PublicKey, SignatureService};
use hotstuff::ConsensusError;
use log::{info, warn};
use mempool::{Mempool, MempoolError, Payload};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use store::{Store, StoreError};
use thiserror::Error;
use tokio::sync::mpsc::{channel, Receiver, Sender};

/// Bound on batches sealed locally but not yet observed as committed. Beyond
/// this, the oldest pending batches are dropped from the ack index and their
/// transactions surface as client-side timeouts.
const ACK_INDEX_CAPACITY: usize = 100_000;

/// Shadow arrivals (broadcast client mode) older than this are dropped:
/// their transactions were shed or lost and will never commit here. Until
/// then they surface in the oldest_pending gauge.
const SHADOW_EXPIRY: Duration = Duration::from_secs(30);

/// Cadence of the shadow-e2e log line (and, every fifth tick, the expiry
/// sweep).
const SHADOW_REPORT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Error, Debug)]
pub enum NodeError {
    #[error("Failed to read config file '{file}': {message}")]
    ReadError { file: String, message: String },

    #[error("Failed to write config file '{file}': {message}")]
    WriteError { file: String, message: String },

    #[error("Store error: {0}")]
    StoreError(#[from] StoreError),

    #[error(transparent)]
    ConsensusError(#[from] ConsensusError),

    #[error(transparent)]
    PbftError(#[from] pbft::PbftError),

    #[error(transparent)]
    SbftError(#[from] sbft::SbftError),

    #[error(transparent)]
    MempoolError(#[from] MempoolError),

    #[error("Adaptive-timer setup error: {0}")]
    AdaptiveError(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolKind {
    Hotstuff,
    Pbft,
    Sbft,
}

impl ProtocolKind {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "hotstuff" => Ok(Self::Hotstuff),
            "pbft" => Ok(Self::Pbft),
            "sbft" => Ok(Self::Sbft),
            other => Err(format!(
                "unknown protocol {:?}; expected hotstuff, pbft, or sbft",
                other
            )),
        }
    }
}

/// Learning-loop settings (all durations in milliseconds). The initial
/// timeout is `parameters.consensus.timeout_delay`.
#[derive(Clone, Debug)]
pub struct LearningOptions {
    pub agent_target: String,
    pub feature_duration_ms: u64,
    pub reply_wait_ms: u64,
    pub warmup_duration_ms: u64,
    pub reward_duration_ms: u64,
}

/// Adaptive-timer wiring parsed from the CLI.
#[derive(Clone, Debug, Default)]
pub struct AdaptiveOptions {
    /// This replica's global 0-based id (failure-spec id space).
    pub replica_id: u32,
    /// Path to replica_map.json ({public key: replica id}); required for
    /// failure injection and learning.
    pub replica_map: Option<String>,
    /// Failure spec XML plus the shared start timestamp.
    pub failure_spec: Option<String>,
    pub failure_start_unix_ms: Option<u64>,
    pub learning: Option<LearningOptions>,
}

/// Protocol-independent view of one delivered consensus decision, consumed
/// by the shared analyze loop (acks + learning samples).
pub struct Delivered {
    pub sequence: u64,
    /// What the learning sample's `view` should be: PBFT reports its real
    /// view (regency), batched HotStuff reports a cumulative round-gap
    /// counter (see the adapter).
    pub sample_view: u64,
    pub leader: PublicKey,
    pub payload: Vec<Digest>,
    pub first_seen: Option<Instant>,
    pub committed_at: Instant,
    /// The delivering replica's (current view, current leader) at delivery
    /// time, for client leader hints. None for rotating-leader protocols.
    /// Deliberately not `leader`/`sample_view`: those describe the delivered
    /// batch, which is stale history while catching up.
    pub leader_hint: Option<(u64, PublicKey)>,
}

pub struct Node {
    pub commit: Receiver<Delivered>,
    store: Store,
    ack_index: Arc<AckIndex>,
    ack_router: Arc<AckRouter>,
    /// Arrival stamps of broadcast-mode transactions (see
    /// [`adaptive::shadow`]); joined against committed payloads to measure
    /// client-perceived latency locally. Empty outside broadcast mode.
    shadow_log: Arc<ShadowLog>,
    /// Client-latency samples resolved at delivery, drained once a second by
    /// the shadow-e2e reporter task.
    shadow_samples: Arc<Mutex<Vec<Duration>>>,
    /// Set once the first client-latency samples feed a learning report, so
    /// the semantic switch of the report latency fields is logged exactly
    /// once.
    shadow_latency_announced: bool,
    learning: Option<Arc<LearningManager>>,
    replica_of: HashMap<PublicKey, u32>,
    /// Stable-leader protocols push leader hints to client connections so a
    /// leader-targeting client can follow elections. Off for HotStuff (the
    /// leader rotates every round).
    emit_leader_hints: bool,
}

impl Node {
    pub async fn new(
        protocol: ProtocolKind,
        committee_file: &str,
        key_file: &str,
        store_path: &str,
        parameters: Option<&str>,
        adaptive_opts: AdaptiveOptions,
    ) -> Result<Self, NodeError> {
        // Read the secret key from file.
        let secret = Secret::read(key_file)?;
        let name = secret.name;
        let secret_key = secret.secret;

        // Make the data store.
        let store = Store::new(store_path)?;

        // Run the signature service.
        let signature_service = SignatureService::new(secret_key);

        // Commit-ack plumbing between the mempool front and the benchmark
        // client.
        let ack_index = Arc::new(AckIndex::new(ACK_INDEX_CAPACITY));
        let ack_router = Arc::new(AckRouter::new());

        // Broadcast-mode client-latency observation: arrivals recorded at
        // the mempool front, resolved at delivery, reported once a second.
        let shadow_log = Arc::new(ShadowLog::new());
        let shadow_samples: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
        Self::spawn_shadow_reporter(Arc::clone(&shadow_log), Arc::clone(&shadow_samples));

        // Adaptive-timer wiring shared by both protocols.
        let replica_of: HashMap<PublicKey, u32> = match &adaptive_opts.replica_map {
            Some(path) => {
                let data = std::fs::read(path).map_err(|e| NodeError::ReadError {
                    file: path.clone(),
                    message: e.to_string(),
                })?;
                serde_json::from_slice(&data).map_err(|e| NodeError::ReadError {
                    file: path.clone(),
                    message: e.to_string(),
                })?
            }
            None => HashMap::new(),
        };
        let failure_section = match protocol {
            ProtocolKind::Hotstuff => ProtocolSection::Hotstuff,
            ProtocolKind::Pbft => ProtocolSection::Pbft,
            ProtocolKind::Sbft => ProtocolSection::Sbft,
        };
        let proposal_delay = match (&adaptive_opts.failure_spec, adaptive_opts.failure_start_unix_ms)
        {
            (Some(spec), Some(start_ms)) => {
                if adaptive_opts.replica_map.is_none() {
                    return Err(NodeError::AdaptiveError(
                        "--failure-spec requires --replica-map".into(),
                    ));
                }
                Arc::new(
                    ProposalDelayController::load_file(spec, start_ms, failure_section)
                        .map_err(|e| NodeError::AdaptiveError(format!("{:#}", e)))?,
                )
            }
            (Some(_), None) => {
                return Err(NodeError::AdaptiveError(
                    "--failure-spec requires --failure-start-unix-ms".into(),
                ));
            }
            _ => Arc::new(ProposalDelayController::disabled()),
        };

        let make_learning = |hooks: ProtocolHooks| -> Result<Option<Arc<LearningManager>>, NodeError> {
            match &adaptive_opts.learning {
                Some(opts) => {
                    if adaptive_opts.replica_map.is_none() {
                        return Err(NodeError::AdaptiveError(
                            "--learning requires --replica-map".into(),
                        ));
                    }
                    let mut cfg =
                        LearningConfig::new(adaptive_opts.replica_id, opts.agent_target.clone());
                    cfg.feature_duration = Duration::from_millis(opts.feature_duration_ms);
                    cfg.reply_wait = Duration::from_millis(opts.reply_wait_ms);
                    cfg.warmup_duration = Duration::from_millis(opts.warmup_duration_ms);
                    cfg.reward_duration = Duration::from_millis(opts.reward_duration_ms);
                    let manager = LearningManager::new(cfg, hooks)
                        .map_err(|e| NodeError::AdaptiveError(format!("{:#}", e)))?;
                    Ok(Some(manager))
                }
                None => Ok(None),
            }
        };

        let (tx_delivered, rx_delivered) = channel::<Delivered>(1000);

        let learning = match protocol {
            ProtocolKind::Hotstuff => {
                let committee = Committee::read(committee_file)?;
                let parameters = match parameters {
                    Some(filename) => Parameters::read(filename)?,
                    None => Parameters::default(),
                };
                let timeout_cell = TimeoutCell::new(Duration::from_millis(
                    parameters.consensus.timeout_delay,
                ));
                let learning = make_learning(hotstuff_hooks(timeout_cell.clone()))?;
                let instrumentation = hotstuff::Instrumentation {
                    timeout_cell,
                    learning: learning.clone(),
                    proposal_delay,
                    replica_id: adaptive_opts.replica_id,
                    replica_of: replica_of.clone(),
                };

                let (tx_commit, rx_commit) = channel(1000);
                let (tx_consensus, rx_consensus) = channel(1000);
                let (tx_consensus_mempool, rx_consensus_mempool) = channel(1000);
                let (tx_mempool_loopback, rx_mempool_loopback) = channel(1000);

                Mempool::run(
                    name,
                    committee.mempool,
                    parameters.mempool,
                    store.clone(),
                    signature_service.clone(),
                    tx_mempool_loopback,
                    rx_consensus_mempool,
                    Arc::clone(&ack_index),
                    Arc::clone(&ack_router),
                    Arc::clone(&shadow_log),
                )?;

                hotstuff::Consensus::run(
                    name,
                    committee.consensus,
                    parameters.consensus,
                    store.clone(),
                    signature_service,
                    tx_consensus,
                    rx_consensus,
                    tx_consensus_mempool,
                    rx_mempool_loopback,
                    tx_commit,
                    instrumentation,
                )
                .await?;

                Self::adapt_hotstuff_commits(rx_commit, tx_delivered);
                learning
            }
            ProtocolKind::Pbft => {
                let committee = PbftCommittee::read(committee_file)?;
                let parameters = match parameters {
                    Some(filename) => PbftParameters::read(filename)?,
                    None => PbftParameters::default(),
                };
                let timeout_cell = TimeoutCell::new(Duration::from_millis(
                    parameters.consensus.timeout_delay,
                ));
                let learning = make_learning(pbft_hooks(timeout_cell.clone()))?;
                let instrumentation = pbft::Instrumentation {
                    timeout_cell,
                    learning: learning.clone(),
                    proposal_delay,
                    replica_id: adaptive_opts.replica_id,
                    replica_of: replica_of.clone(),
                };

                let (tx_commit, rx_commit) = channel(1000);
                let (tx_consensus, rx_consensus) = channel(1000);
                let (tx_consensus_mempool, rx_consensus_mempool) = channel(1000);
                let (tx_mempool_loopback, rx_mempool_loopback) = channel(1000);

                Mempool::run(
                    name,
                    committee.mempool,
                    parameters.mempool,
                    store.clone(),
                    signature_service.clone(),
                    tx_mempool_loopback,
                    rx_consensus_mempool,
                    Arc::clone(&ack_index),
                    Arc::clone(&ack_router),
                    Arc::clone(&shadow_log),
                )?;

                pbft::Consensus::run(
                    name,
                    committee.consensus,
                    parameters.consensus,
                    store.clone(),
                    signature_service,
                    tx_consensus,
                    rx_consensus,
                    tx_consensus_mempool,
                    rx_mempool_loopback,
                    tx_commit,
                    instrumentation,
                )
                .await?;

                Self::adapt_pbft_commits(rx_commit, tx_delivered);
                learning
            }
            ProtocolKind::Sbft => {
                let committee = SbftCommittee::read(committee_file)?;
                let parameters = match parameters {
                    Some(filename) => SbftParameters::read(filename)?,
                    None => SbftParameters::default(),
                };
                let timeout_cells = SbftTimeoutCells::new(
                    Duration::from_millis(parameters.consensus.timeout_delay),
                    Duration::from_millis(parameters.consensus.slow_path_timeout),
                    Duration::from_millis(parameters.consensus.batch_timeout),
                );
                let learning = make_learning(sbft_hooks(timeout_cells.clone()))?;
                let instrumentation = sbft::Instrumentation {
                    timeout_cells,
                    learning: learning.clone(),
                    proposal_delay,
                    replica_id: adaptive_opts.replica_id,
                    replica_of: replica_of.clone(),
                };

                let (tx_commit, rx_commit) = channel(1000);
                let (tx_consensus, rx_consensus) = channel(1000);
                let (tx_consensus_mempool, rx_consensus_mempool) = channel(1000);
                let (tx_mempool_loopback, rx_mempool_loopback) = channel(1000);

                Mempool::run(
                    name,
                    committee.mempool,
                    parameters.mempool,
                    store.clone(),
                    signature_service.clone(),
                    tx_mempool_loopback,
                    rx_consensus_mempool,
                    Arc::clone(&ack_index),
                    Arc::clone(&ack_router),
                    Arc::clone(&shadow_log),
                )?;

                sbft::Consensus::run(
                    name,
                    committee.consensus,
                    parameters.consensus,
                    store.clone(),
                    signature_service,
                    tx_consensus,
                    rx_consensus,
                    tx_consensus_mempool,
                    rx_mempool_loopback,
                    tx_commit,
                    instrumentation,
                )
                .await?;

                Self::adapt_sbft_commits(rx_commit, tx_delivered);
                learning
            }
        };

        info!("Node {} successfully booted", name);
        Ok(Self {
            commit: rx_delivered,
            store,
            ack_index,
            ack_router,
            shadow_log,
            shadow_samples,
            shadow_latency_announced: false,
            learning,
            replica_of,
            emit_leader_hints: matches!(protocol, ProtocolKind::Pbft | ProtocolKind::Sbft),
        })
    }

    /// Once a second, report the client-latency samples resolved since the
    /// last tick plus the pending-arrival gauge, and periodically expire
    /// arrivals whose transactions will never commit. Prints nothing until
    /// the shadow log sees its first arrival (i.e. outside broadcast client
    /// mode).
    fn spawn_shadow_reporter(log: Arc<ShadowLog>, samples: Arc<Mutex<Vec<Duration>>>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SHADOW_REPORT_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut ticks: u64 = 0;
            loop {
                interval.tick().await;
                ticks += 1;
                let mut drained: Vec<Duration> = {
                    let mut samples = samples.lock().unwrap();
                    samples.drain(..).collect()
                };
                let pending = log.len();
                if !drained.is_empty() || pending > 0 {
                    drained.sort_unstable();
                    let n = drained.len();
                    let (avg, p10, p50, p95, max) = if n > 0 {
                        let sum: Duration = drained.iter().sum();
                        (
                            (sum / n as u32).as_millis(),
                            drained[n / 10].as_millis(),
                            drained[n / 2].as_millis(),
                            drained[(n * 95 / 100).min(n - 1)].as_millis(),
                            drained[n - 1].as_millis(),
                        )
                    } else {
                        (0, 0, 0, 0, 0)
                    };
                    let oldest = log
                        .oldest_age()
                        .map(|age| age.as_millis())
                        .unwrap_or(0);
                    info!(
                        "shadow-e2e: n={} avg_ms={} p10_ms={} p50_ms={} p95_ms={} max_ms={} pending={} oldest_pending_ms={}",
                        n, avg, p10, p50, p95, max, pending, oldest
                    );
                }
                if ticks % 5 == 0 {
                    let dropped = log.sweep(SHADOW_EXPIRY);
                    if dropped > 0 {
                        warn!(
                            "shadow-e2e: expired {} arrivals older than {:?} (their txs never committed here)",
                            dropped, SHADOW_EXPIRY
                        );
                    }
                }
            }
        });
    }

    /// Batched HotStuff: rounds are the sequence; the sample view is a
    /// cumulative round-gap counter so regency_change_count counts rounds
    /// skipped via TCs.
    fn adapt_hotstuff_commits(
        mut rx_commit: Receiver<hotstuff::CommittedBlock>,
        tx_delivered: Sender<Delivered>,
    ) {
        tokio::spawn(async move {
            let mut last_round: Option<u64> = None;
            let mut gap_events: u64 = 0;
            while let Some(committed) = rx_commit.recv().await {
                let block = committed.block;
                if let Some(last) = last_round {
                    if block.round > last + 1 {
                        gap_events += 1;
                    }
                }
                last_round = Some(block.round);
                let delivered = Delivered {
                    sequence: block.round,
                    sample_view: gap_events,
                    leader: block.author,
                    payload: block.payload,
                    first_seen: committed.first_seen,
                    committed_at: committed.committed_at,
                    leader_hint: None,
                };
                if tx_delivered.send(delivered).await.is_err() {
                    break;
                }
            }
        });
    }

    /// PBFT: the sample view is the real view, matching SmartBFT's regency
    /// semantics.
    fn adapt_pbft_commits(
        mut rx_commit: Receiver<pbft::CommittedBatch>,
        tx_delivered: Sender<Delivered>,
    ) {
        tokio::spawn(async move {
            while let Some(committed) = rx_commit.recv().await {
                let delivered = Delivered {
                    sequence: committed.seq,
                    sample_view: committed.view,
                    leader: committed.leader,
                    payload: committed.payload,
                    first_seen: committed.first_seen,
                    committed_at: committed.committed_at,
                    leader_hint: Some((committed.current_view, committed.current_leader)),
                };
                if tx_delivered.send(delivered).await.is_err() {
                    break;
                }
            }
        });
    }

    /// SBFT: like PBFT, the sample view is the real view (regency
    /// semantics).
    fn adapt_sbft_commits(
        mut rx_commit: Receiver<sbft::CommittedBatch>,
        tx_delivered: Sender<Delivered>,
    ) {
        tokio::spawn(async move {
            while let Some(committed) = rx_commit.recv().await {
                let delivered = Delivered {
                    sequence: committed.seq,
                    sample_view: committed.view,
                    leader: committed.leader,
                    payload: committed.payload,
                    first_seen: committed.first_seen,
                    committed_at: committed.committed_at,
                    leader_hint: Some((committed.current_view, committed.current_leader)),
                };
                if tx_delivered.send(delivered).await.is_err() {
                    break;
                }
            }
        });
    }

    pub fn print_key_file(filename: &str) -> Result<(), NodeError> {
        Secret::new().write(filename)
    }

    pub async fn analyze_block(&mut self) {
        while let Some(delivered) = self.commit.recv().await {
            // Ack the client transactions contained in every locally created
            // payload of this committed decision. Payloads created by other
            // replicas are not in our index and yield no acks here; their
            // clients are acked by the replica that ingested them.
            for digest in &delivered.payload {
                if let Some(txs) = self.ack_index.take(&digest.0) {
                    self.ack_router.ack(&txs);
                }
            }

            // Tell clients who leads now (stable-leader protocols only), so
            // a leader-targeting client can aim initially and re-aim after
            // elections. Sent on every delivery, not only on change: a
            // client may connect (or lose its targeted connection) at any
            // time, and heartbeat deliveries make this a steady beacon. The
            // hint carries the replica's live view and leader, not the
            // delivered batch's, so catch-up replay never advertises stale
            // leaders.
            if self.emit_leader_hints {
                if let Some((view, leader)) = &delivered.leader_hint {
                    if let Some(id) = self.replica_of.get(leader) {
                        self.ack_router
                            .broadcast(encode_leader_hint(*view, *id as u64));
                    }
                }
            }

            // Read the committed payloads once for both consumers: the
            // learning sample's transaction count, and the broadcast-mode
            // client-latency join (any committed transaction whose arrival
            // this replica stamped - shadow copy on a follower, tracked real
            // copy on the ingester - yields one locally measured sample).
            let shadow_active = !self.shadow_log.is_empty();
            let mut tx_count = 0usize;
            let mut resolved: Vec<Duration> = Vec::new();
            if self.learning.is_some() || shadow_active {
                for digest in &delivered.payload {
                    match self.store.read(digest.to_vec()).await {
                        Ok(Some(bytes)) => match bincode::deserialize::<Payload>(&bytes) {
                            Ok(payload) => {
                                tx_count += payload.transactions.len();
                                if shadow_active {
                                    for tx in &payload.transactions {
                                        if let Some(arrival) =
                                            tx_seq(tx).and_then(|seq| self.shadow_log.take(seq))
                                        {
                                            resolved.push(
                                                delivered
                                                    .committed_at
                                                    .saturating_duration_since(arrival),
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => warn!("Failed to deserialize committed payload: {}", e),
                        },
                        Ok(None) => warn!("Committed payload {} missing from store", digest),
                        Err(e) => warn!("Failed to read committed payload: {}", e),
                    }
                }
            }
            if !resolved.is_empty() {
                self.shadow_samples
                    .lock()
                    .unwrap()
                    .extend(resolved.iter().copied());
                if self.learning.is_some() && !self.shadow_latency_announced {
                    self.shadow_latency_announced = true;
                    info!(
                        "shadow-e2e: broadcast client mode detected; the agent report \
                         latency fields now carry client-perceived (arrival-to-commit) \
                         latencies instead of consensus latencies"
                    );
                }
            }

            // Feed the learning window: in broadcast client mode the latency
            // stream is the per-transaction client-perceived samples; outside
            // it, the per-decision consensus latency (first pre-prepare to
            // delivery), as before. A broadcast-mode delivery with no tracked
            // transactions (heartbeat, or replayed foreign history)
            // contributes no latency samples rather than mixing semantics.
            if let Some(learning) = &self.learning {
                let latencies = if !resolved.is_empty() {
                    resolved
                } else if shadow_active {
                    Vec::new()
                } else {
                    match delivered.first_seen {
                        Some(first_seen) => vec![delivered.committed_at - first_seen],
                        None => Vec::new(),
                    }
                };
                // Leader ids are 1-based in the report samples; 0 = unknown.
                let leader_id = self
                    .replica_of
                    .get(&delivered.leader)
                    .map(|id| *id as u64 + 1)
                    .unwrap_or(0);
                learning.record_consensus(LearningSample {
                    sequence: delivered.sequence,
                    view: delivered.sample_view,
                    leader_id,
                    batch_size: tx_count,
                    decision_time: delivered.committed_at,
                    latencies,
                    timeout: Duration::ZERO,
                });
            }
        }
    }
}
