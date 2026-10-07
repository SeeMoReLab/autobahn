use crate::config::Export as _;
use crate::config::{Committee, Parameters, Secret};
use adaptive::ack::{AckIndex, AckRouter};
use adaptive::episode::{hotstuff_hooks, LearningConfig, LearningManager, ProtocolHooks};
use adaptive::failure::{FaultController, ProtocolSection};
use adaptive::metrics::LearningSample;
use adaptive::timeouts::TimeoutCell;
use crypto::{Digest, PublicKey, SignatureService};
use hotstuff::ConsensusError;
use log::{info, warn};
use mempool::{Mempool, MempoolError, Payload};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::{Store, StoreError};
use thiserror::Error;
use tokio::sync::mpsc::{channel, Receiver, Sender};

/// Bound on batches sealed locally but not yet observed as committed. Beyond
/// this, the oldest pending batches are dropped from the ack index and their
/// transactions surface as client-side timeouts.
const ACK_INDEX_CAPACITY: usize = 100_000;

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
    MempoolError(#[from] MempoolError),

    #[error("Adaptive-timer setup error: {0}")]
    AdaptiveError(String),
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
    /// What the learning sample's `view` should be: batched HotStuff reports
    /// a cumulative round-gap counter (see the adapter).
    pub sample_view: u64,
    pub leader: PublicKey,
    pub payload: Vec<Digest>,
    pub first_seen: Option<Instant>,
    pub committed_at: Instant,
}

pub struct Node {
    pub commit: Receiver<Delivered>,
    store: Store,
    ack_index: Arc<AckIndex>,
    ack_router: Arc<AckRouter>,
    learning: Option<Arc<LearningManager>>,
    replica_of: HashMap<PublicKey, u32>,
}

impl Node {
    pub async fn new(
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

        // Adaptive-timer wiring.
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
        let faults = match (&adaptive_opts.failure_spec, adaptive_opts.failure_start_unix_ms)
        {
            (Some(spec), Some(start_ms)) => {
                if adaptive_opts.replica_map.is_none() {
                    return Err(NodeError::AdaptiveError(
                        "--failure-spec requires --replica-map".into(),
                    ));
                }
                Arc::new(
                    FaultController::load_file(spec, start_ms, ProtocolSection::Hotstuff)
                        .map_err(|e| NodeError::AdaptiveError(format!("{:#}", e)))?,
                )
            }
            (Some(_), None) => {
                return Err(NodeError::AdaptiveError(
                    "--failure-spec requires --failure-start-unix-ms".into(),
                ));
            }
            _ => Arc::new(FaultController::disabled()),
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
            faults,
            replica_id: adaptive_opts.replica_id,
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

        info!("Node {} successfully booted", name);
        Ok(Self {
            commit: rx_delivered,
            store,
            ack_index,
            ack_router,
            learning,
            replica_of,
        })
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

            // The learning sample counts the transactions in the committed
            // payloads; the latency is the per-decision consensus latency
            // (first sighting to delivery).
            if let Some(learning) = &self.learning {
                let mut tx_count = 0usize;
                for digest in &delivered.payload {
                    match self.store.read(digest.to_vec()).await {
                        Ok(Some(bytes)) => match bincode::deserialize::<Payload>(&bytes) {
                            Ok(payload) => tx_count += payload.transactions.len(),
                            Err(e) => warn!("Failed to deserialize committed payload: {}", e),
                        },
                        Ok(None) => warn!("Committed payload {} missing from store", digest),
                        Err(e) => warn!("Failed to read committed payload: {}", e),
                    }
                }
                let latencies = match delivered.first_seen {
                    Some(first_seen) => vec![delivered.committed_at - first_seen],
                    None => Vec::new(),
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
                });
            }
        }
    }
}
