#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
// Copyright(C) Facebook, Inc. and its affiliates.
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{crate_name, crate_version, App, AppSettings, ArgMatches, SubCommand};
use config::Export as _;
use config::Import as _;
use config::{Committee, KeyPair, Parameters, WorkerId};
use crypto::{Digest, PublicKey, SignatureService};
use env_logger::Env;
use adaptive::episode::{autobahn_hooks, LearningConfig, LearningManager};
use adaptive::failure::{FaultController, ProtocolSection};
use adaptive::metrics::LearningSample;
use adaptive::timeouts::TimeoutCell;
use network::SimpleSender;
use primary::Header;
use primary::Primary;
use primary::PrimaryInstrumentation;
use primary::PrimaryWorkerMessage;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver};
use worker::Worker;

/// The default channel capacity.
pub const CHANNEL_CAPACITY: usize = 1_000;

#[tokio::main]
async fn main() -> Result<()> {
    //std::env::set_var("RUST_BACKTRACE", "1");
    
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("A research implementation of Sailfish.")
        .args_from_usage("-v... 'Sets the level of verbosity'")
        .subcommand(
            SubCommand::with_name("generate_keys")
                .about("Print a fresh key pair to file")
                .args_from_usage("--filename=<FILE> 'The file where to print the new key pair'"),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Run a node")
                .args_from_usage("--keys=<FILE> 'The file containing the node keys'")
                .args_from_usage("--committee=<FILE> 'The file containing committee information'")
                .args_from_usage("--parameters=[FILE] 'The file containing the node parameters'")
                .args_from_usage("--store=<PATH> 'The path where to create the data store'")
                .args_from_usage("--replica-id=[INT] 'Global 0-based id of this replica (default 0)'")
                .args_from_usage("--replica-map=[FILE] 'replica_map.json mapping public keys to replica ids'")
                .args_from_usage("--failure-spec=[FILE] 'failure_spec.xml for proposal-delay injection'")
                .args_from_usage("--failure-start-unix-ms=[INT] 'Shared injection start timestamp (epoch ms)'")
                .args_from_usage("--learning 'Enable the learning-agent episode loop'")
                .args_from_usage("--agent-target=[ADDR] 'Learning agent host:port (default 127.0.0.1:15501)'")
                .args_from_usage("--learning-feature-duration=[INT] 'Feature window ms (default 10000)'")
                .args_from_usage("--learning-reply-wait=[INT] 'Recommendation wait ms (default 2000)'")
                .args_from_usage("--learning-warmup-duration=[INT] 'Post-apply warm-up ms (default 3000)'")
                .args_from_usage("--learning-reward-duration=[INT] 'Reward window ms (default 5000)'")
                .subcommand(SubCommand::with_name("primary").about("Run a single primary"))
                .subcommand(
                    SubCommand::with_name("worker")
                        .about("Run a single worker")
                        .args_from_usage("--id=<INT> 'The worker id'"),
                )
                .setting(AppSettings::SubcommandRequiredElseHelp),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    let log_level = match matches.occurrences_of("v") {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or(log_level));
    #[cfg(feature = "benchmark")]
    logger.format_timestamp_millis();
    logger.init();

    match matches.subcommand() {
        ("generate_keys", Some(sub_matches)) => KeyPair::new()
            .export(sub_matches.value_of("filename").unwrap())
            .context("Failed to generate key pair")?,
        ("run", Some(sub_matches)) => run(sub_matches).await?,
        _ => unreachable!(),
    }
    Ok(())
}

// Runs either a worker or a primary.
async fn run(matches: &ArgMatches<'_>) -> Result<()> {
    let key_file = matches.value_of("keys").unwrap();
    let committee_file = matches.value_of("committee").unwrap();
    let parameters_file = matches.value_of("parameters");
    let store_path = matches.value_of("store").unwrap();

    // Read the committee and node's keypair from file.
    let keypair = KeyPair::import(key_file).context("Failed to load the node's keypair")?;
    let name = keypair.name;
    let committee =
        Committee::import(committee_file).context("Failed to load the committee information")?;

    // Load default parameters if none are specified.
    let parameters = match parameters_file {
        Some(filename) => {
            Parameters::import(filename).context("Failed to load the node's parameters")?
        }
        None => Parameters::default(),
    };

    // The `SignatureService` provides signatures on input digests.
    let signature_service = SignatureService::new(keypair.secret);

    // Make the data store.
    let store = Store::new(store_path).context("Failed to create a store")?;

    // Channels the sequence of certificates.
    let (tx_output, rx_output) = channel(CHANNEL_CAPACITY);

    // Channel for sending headers between DAG and Consensus
    let (tx_sailfish, rx_sailfish) = channel(CHANNEL_CAPACITY);

    // Channel for sending loopback headerds that completed validation between DAG and Consensus
    //let (tx_validation, rx_validation) = channel(CHANNEL_CAPACITY);

    // Channel for indicating commit and that new header should be proposed
    //let (tx_ticket, rx_ticket) = channel(CHANNEL_CAPACITY);

    // Adaptive-timer wiring (primary only). Cells start at the parameters'
    // values; the learning agent's recommendations update them at runtime.
    let parse_u64 = |name: &str| -> Result<Option<u64>> {
        matches
            .value_of(name)
            .map(|v| {
                v.parse::<u64>()
                    .with_context(|| format!("invalid --{}", name))
            })
            .transpose()
    };
    let replica_id = parse_u64("replica-id")?.unwrap_or(0) as u32;
    let replica_of: HashMap<PublicKey, u32> = match matches.value_of("replica-map") {
        Some(path) => {
            let data = std::fs::read(path)
                .with_context(|| format!("failed to read replica map {}", path))?;
            serde_json::from_slice(&data)
                .with_context(|| format!("failed to parse replica map {}", path))?
        }
        None => HashMap::new(),
    };
    let first_seen: Arc<Mutex<HashMap<Digest, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut analyze_learning: Option<Arc<LearningManager>> = None;

    // Check whether to run a primary, a worker, or an entire authority.
    //Note: Each node has at most one worker. Workers that don't include a primary (e.g. are not an entire authority) use PrimaryConnector to connect to a designated primary.
    match matches.subcommand() {
        // Spawn the primary and consensus core.
        ("primary", _) => {
            // The agent sets only timeout_delay; the fast-path wait stays at
            // its parameters.json value.
            let timeout_delay = TimeoutCell::new(Duration::from_millis(parameters.timeout_delay));
            let fast_path_timeout =
                TimeoutCell::new(Duration::from_millis(parameters.fast_path_timeout));
            let faults = match (
                matches.value_of("failure-spec"),
                parse_u64("failure-start-unix-ms")?,
            ) {
                (Some(spec), Some(start_ms)) => {
                    anyhow::ensure!(
                        !replica_of.is_empty(),
                        "--failure-spec requires --replica-map"
                    );
                    Arc::new(
                        FaultController::load_file(
                            spec,
                            start_ms,
                            ProtocolSection::Autobahn,
                        )
                        .context("failed to load failure spec")?,
                    )
                }
                (Some(_), None) => {
                    anyhow::bail!("--failure-spec requires --failure-start-unix-ms")
                }
                _ => Arc::new(FaultController::disabled()),
            };
            let learning = if matches.is_present("learning") {
                anyhow::ensure!(!replica_of.is_empty(), "--learning requires --replica-map");
                let mut cfg = LearningConfig::new(
                    replica_id,
                    matches
                        .value_of("agent-target")
                        .unwrap_or("127.0.0.1:15501")
                        .to_string(),
                );
                cfg.feature_duration =
                    Duration::from_millis(parse_u64("learning-feature-duration")?.unwrap_or(10_000));
                cfg.reply_wait =
                    Duration::from_millis(parse_u64("learning-reply-wait")?.unwrap_or(2_000));
                cfg.warmup_duration =
                    Duration::from_millis(parse_u64("learning-warmup-duration")?.unwrap_or(3_000));
                cfg.reward_duration =
                    Duration::from_millis(parse_u64("learning-reward-duration")?.unwrap_or(5_000));
                let manager = LearningManager::new(cfg, autobahn_hooks(timeout_delay.clone()))
                    .context("failed to start learning manager")?;
                Some(manager)
            } else {
                None
            };
            analyze_learning = learning.clone();
            let instrumentation = PrimaryInstrumentation {
                timeout_delay,
                fast_path_timeout,
                learning,
                faults,
                first_seen: Arc::clone(&first_seen),
                replica_id,
                replica_of: replica_of.clone(),
            };
            let (tx_new_certificates, rx_new_certificates) = channel(CHANNEL_CAPACITY);
            let (tx_feedback, rx_feedback) = channel(CHANNEL_CAPACITY);
            let (tx_committer, rx_committer) = channel(CHANNEL_CAPACITY);
            let (tx_pushdown_cert, rx_pushdown_cert) = channel(CHANNEL_CAPACITY);
            let(tx_request_header_sync, rx_request_header_sync) = channel(CHANNEL_CAPACITY);

            Primary::spawn(
                name,
                committee.clone(),
                parameters.clone(),
                signature_service.clone(),
                store.clone(),
                /* tx_consensus */ tx_new_certificates,
                tx_committer,
                rx_committer,
                /* rx_consensus */ rx_feedback,
                tx_sailfish,
                //rx_ticket,
                rx_pushdown_cert,
                rx_request_header_sync,
                tx_output,
                instrumentation,
            );
            /*Consensus::spawn(
                name,
                committee,
                parameters,
                signature_service,
                store,
                /* rx_consensus */ rx_new_certificates,
                rx_committer,
                /* tx_mempool */ tx_feedback,
                tx_output,
                tx_ticket,
                tx_validation,
                rx_sailfish,
                tx_pushdown_cert,
                tx_request_header_sync,
            );*/
        }

        // Spawn a single worker.
        ("worker", Some(sub_matches)) => {
            let id = sub_matches
                .value_of("id")
                .unwrap()
                .parse::<WorkerId>()
                .context("The worker id must be a positive integer")?;
            Worker::spawn(keypair.name, id, committee.clone(), parameters, store);
        }
        _ => unreachable!(),
    }

    // Analyze the consensus' output.
    analyze(rx_output, name, committee, analyze_learning, first_seen, replica_of).await;

    // If this expression is reached, the program ends and all other tasks terminate.
    unreachable!();
}

/// Receives an ordered list of committed headers. Notifies our own workers of
/// the committed batch digests so they can ack the client transactions those
/// batches contain, and feeds the learning window (only the primary process
/// ever receives output here).
async fn analyze(
    mut rx_output: Receiver<Header>,
    name: PublicKey,
    committee: Committee,
    learning: Option<Arc<LearningManager>>,
    first_seen: Arc<Mutex<HashMap<Digest, Instant>>>,
    replica_of: HashMap<PublicKey, u32>,
) {
    let worker_addresses: Vec<_> = committee
        .our_workers(&name)
        .expect("Our public key is not in the committee")
        .iter()
        .map(|addresses| addresses.primary_to_worker)
        .collect();
    let mut network = SimpleSender::new();
    // Local commit index; used as the sample sequence since header heights
    // interleave across lanes.
    let mut commit_index: u64 = 0;

    while let Some(header) = rx_output.recv().await {
        commit_index += 1;

        if let Some(learning) = &learning {
            let committed_at = Instant::now();
            let seen = {
                let mut map = first_seen.lock().unwrap();
                if commit_index % 1024 == 0 {
                    // Prune entries for headers that will never commit.
                    map.retain(|_, seen| seen.elapsed() < Duration::from_secs(600));
                }
                map.remove(&header.id)
            };
            let latencies = match seen {
                Some(seen) => vec![committed_at - seen],
                None => Vec::new(),
            };
            // Leader ids are 1-based in the report samples; 0 = unknown.
            let leader_id = replica_of
                .get(&header.author)
                .map(|id| *id as u64 + 1)
                .unwrap_or(0);
            learning.record_consensus(LearningSample {
                sequence: commit_index,
                // View/regency tracking is not surfaced per committed header
                // by this engine; view changes are recorded separately by
                // the core, so regency_change_count stays 0.
                view: 0,
                leader_id,
                // Batch size counts payload digests; transaction counts live
                // in the worker processes.
                batch_size: header.payload.len(),
                decision_time: committed_at,
                latencies,
                timeout: Duration::ZERO,
            });
        }

        let digests: Vec<Digest> = header.payload.keys().cloned().collect();
        if digests.is_empty() {
            continue;
        }
        let message = PrimaryWorkerMessage::Committed(digests);
        let serialized =
            bincode::serialize(&message).expect("Failed to serialize commit notification");
        for address in &worker_addresses {
            network.send(*address, Bytes::from(serialized.clone())).await;
        }
    }
}
