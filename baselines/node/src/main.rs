mod config;
mod node;

use crate::config::Export as _;
use crate::config::{Committee, Secret};
use crate::node::{AdaptiveOptions, LearningOptions, Node, ProtocolKind};
use clap::{crate_name, crate_version, App, AppSettings, SubCommand};
use hotstuff::Committee as ConsensusCommittee;
use env_logger::Env;
use futures::future::join_all;
use log::error;
use mempool::Committee as MempoolCommittee;
use std::fs;
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("A research implementation of the HostStuff protocol.")
        .args_from_usage("-v... 'Sets the level of verbosity'")
        .subcommand(
            SubCommand::with_name("keys")
                .about("Print a fresh key pair to file")
                .args_from_usage("--filename=<FILE> 'The file where to print the new key pair'"),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Runs a single node")
                .args_from_usage("--keys=<FILE> 'The file containing the node keys'")
                .args_from_usage("--committee=<FILE> 'The file containing committee information'")
                .args_from_usage("--parameters=[FILE] 'The file containing the node parameters'")
                .args_from_usage("--store=<PATH> 'The path where to create the data store'")
                .args_from_usage("--protocol=[NAME] 'Consensus protocol: hotstuff, pbft, or sbft (default hotstuff)'")
                .args_from_usage("--replica-id=[INT] 'Global 0-based id of this replica (default 0)'")
                .args_from_usage("--replica-map=[FILE] 'replica_map.json mapping public keys to replica ids'")
                .args_from_usage("--failure-spec=[FILE] 'failure_spec.xml for proposal-delay injection'")
                .args_from_usage("--failure-start-unix-ms=[INT] 'Shared injection start timestamp (epoch ms)'")
                .args_from_usage("--learning 'Enable the learning-agent episode loop'")
                .args_from_usage("--agent-target=[ADDR] 'Learning agent host:port (default 127.0.0.1:15501)'")
                .args_from_usage("--learning-feature-duration=[INT] 'Feature window ms (default 10000)'")
                .args_from_usage("--learning-reply-wait=[INT] 'Recommendation wait ms (default 2000)'")
                .args_from_usage("--learning-warmup-duration=[INT] 'Post-apply warm-up ms (default 3000)'")
                .args_from_usage("--learning-reward-duration=[INT] 'Reward window ms (default 5000)'"),
        )
        .subcommand(
            SubCommand::with_name("deploy")
                .about("Deploys a network of nodes locally")
                .args_from_usage("--nodes=<INT> 'The number of nodes to deploy'"),
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
        ("keys", Some(subm)) => {
            let filename = subm.value_of("filename").unwrap();
            if let Err(e) = Node::print_key_file(&filename) {
                error!("{}", e);
            }
        }
        ("run", Some(subm)) => {
            let key_file = subm.value_of("keys").unwrap();
            let committee_file = subm.value_of("committee").unwrap();
            let parameters_file = subm.value_of("parameters");
            let store_path = subm.value_of("store").unwrap();
            let adaptive_opts = match parse_adaptive_options(subm) {
                Ok(opts) => opts,
                Err(e) => {
                    error!("{}", e);
                    return;
                }
            };
            let protocol = match ProtocolKind::parse(subm.value_of("protocol").unwrap_or("hotstuff")) {
                Ok(protocol) => protocol,
                Err(e) => {
                    error!("{}", e);
                    return;
                }
            };
            match Node::new(protocol, committee_file, key_file, store_path, parameters_file, adaptive_opts).await {
                Ok(mut node) => {
                    tokio::spawn(async move {
                        node.analyze_block().await;
                    })
                    .await
                    .expect("Failed to analyze committed blocks");
                }
                Err(e) => error!("{}", e),
            }
        }
        ("deploy", Some(subm)) => {
            let nodes = subm.value_of("nodes").unwrap();
            match nodes.parse::<usize>() {
                Ok(nodes) if nodes > 0 => match deploy_testbed(nodes) {
                    Ok(handles) => {
                        let _ = join_all(handles).await;
                    }
                    Err(e) => error!("Failed to deploy testbed: {}", e),
                },
                _ => error!("The number of nodes must be a positive integer"),
            }
        }
        _ => unreachable!(),
    }
}

fn parse_adaptive_options(subm: &clap::ArgMatches<'_>) -> Result<AdaptiveOptions, String> {
    let parse_u64 = |name: &str| -> Result<Option<u64>, String> {
        subm.value_of(name)
            .map(|v| v.parse::<u64>().map_err(|e| format!("invalid --{}: {}", name, e)))
            .transpose()
    };
    let replica_id = parse_u64("replica-id")?.unwrap_or(0) as u32;
    let learning = if subm.is_present("learning") {
        Some(LearningOptions {
            agent_target: subm
                .value_of("agent-target")
                .unwrap_or("127.0.0.1:15501")
                .to_string(),
            feature_duration_ms: parse_u64("learning-feature-duration")?.unwrap_or(10_000),
            reply_wait_ms: parse_u64("learning-reply-wait")?.unwrap_or(2_000),
            warmup_duration_ms: parse_u64("learning-warmup-duration")?.unwrap_or(3_000),
            reward_duration_ms: parse_u64("learning-reward-duration")?.unwrap_or(5_000),
        })
    } else {
        None
    };
    Ok(AdaptiveOptions {
        replica_id,
        replica_map: subm.value_of("replica-map").map(String::from),
        failure_spec: subm.value_of("failure-spec").map(String::from),
        failure_start_unix_ms: parse_u64("failure-start-unix-ms")?,
        learning,
    })
}

fn deploy_testbed(nodes: usize) -> Result<Vec<JoinHandle<()>>, Box<dyn std::error::Error>> {
    let keys: Vec<_> = (0..nodes).map(|_| Secret::new()).collect();

    // Print the committee file.
    let epoch = 1;
    let mempool_committee = MempoolCommittee::new(
        keys.iter()
            .enumerate()
            .map(|(i, key)| {
                let name = key.name;
                let front = format!("127.0.0.1:{}", 7000 + i).parse().unwrap();
                let mempool = format!("127.0.0.1:{}", 7100 + i).parse().unwrap();
                (name, front, mempool)
            })
            .collect(),
        epoch,
    );
    let consensus_committee = ConsensusCommittee::new(
        keys.iter()
            .enumerate()
            .map(|(i, key)| {
                let name = key.name;
                let stake = 1;
                let addresses = format!("127.0.0.1:{}", 7200 + i).parse().unwrap();
                (name, stake, addresses)
            })
            .collect(),
        epoch,
    );
    let committee_file = "committee.json";
    let _ = fs::remove_file(committee_file);
    Committee {
        mempool: mempool_committee,
        consensus: consensus_committee,
    }
    .write(committee_file)?;

    // Write the key files and spawn all nodes.
    keys.iter()
        .enumerate()
        .map(|(i, keypair)| {
            let key_file = format!("node_{}.json", i);
            let _ = fs::remove_file(&key_file);
            keypair.write(&key_file)?;

            let store_path = format!("db_{}", i);
            let _ = fs::remove_dir_all(&store_path);

            Ok(tokio::spawn(async move {
                match Node::new(ProtocolKind::Hotstuff, committee_file, &key_file, &store_path, None, AdaptiveOptions::default()).await {
                    // Process committed blocks (acks client transactions).
                    Ok(mut node) => node.analyze_block().await,
                    Err(e) => error!("{}", e),
                }
            }))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()
}
