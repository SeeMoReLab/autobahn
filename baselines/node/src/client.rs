use adaptive::client::{run_client, ClientConfig, TargetMode};
use anyhow::{Context, Result};
use clap::{crate_name, crate_version, App, AppSettings};
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client: submits transactions to every replica, tracks commit acks, and prints per-interval Monitor lines.")
        .args_from_usage("--targets=<ADDR>... 'Transaction endpoints, one per replica'")
        .args_from_usage("--size=<INT> 'The size of each transaction in bytes'")
        .args_from_usage("--rate=<INT> 'The total rate (txs/s), split across targets'")
        .args_from_usage("--request-timeout=<INT> 'Unacked transactions count as errors after this many ms'")
        .args_from_usage("--target-mode=[MODE] 'spread: split rate across all replicas (default); leader: send everything to the current leader, following leader hints; broadcast: like leader, plus shadow tx headers to every other replica so followers can measure client latency'")
        .args_from_usage("--connections-per-target=[INT] 'Parallel connections (independent senders) per replica (default 4)'")
        .args_from_usage("--monitor-interval=[INT] 'Milliseconds between Monitor lines (default 1000)'")
        .args_from_usage("--start-unix-ms=[INT] 'Epoch ms at which to start submitting'")
        .args_from_usage("--duration=[INT] 'How many seconds to run (default: until SIGINT)'")
        .setting(AppSettings::ArgRequiredElseHelp)
        .get_matches();

    let targets = matches
        .values_of("targets")
        .unwrap()
        .map(|x| x.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid target address")?;
    let tx_size = matches
        .value_of("size")
        .unwrap()
        .parse::<usize>()
        .context("The size of transactions must be a non-negative integer")?;
    let rate = matches
        .value_of("rate")
        .unwrap()
        .parse::<u64>()
        .context("The rate of transactions must be a non-negative integer")?;
    let request_timeout = matches
        .value_of("request-timeout")
        .unwrap()
        .parse::<u64>()
        .map(Duration::from_millis)
        .context("The request timeout must be a non-negative integer (ms)")?;
    let monitor_interval = matches
        .value_of("monitor-interval")
        .unwrap_or("1000")
        .parse::<u64>()
        .map(Duration::from_millis)
        .context("The monitor interval must be a non-negative integer (ms)")?;
    let start_unix_ms = matches
        .value_of("start-unix-ms")
        .map(|x| x.parse::<u64>())
        .transpose()
        .context("The start time must be epoch milliseconds")?;
    let duration = matches
        .value_of("duration")
        .map(|x| x.parse::<u64>().map(Duration::from_secs))
        .transpose()
        .context("The duration must be a non-negative integer (seconds)")?;
    let target_mode = TargetMode::parse(matches.value_of("target-mode").unwrap_or("spread"))
        .map_err(anyhow::Error::msg)?;
    let connections_per_target = matches
        .value_of("connections-per-target")
        .unwrap_or("4")
        .parse::<usize>()
        .context("The connections per target must be a positive integer")?;

    run_client(ClientConfig {
        targets,
        target_mode,
        connections_per_target,
        rate,
        tx_size,
        request_timeout,
        monitor_interval,
        start_unix_ms,
        duration,
    })
    .await
}
