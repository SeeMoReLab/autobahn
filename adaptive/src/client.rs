//! The benchmark client engine, shared by both workspaces' client binaries.
//!
//! One client process (on node0) opens `connections_per_target` connections
//! to every replica's transaction port (each connection models an
//! independent client: own sequence space, own sender pacing), splits the
//! configured rate evenly across all of them (ingestion is leader-agnostic,
//! and every supported protocol rotates leaders), and tracks each
//! transaction until its commit ack returns on the same connection (see
//! [`crate::ack`] for the wire formats). Successes record client-observed
//! latency; transactions with no ack within `request_timeout` count as
//! errors. A `Monitor` line in the SmartBFT smallbank format is printed every
//! `monitor_interval`.

use crate::ack::{decode_ack_frame, TX_HEADER_BYTES, TX_TAG_REAL};
use crate::monitor::{diff_snapshot, format_results, BenchmarkMetrics, MetricsSnapshot};
use crate::timestamped_log_tag;
use anyhow::{bail, Context, Result};
use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const CONNECT_RETRY: Duration = Duration::from_millis(200);
/// A single write blocked this long means the front is gone or hopelessly
/// behind. The kernel will not tell us: after a partition of more than a few
/// seconds TCP's retransmission timer has backed off to a minute or more, so
/// a lane stays idle long after the network is healed. This is also exactly
/// the point past which the transaction is counted as an error anyway, so
/// giving up on the socket costs nothing that was not already lost.
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(10);
const SWEEP_INTERVAL: Duration = Duration::from_millis(100);
/// Sender pacing frequency: each lane sends its allotment this many times
/// per second.
const PRECISION: u64 = 20;
type TxStream = futures::stream::SplitStream<Framed<TcpStream, LengthDelimitedCodec>>;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Transaction endpoints, one per replica (worker tx port / mempool front).
    pub targets: Vec<SocketAddr>,
    /// Parallel connections per target, each an independent sender. One
    /// framed TCP connection tops out well below high benchmark rates
    /// (every transaction is a flushed frame), so the rate through one
    /// front must be spread over several.
    pub connections_per_target: usize,
    /// Total submission rate in tx/s.
    pub rate: u64,
    /// Transaction size in bytes (>= 9).
    pub tx_size: usize,
    /// A transaction unacked for this long counts as an error.
    pub request_timeout: Duration,
    /// Cadence of the Monitor line.
    pub monitor_interval: Duration,
    /// Epoch ms at which to start submitting (the harness-wide synchronized
    /// start). None or a past value starts immediately.
    pub start_unix_ms: Option<u64>,
}

macro_rules! client_println {
    ($($arg:tt)*) => {
        println!("{} {}", timestamped_log_tag("client"), format!($($arg)*))
    };
}

pub async fn run_client(cfg: ClientConfig) -> Result<()> {
    if cfg.tx_size < TX_HEADER_BYTES {
        bail!("transaction size must be at least {} bytes", TX_HEADER_BYTES);
    }
    if cfg.targets.is_empty() {
        bail!("no targets given");
    }
    if cfg.rate == 0 {
        bail!("rate must be positive");
    }

    if cfg.connections_per_target == 0 {
        bail!("connections per target must be positive");
    }

    client_println!(
        "targets={:?} connections_per_target={} rate={} tx_size={} request_timeout_ms={} monitor_interval_ms={}",
        cfg.targets,
        cfg.connections_per_target,
        cfg.rate,
        cfg.tx_size,
        cfg.request_timeout.as_millis(),
        cfg.monitor_interval.as_millis()
    );

    // Connect to every target before starting; the harness may start the
    // client before the replicas are up.
    let mut connections = Vec::with_capacity(cfg.targets.len() * cfg.connections_per_target);
    for target in &cfg.targets {
        for _ in 0..cfg.connections_per_target {
            let stream = connect_with_retry(*target).await?;
            connections.push(Framed::new(stream, LengthDelimitedCodec::new()));
        }
    }
    client_println!(
        "all {} targets reachable ({} connections)",
        cfg.targets.len(),
        connections.len()
    );

    wait_for_start(cfg.start_unix_ms).await;
    client_println!("start sending transactions");

    let metrics = Arc::new(BenchmarkMetrics::new(cfg.request_timeout));
    let per_sender_rate =
        cfg.rate as f64 / (cfg.targets.len() * cfg.connections_per_target) as f64;

    let mut tasks = Vec::new();
    for (conn_index, framed) in connections.into_iter().enumerate() {
        let target = cfg.targets[conn_index / cfg.connections_per_target];
        let outstanding: Arc<Mutex<HashMap<u64, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        tasks.push(tokio::spawn(sender(
            framed,
            target,
            per_sender_rate,
            cfg.tx_size,
            Arc::clone(&outstanding),
            Arc::clone(&metrics),
        )));
        tasks.push(tokio::spawn(sweeper(
            cfg.request_timeout,
            Arc::clone(&outstanding),
            Arc::clone(&metrics),
        )));
    }

    let monitor = tokio::spawn(monitor_loop(cfg.monitor_interval, Arc::clone(&metrics)));

    let benchmark_start = Instant::now();
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;

    monitor.abort();
    for task in tasks {
        task.abort();
    }
    let final_snapshot = metrics.snapshot();
    println!(
        "{}",
        format_results("Benchmark", benchmark_start.elapsed(), &final_snapshot)
    );
    Ok(())
}

async fn connect_with_retry(target: SocketAddr) -> Result<TcpStream> {
    let mut logged = false;
    loop {
        match TcpStream::connect(target).await {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .context("failed to set TCP_NODELAY")?;
                return Ok(stream);
            }
            Err(err) => {
                if !logged {
                    client_println!("waiting for {} ({})", target, err);
                    logged = true;
                }
                tokio::time::sleep(CONNECT_RETRY).await;
            }
        }
    }
}

async fn wait_for_start(start_unix_ms: Option<u64>) {
    let Some(start_ms) = start_unix_ms else {
        return;
    };
    // The same start line the CppBedrock, SmartBFT and Tendermint clients print.
    client_println!("Waiting until benchmark start unix ms {}", start_ms);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64;
    if start_ms <= now_ms {
        client_println!(
            "start time {} already passed (now {}), starting immediately",
            start_ms,
            now_ms
        );
        return;
    }
    let delay = Duration::from_millis(start_ms - now_ms);
    client_println!("waiting {:?} until synchronized start", delay);
    tokio::time::sleep(delay).await;
}

/// How often a lane reports transactions it could not generate.
const SHORTFALL_REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// Paces one lane at `rate` tx/s over the ticks that actually run.
///
/// Credit only accrues on executed ticks, so a lane that was blocked in a
/// write (its front down or saturated) resumes at its nominal rate instead of
/// replaying the missed allowance in one burst - the ticks it missed are
/// skipped (`MissedTickBehavior::Skip`) and the shortfall is reported. The
/// fractional credit keeps the long-run rate exact for rates that do not
/// divide evenly by the tick frequency.
struct LanePacer {
    rate: f64,
    credit: f64,
    last_tick: Instant,
    shortfall: f64,
    report_at: Instant,
}

impl LanePacer {
    fn new(rate: f64) -> Self {
        let now = Instant::now();
        Self {
            rate,
            credit: 0.0,
            last_tick: now,
            shortfall: 0.0,
            report_at: now + SHORTFALL_REPORT_INTERVAL,
        }
    }

    /// Account for the time since the previous tick and return the number of
    /// transactions to send now.
    fn tick(&mut self, now: Instant, label: &str) -> u64 {
        let period = 1.0 / PRECISION as f64;
        let gap = now.duration_since(self.last_tick).as_secs_f64();
        self.last_tick = now;
        if gap > 1.5 * period {
            self.shortfall += (gap - period) * self.rate;
        }
        if self.shortfall >= 1.0 && now >= self.report_at {
            client_println!(
                "{} fell behind by {} transactions (blocked or too slow); they were not generated",
                label,
                self.shortfall as u64
            );
            self.shortfall = 0.0;
            self.report_at = now + SHORTFALL_REPORT_INTERVAL;
        }
        self.credit += self.rate * period;
        let burst = self.credit as u64;
        self.credit -= burst as f64;
        burst
    }

    /// Resume pacing from `now` after an outage: no credit and no shortfall
    /// accrue for the time the lane was down.
    fn idle(&mut self, now: Instant) {
        self.credit = 0.0;
        self.last_tick = now;
    }
}

async fn sender(
    framed: Framed<TcpStream, LengthDelimitedCodec>,
    target: SocketAddr,
    rate: f64,
    tx_size: usize,
    outstanding: Arc<Mutex<HashMap<u64, Instant>>>,
    metrics: Arc<BenchmarkMetrics>,
) {
    let (mut sink, stream) = framed.split();
    tokio::spawn(receiver(
        stream,
        target,
        Arc::clone(&outstanding),
        Arc::clone(&metrics),
    ));
    let tick_period = Duration::from_millis(1000 / PRECISION);
    let mut interval = tokio::time::interval(tick_period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let label = format!("lane to {}", target);
    let mut pacer = LanePacer::new(rate);
    let mut seq: u64 = 0;
    loop {
        interval.tick().await;
        let tick_start = Instant::now();
        let burst = pacer.tick(tick_start, &label);

        for _ in 0..burst {
            seq += 1;
            let mut tx = BytesMut::with_capacity(tx_size);
            tx.put_u8(TX_TAG_REAL);
            tx.put_u64(seq);
            tx.resize(tx_size, 0u8);
            outstanding.lock().unwrap().insert(seq, Instant::now());
            let outcome = match tokio::time::timeout(WRITE_STALL_TIMEOUT, sink.send(tx.freeze())).await {
                Ok(Ok(())) => None,
                Ok(Err(err)) => Some(format!("{}", err)),
                Err(_) => Some(format!("blocked for {:?}", WRITE_STALL_TIMEOUT)),
            };
            if let Some(err) = outcome {
                // A partition (or a replica restart) destroys this socket.
                // Everything still outstanding on it is counted as an error
                // by the sweeper, but the lane itself must come back: a real
                // client reconnects, and without that this benchmark
                // permanently stops offering this front its share of the
                // load, which caps throughput at (n-1)/n forever.
                client_println!("connection to {} failed: {}; reconnecting", target, err);
                let stream = match connect_with_retry(target).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        client_println!("lane to {} could not reconnect: {}", target, err);
                        return;
                    }
                };
                let (new_sink, new_stream) = Framed::new(stream, LengthDelimitedCodec::new()).split();
                sink = new_sink;
                tokio::spawn(receiver(
                    new_stream,
                    target,
                    Arc::clone(&outstanding),
                    Arc::clone(&metrics),
                ));
                client_println!("lane to {} reconnected", target);
                // Drop the rest of this burst and resume pacing from now, so
                // the outage is not replayed as one giant burst.
                pacer.idle(Instant::now());
                break;
            }
        }
    }
}

async fn receiver(
    mut stream: TxStream,
    target: SocketAddr,
    outstanding: Arc<Mutex<HashMap<u64, Instant>>>,
    metrics: Arc<BenchmarkMetrics>,
) {
    while let Some(frame) = stream.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(err) => {
                client_println!("ack stream from {} failed: {}", target, err);
                return;
            }
        };
        let seqs = match decode_ack_frame(&frame) {
            Ok(seqs) => seqs,
            Err(err) => {
                client_println!("malformed ack frame from {}: {}", target, err);
                continue;
            }
        };
        let now = Instant::now();
        let mut map = outstanding.lock().unwrap();
        for seq in seqs {
            // A seq missing here already timed out and was counted as an
            // error; a late ack must not double-count.
            if let Some(sent_at) = map.remove(&seq) {
                metrics.record(true, now - sent_at);
            }
        }
    }
    client_println!("ack stream from {} closed", target);
}

async fn sweeper(
    request_timeout: Duration,
    outstanding: Arc<Mutex<HashMap<u64, Instant>>>,
    metrics: Arc<BenchmarkMetrics>,
) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        let now = Instant::now();
        let mut expired = 0usize;
        {
            let mut map = outstanding.lock().unwrap();
            map.retain(|_, sent_at| {
                if now.duration_since(*sent_at) > request_timeout {
                    expired += 1;
                    false
                } else {
                    true
                }
            });
        }
        for _ in 0..expired {
            metrics.record(false, Duration::ZERO);
        }
    }
}

async fn monitor_loop(monitor_interval: Duration, metrics: Arc<BenchmarkMetrics>) {
    let mut previous = MetricsSnapshot::default();
    let mut last_tick = Instant::now();
    let mut interval = tokio::time::interval(monitor_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await; // completes immediately
    loop {
        interval.tick().await;
        let now = Instant::now();
        let snapshot = metrics.snapshot();
        let delta = diff_snapshot(&previous, &snapshot);
        println!("{}", format_results("Monitor", now - last_tick, &delta));
        previous = snapshot;
        last_tick = now;
    }
}
