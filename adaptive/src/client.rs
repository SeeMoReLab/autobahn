//! The benchmark client engine, shared by both workspaces' client binaries.
//!
//! One client process (on node0) opens `connections_per_target` connections
//! to every replica's transaction port (each connection models an
//! independent client: own sequence space, own sender pacing), splits the
//! configured rate across the sending connections, and tracks each
//! transaction until its commit ack returns on the same connection (see
//! [`crate::ack`] for the wire formats). Successes record client-observed
//! latency; transactions with no ack within `request_timeout` count as
//! errors. A `Monitor` line in the SmartBFT smallbank format is printed every
//! `monitor_interval`.

use crate::ack::{
    decode_ack_frame, decode_leader_hint, TX_HEADER_BYTES, TX_TAG_REAL, TX_TAG_SHADOW,
    TX_TAG_TRACKED,
};
use crate::monitor::{diff_snapshot, format_results, BenchmarkMetrics, MetricsSnapshot};
use crate::timestamped_log_tag;
use anyhow::{bail, Context, Result};
use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const CONNECT_RETRY: Duration = Duration::from_millis(200);
const SWEEP_INTERVAL: Duration = Duration::from_millis(100);

type TxSink = futures::stream::SplitSink<Framed<TcpStream, LengthDelimitedCodec>, bytes::Bytes>;
type TxStream = futures::stream::SplitStream<Framed<TcpStream, LengthDelimitedCodec>>;

/// How transactions are distributed over the replica fronts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetMode {
    /// The rate is split evenly across all fronts (the mempool-architecture
    /// default; ingestion is leader-agnostic).
    Spread,
    /// The full rate goes to the current consensus leader's front, following
    /// the leader hints replicas push on the ack connections (classical
    /// PBFT-style submission; the leader batches everything, as in the
    /// SmartBFT baseline). Only meaningful for stable-leader protocols.
    Leader,
    /// Like `Leader` for the real transaction stream, but every other front
    /// additionally receives the 9-byte header of each transaction as a
    /// shadow copy (classical PBFT client broadcast). Followers timestamp
    /// the shadow arrivals, giving every replica a local, leader-independent
    /// measure of client-perceived latency. Only meaningful for
    /// stable-leader protocols.
    Broadcast,
}

impl TargetMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "spread" => Ok(Self::Spread),
            "leader" => Ok(Self::Leader),
            "broadcast" => Ok(Self::Broadcast),
            other => Err(format!(
                "unknown target mode {:?}; expected spread, leader, or broadcast",
                other
            )),
        }
    }
}

/// Broadcast mode stripes each lane's seqs into a disjoint range so that a
/// seq is globally unique across the client process (replica-side arrival
/// tracking is keyed by seq alone). 2^48 transactions per lane is years of
/// runtime at benchmark rates.
const LANE_SHIFT: u32 = 48;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Transaction endpoints, one per replica (worker tx port / mempool front).
    pub targets: Vec<SocketAddr>,
    /// How transactions are distributed over the targets.
    pub target_mode: TargetMode,
    /// Parallel connections per target, each an independent sender. One
    /// framed TCP connection tops out well below high benchmark rates
    /// (every transaction is a flushed frame), so the rate through one
    /// front - all of it, in leader mode - must be spread over several.
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
    /// How long to submit for. None runs until SIGINT.
    pub duration: Option<Duration>,
}

macro_rules! client_println {
    ($($arg:tt)*) => {
        println!("{} {}", timestamped_log_tag("client"), format!($($arg)*))
    };
}

/// Tracks leader hints per front and decides which replica the senders
/// should target. A hint is only adopted once f+1 distinct fronts' latest
/// hints agree on the same leader, so a single stale or lying replica can
/// never move the stream (a replica replaying history during catch-up used
/// to flap the target dozens of times per run). Among agreeing fronts the
/// highest view ranks, and switching to a *different* leader requires a
/// strictly higher view than the adopted one, so two quorums that coexist
/// briefly during an election cannot make the client oscillate.
struct LeaderTracker {
    /// f+1 for the front count, with f = (n-1)/3.
    quorum: usize,
    /// Latest (view, leader) claimed by each front; view is kept monotone
    /// per front.
    latest: Vec<Option<(u64, usize)>>,
    adopted: Option<(u64, usize)>,
}

impl LeaderTracker {
    fn new(front_count: usize) -> Self {
        let f = front_count.saturating_sub(1) / 3;
        Self {
            quorum: f + 1,
            latest: vec![None; front_count],
            adopted: None,
        }
    }

    /// Record a hint from `front`; Some(leader) when the adopted leader
    /// changes.
    fn observe(&mut self, front: usize, view: u64, leader: usize) -> Option<usize> {
        match self.latest[front] {
            Some((v, _)) if v > view => return None,
            _ => self.latest[front] = Some((view, leader)),
        }

        // The candidate: a leader claimed by at least `quorum` fronts,
        // ranked by the highest view among its supporters (ties break on
        // the lower replica index, deterministically).
        let mut best: Option<(u64, usize)> = None;
        for entry in self.latest.iter().flatten() {
            let candidate = entry.1;
            let supporters = self
                .latest
                .iter()
                .flatten()
                .filter(|(_, l)| *l == candidate);
            let count = supporters.clone().count();
            if count < self.quorum {
                continue;
            }
            let view = supporters.map(|(v, _)| *v).max().unwrap();
            let better = match best {
                None => true,
                Some((bv, bl)) => view > bv || (view == bv && candidate < bl),
            };
            if better {
                best = Some((view, candidate));
            }
        }
        let (view, leader) = best?;

        match self.adopted {
            None => {
                self.adopted = Some((view, leader));
                Some(leader)
            }
            Some((cur_view, cur_leader)) if cur_leader == leader => {
                if view > cur_view {
                    self.adopted = Some((view, leader));
                }
                None
            }
            Some((cur_view, _)) if view > cur_view => {
                self.adopted = Some((view, leader));
                Some(leader)
            }
            Some(_) => None,
        }
    }
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
        "targets={:?} target_mode={:?} connections_per_target={} rate={} tx_size={} request_timeout_ms={} monitor_interval_ms={}",
        cfg.targets,
        cfg.target_mode,
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
    let per_sender_rate = match cfg.target_mode {
        TargetMode::Spread => {
            cfg.rate as f64 / (cfg.targets.len() * cfg.connections_per_target) as f64
        }
        TargetMode::Leader | TargetMode::Broadcast => {
            cfg.rate as f64 / cfg.connections_per_target as f64
        }
    };
    // Front index (targets order) currently believed to be the leader;
    // updated when a quorum of leader hints agrees (see LeaderTracker).
    // Senders in Leader mode only submit while their front matches. Starts
    // unassigned (usize::MAX): stable-leader replicas beacon the current
    // leader on every delivery (heartbeats included), so the first hints
    // arrive within a block delay.
    let leader_index = Arc::new(AtomicUsize::new(usize::MAX));
    let tracker = Arc::new(Mutex::new(LeaderTracker::new(cfg.targets.len())));
    if matches!(cfg.target_mode, TargetMode::Leader | TargetMode::Broadcast) {
        client_println!(
            "{:?} mode: waiting for a leader hint quorum before submitting",
            cfg.target_mode
        );
    }

    let mut tasks = Vec::new();
    match cfg.target_mode {
        TargetMode::Spread | TargetMode::Leader => {
            for (conn_index, framed) in connections.into_iter().enumerate() {
                let front = conn_index / cfg.connections_per_target;
                let outstanding: Arc<Mutex<HashMap<u64, Instant>>> =
                    Arc::new(Mutex::new(HashMap::new()));
                let (sink, stream) = framed.split();
                let target = cfg.targets[front];

                tasks.push(tokio::spawn(sender(
                    sink,
                    target,
                    per_sender_rate,
                    cfg.tx_size,
                    cfg.target_mode,
                    front,
                    Arc::clone(&leader_index),
                    Arc::clone(&outstanding),
                    Arc::clone(&metrics),
                )));
                tasks.push(tokio::spawn(receiver(
                    stream,
                    target,
                    front,
                    Arc::clone(&tracker),
                    Arc::clone(&leader_index),
                    Arc::clone(&outstanding),
                    Arc::clone(&metrics),
                )));
                tasks.push(tokio::spawn(sweeper(
                    cfg.request_timeout,
                    Arc::clone(&outstanding),
                    Arc::clone(&metrics),
                )));
            }
        }
        TargetMode::Broadcast => {
            // Lane structure: lane k owns connection k of every front, so
            // one sender can push the real transaction to the leader and the
            // shadow header everywhere else. Acks for a lane's transactions
            // arrive on whichever of the lane's connections ingested them,
            // so the outstanding map is shared per lane, not per connection.
            let mut slots: Vec<Option<_>> = connections.into_iter().map(Some).collect();
            for lane in 0..cfg.connections_per_target {
                let outstanding: Arc<Mutex<HashMap<u64, Instant>>> =
                    Arc::new(Mutex::new(HashMap::new()));
                let mut sinks: Vec<Option<TxSink>> = Vec::with_capacity(cfg.targets.len());
                for front in 0..cfg.targets.len() {
                    let framed = slots[front * cfg.connections_per_target + lane]
                        .take()
                        .expect("every lane slot is taken exactly once");
                    let (sink, stream) = framed.split();
                    sinks.push(Some(sink));
                    tasks.push(tokio::spawn(receiver(
                        stream,
                        cfg.targets[front],
                        front,
                        Arc::clone(&tracker),
                        Arc::clone(&leader_index),
                        Arc::clone(&outstanding),
                        Arc::clone(&metrics),
                    )));
                }
                tasks.push(tokio::spawn(broadcast_sender(
                    sinks,
                    cfg.targets.clone(),
                    lane,
                    per_sender_rate,
                    cfg.tx_size,
                    Arc::clone(&leader_index),
                    Arc::clone(&outstanding),
                )));
                tasks.push(tokio::spawn(sweeper(
                    cfg.request_timeout,
                    Arc::clone(&outstanding),
                    Arc::clone(&metrics),
                )));
            }
        }
    }

    let monitor = tokio::spawn(monitor_loop(cfg.monitor_interval, Arc::clone(&metrics)));

    let benchmark_start = Instant::now();
    match cfg.duration {
        Some(duration) => {
            tokio::select! {
                _ = tokio::time::sleep(duration) => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        None => {
            tokio::signal::ctrl_c()
                .await
                .context("failed to listen for ctrl-c")?;
        }
    }

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

#[allow(clippy::too_many_arguments)]
async fn sender(
    mut sink: TxSink,
    target: SocketAddr,
    rate: f64,
    tx_size: usize,
    target_mode: TargetMode,
    front: usize,
    leader_index: Arc<AtomicUsize>,
    outstanding: Arc<Mutex<HashMap<u64, Instant>>>,
    metrics: Arc<BenchmarkMetrics>,
) {
    const PRECISION: u64 = 20; // pacing ticks per second
    let tick_period = Duration::from_millis(1000 / PRECISION);
    let mut interval = tokio::time::interval(tick_period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);

    let start = Instant::now();
    let mut seq: u64 = 0;
    let mut sent: u64 = 0;
    // Leader mode paces with a credit accumulator instead of the absolute
    // token count: after an inactive stretch the sender must NOT burst the
    // whole missed allowance at once.
    let mut credit: f64 = 0.0;
    loop {
        interval.tick().await;
        let tick_start = Instant::now();
        let burst = match target_mode {
            TargetMode::Spread => {
                // Token accounting keeps the long-run rate exact even for
                // rates that do not divide evenly by the tick frequency.
                let target_count = (start.elapsed().as_secs_f64() * rate) as u64;
                target_count.saturating_sub(sent)
            }
            TargetMode::Leader => {
                if leader_index.load(Ordering::Relaxed) != front {
                    credit = 0.0;
                    continue;
                }
                credit += rate / PRECISION as f64;
                let burst = credit as u64;
                credit -= burst as f64;
                burst
            }
            TargetMode::Broadcast => {
                unreachable!("broadcast mode spawns broadcast_sender, not sender")
            }
        };

        for _ in 0..burst {
            seq += 1;
            let mut tx = BytesMut::with_capacity(tx_size);
            tx.put_u8(TX_TAG_REAL);
            tx.put_u64(seq);
            tx.resize(tx_size, 0u8);
            outstanding.lock().unwrap().insert(seq, Instant::now());
            if let Err(err) = sink.send(tx.freeze()).await {
                client_println!("connection to {} failed: {}", target, err);
                // Everything still outstanding on this connection will be
                // counted as errors by the sweeper.
                return;
            }
        }
        sent += burst;

        if tick_start.elapsed() > tick_period {
            client_println!("transaction rate too high for this client (target {})", target);
        }
        let _ = &metrics; // metrics are recorded by receiver and sweeper
    }
}

/// The broadcast-mode sender for one lane. Paces like the Leader-mode
/// sender; per transaction, the real (tracked) copy is fed to the adopted
/// leader's sink and the 9-byte shadow header to every other front, with one
/// flush per sink per burst. A failed shadow sink is dropped (that front
/// simply stops observing this lane); a failed leader sink ends the lane,
/// like the plain sender - its outstanding transactions surface as errors
/// via the sweeper.
#[allow(clippy::too_many_arguments)]
async fn broadcast_sender(
    mut sinks: Vec<Option<TxSink>>,
    targets: Vec<SocketAddr>,
    lane: usize,
    rate: f64,
    tx_size: usize,
    leader_index: Arc<AtomicUsize>,
    outstanding: Arc<Mutex<HashMap<u64, Instant>>>,
) {
    const PRECISION: u64 = 20; // pacing ticks per second
    let tick_period = Duration::from_millis(1000 / PRECISION);
    let mut interval = tokio::time::interval(tick_period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);

    let mut counter: u64 = 0;
    // Credit accumulator, as in Leader mode: no burst of the missed
    // allowance after an inactive stretch.
    let mut credit: f64 = 0.0;
    loop {
        interval.tick().await;
        let tick_start = Instant::now();
        let adopted = leader_index.load(Ordering::Relaxed);
        if adopted >= sinks.len() {
            credit = 0.0;
            continue;
        }
        if sinks[adopted].is_none() {
            client_println!(
                "lane {}: connection to adopted leader {} is gone; lane stops",
                lane,
                targets[adopted]
            );
            return;
        }
        credit += rate / PRECISION as f64;
        let burst = credit as u64;
        credit -= burst as f64;

        for _ in 0..burst {
            counter += 1;
            let seq = ((lane as u64) << LANE_SHIFT) | counter;
            let mut shadow = BytesMut::with_capacity(TX_HEADER_BYTES);
            shadow.put_u8(TX_TAG_SHADOW);
            shadow.put_u64(seq);
            let shadow = shadow.freeze();
            let mut tx = BytesMut::with_capacity(tx_size);
            tx.put_u8(TX_TAG_TRACKED);
            tx.put_u64(seq);
            tx.resize(tx_size, 0u8);
            outstanding.lock().unwrap().insert(seq, Instant::now());
            // Shadows are fed before the real copy so a follower's arrival
            // stamp is never later than the leader's ingest.
            for front in 0..sinks.len() {
                if front == adopted {
                    continue;
                }
                if let Some(sink) = sinks[front].as_mut() {
                    if let Err(err) = sink.feed(shadow.clone()).await {
                        client_println!(
                            "lane {}: shadow stream to {} failed: {}; front dropped from shadowing",
                            lane,
                            targets[front],
                            err
                        );
                        sinks[front] = None;
                    }
                }
            }
            let sink = sinks[adopted].as_mut().expect("checked at tick start");
            if let Err(err) = sink.feed(tx.freeze()).await {
                client_println!(
                    "lane {}: connection to leader {} failed: {}",
                    lane,
                    targets[adopted],
                    err
                );
                return;
            }
        }
        if burst > 0 {
            for front in 0..sinks.len() {
                if let Some(sink) = sinks[front].as_mut() {
                    if let Err(err) = sink.flush().await {
                        if front == adopted {
                            client_println!(
                                "lane {}: connection to leader {} failed: {}",
                                lane,
                                targets[adopted],
                                err
                            );
                            return;
                        }
                        client_println!(
                            "lane {}: shadow stream to {} failed: {}; front dropped from shadowing",
                            lane,
                            targets[front],
                            err
                        );
                        sinks[front] = None;
                    }
                }
            }
        }

        if tick_start.elapsed() > tick_period {
            client_println!("transaction rate too high for this client (lane {})", lane);
        }
    }
}

async fn receiver(
    mut stream: TxStream,
    target: SocketAddr,
    front: usize,
    tracker: Arc<Mutex<LeaderTracker>>,
    leader_index: Arc<AtomicUsize>,
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
        if let Some((view, leader)) = decode_leader_hint(&frame) {
            let leader = leader as usize;
            let adopted = {
                let mut tracker = tracker.lock().unwrap();
                if leader < tracker.latest.len() {
                    tracker.observe(front, view, leader)
                } else {
                    None
                }
            };
            if let Some(new_leader) = adopted {
                leader_index.store(new_leader, Ordering::Relaxed);
                client_println!(
                    "leader hint quorum: replica {} is now the leader (view {})",
                    new_leader,
                    view
                );
            }
            continue;
        }
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

#[cfg(test)]
mod tests {
    use super::LeaderTracker;

    #[test]
    fn adopts_only_on_quorum() {
        let mut tracker = LeaderTracker::new(4); // f = 1, quorum = 2
        assert_eq!(tracker.observe(0, 0, 2), None);
        assert_eq!(tracker.observe(1, 0, 2), Some(2));
        // Steady-state repeats change nothing.
        assert_eq!(tracker.observe(2, 0, 2), None);
        assert_eq!(tracker.observe(0, 0, 2), None);
    }

    #[test]
    fn single_stale_front_cannot_flap() {
        let mut tracker = LeaderTracker::new(4);
        tracker.observe(0, 5, 3);
        assert_eq!(tracker.observe(1, 5, 3), Some(3));
        // One front replaying history claims an old leader: no quorum for
        // it, and its own per-front view is monotone so the stale claim is
        // dropped entirely.
        assert_eq!(tracker.observe(2, 1, 0), None);
        assert_eq!(tracker.observe(2, 0, 0), None);
    }

    #[test]
    fn election_moves_leader_with_higher_view() {
        let mut tracker = LeaderTracker::new(4);
        tracker.observe(0, 5, 3);
        assert_eq!(tracker.observe(1, 5, 3), Some(3));
        assert_eq!(tracker.observe(2, 6, 0), None); // one voice, not enough
        assert_eq!(tracker.observe(3, 6, 0), Some(0));
        // The two laggard fronts still on the old leader cannot pull the
        // target back: their view is not higher than the adopted one.
        assert_eq!(tracker.observe(0, 5, 3), None);
        assert_eq!(tracker.observe(1, 5, 3), None);
    }

    #[test]
    fn same_leader_view_bump_is_silent() {
        let mut tracker = LeaderTracker::new(4);
        tracker.observe(0, 1, 2);
        assert_eq!(tracker.observe(1, 1, 2), Some(2));
        // The same leader re-elected in a later view: adopted view advances
        // without a target change.
        tracker.observe(0, 4, 2);
        assert_eq!(tracker.observe(1, 4, 2), None);
        // A competing quorum now needs a view above 4.
        tracker.observe(2, 3, 1);
        assert_eq!(tracker.observe(3, 3, 1), None);
        assert_eq!(tracker.observe(2, 5, 1), Some(1));
    }
}
