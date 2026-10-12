//! Wall-clock learning episode loop, a port of the Go `learningManager`'s
//! wall-clock mode (SmartBFT/examples/smallbank/learning.go). Per episode:
//! collect features for `feature_duration`, send the report (with the previous
//! episode's reward attached), poll GetTimeout for up to `reply_wait`, apply
//! the recommendation, discard `warmup_duration`, measure the reward for
//! `reward_duration`, then start the next episode.
//!
//! Episodes sit on a grid shared by every replica: episode e (e >= 1) applies
//! its recommendation at `anchor_unix_ms + period * (e - 1)` and starts
//! `feature_duration + reply_wait` earlier, where the period is the sum of the
//! four stage durations. The loop starts with the manager and joins at the
//! first episode whose start is still ahead.
//!
//! The consensus-count window mode is intentionally not implemented yet; the
//! CloudLab harness drives the wall-clock mode.

use crate::agent::AgentClient;
use crate::metrics::{LearningSample, LearningWindowMetrics, WindowSnapshot};
use crate::pb;
use crate::saturating_u32;
use crate::timestamped_log_tag;
use anyhow::{bail, Context, Result};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_FEATURE_DURATION: Duration = Duration::from_secs(10);
pub const DEFAULT_REPLY_WAIT: Duration = Duration::from_secs(2);
pub const DEFAULT_WARMUP_DURATION: Duration = Duration::from_secs(3);
pub const DEFAULT_REWARD_DURATION: Duration = Duration::from_secs(5);
/// How late an episode may begin before it is skipped. The previous episode's
/// reward end is the next start, so a zero tolerance would skip every episode.
const EPISODE_OVERRUN_TOLERANCE: Duration = Duration::from_secs(1);

macro_rules! learning_println {
    ($($arg:tt)*) => {
        println!("{} {}", timestamped_log_tag("learning"), format!($($arg)*))
    };
}

#[derive(Clone, Debug)]
pub struct LearningConfig {
    pub node_id: u32,
    pub agent_target: String,
    /// Wall-clock apply instant of episode 1 (benchmark start plus the failure
    /// spec's warm-up), the same on every replica.
    pub anchor_unix_ms: u64,
    pub poll_interval: Duration,
    pub rpc_timeout: Duration,
    pub feature_duration: Duration,
    pub reply_wait: Duration,
    pub warmup_duration: Duration,
    pub reward_duration: Duration,
}

impl LearningConfig {
    pub fn new(node_id: u32, agent_target: String, anchor_unix_ms: u64) -> Self {
        Self {
            node_id,
            agent_target,
            anchor_unix_ms,
            poll_interval: DEFAULT_POLL_INTERVAL,
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            feature_duration: DEFAULT_FEATURE_DURATION,
            reply_wait: DEFAULT_REPLY_WAIT,
            warmup_duration: DEFAULT_WARMUP_DURATION,
            reward_duration: DEFAULT_REWARD_DURATION,
        }
    }
}

/// Protocol-specific behavior plugged into the generic episode loop.
pub struct ProtocolHooks {
    pub protocol: pb::Protocol,
    /// The timeout value in force at startup. Must equal what the consensus
    /// timers were initialized with.
    pub initial_timeout: pb::timeout::Value,
    /// Build the `ReportLocal.state` oneof from a window snapshot.
    pub build_state: Box<dyn Fn(&WindowSnapshot) -> pb::report_local::State + Send + Sync>,
    /// Build the `Reward.value` oneof for a completed reward window. The
    /// `timeout::Value` passed is the exact value applied for that window and
    /// must be echoed verbatim into `timeout_used` (the agent requires
    /// byte-identical `timeout_used` across nodes to accept a reward).
    pub build_reward: Box<dyn Fn(u32, &WindowSnapshot, &pb::timeout::Value) -> pb::reward::Value + Send + Sync>,
    /// Apply a recommendation to the running consensus timers.
    pub apply_timeout: Box<dyn Fn(&pb::timeout::Value) -> Result<()> + Send + Sync>,
    /// The primary knob in milliseconds, for logging and `Report.timeout_ms`.
    pub timeout_ms: Box<dyn Fn(&pb::timeout::Value) -> u32 + Send + Sync>,
}

/// Ready-made hooks for batched HotStuff: a single timeout_delay knob
/// written to `cell`, reports built by [`crate::report::build_hotstuff_report`].
pub fn hotstuff_hooks(cell: crate::timeouts::TimeoutCell) -> ProtocolHooks {
    let initial_ms = cell.get().as_millis().min(u32::MAX as u128) as u32;
    let apply_cell = cell.clone();
    ProtocolHooks {
        protocol: pb::Protocol::Hotstuff,
        initial_timeout: pb::timeout::Value::Hotstuff(pb::HotstuffTimeout {
            timeout_delay_milliseconds: initial_ms,
        }),
        build_state: Box::new(|snap| {
            pb::report_local::State::HotstuffState(crate::report::build_hotstuff_report(snap))
        }),
        build_reward: Box::new(|episode, snap, used| {
            let timeout_used = match used {
                pb::timeout::Value::Hotstuff(t) => t.clone(),
                other => panic!("HotStuff reward built with non-HotStuff timeout {:?}", other),
            };
            pb::reward::Value::Hotstuff(pb::HotstuffReward {
                episode,
                report: Some(crate::report::build_hotstuff_report(snap)),
                timeout_used: Some(timeout_used),
            })
        }),
        apply_timeout: Box::new(move |value| match value {
            pb::timeout::Value::Hotstuff(t) => {
                if t.timeout_delay_milliseconds == 0 {
                    bail!("non-positive timeout delay");
                }
                apply_cell.set(Duration::from_millis(t.timeout_delay_milliseconds as u64));
                Ok(())
            }
            other => bail!("expected HotStuff timeout, got {:?}", other),
        }),
        timeout_ms: Box::new(|value| match value {
            pb::timeout::Value::Hotstuff(t) => t.timeout_delay_milliseconds,
            _ => 0,
        }),
    }
}

/// Ready-made hooks for Autobahn: a single knob, the per-slot view-change
/// timeout_delay, written to `cell`. The fast-path wait is a fixed parameter
/// (parameters.json), not an action.
pub fn autobahn_hooks(cell: crate::timeouts::TimeoutCell) -> ProtocolHooks {
    let initial = pb::AutobahnTimeout {
        timeout_delay_milliseconds: cell.get().as_millis().min(u32::MAX as u128) as u32,
    };
    let apply_cell = cell.clone();
    ProtocolHooks {
        protocol: pb::Protocol::Autobahn,
        initial_timeout: pb::timeout::Value::Autobahn(initial),
        build_state: Box::new(|snap| {
            pb::report_local::State::AutobahnState(crate::report::build_autobahn_report(snap))
        }),
        build_reward: Box::new(|episode, snap, used| {
            let timeout_used = match used {
                pb::timeout::Value::Autobahn(t) => t.clone(),
                other => panic!("Autobahn reward built with non-Autobahn timeout {:?}", other),
            };
            pb::reward::Value::Autobahn(pb::AutobahnReward {
                episode,
                report: Some(crate::report::build_autobahn_report(snap)),
                timeout_used: Some(timeout_used),
            })
        }),
        apply_timeout: Box::new(move |value| match value {
            pb::timeout::Value::Autobahn(t) => {
                if t.timeout_delay_milliseconds == 0 {
                    bail!("non-positive timeout delay");
                }
                apply_cell.set(Duration::from_millis(t.timeout_delay_milliseconds as u64));
                Ok(())
            }
            other => bail!("expected Autobahn timeout, got {:?}", other),
        }),
        timeout_ms: Box::new(|value| match value {
            pb::timeout::Value::Autobahn(t) => t.timeout_delay_milliseconds,
            _ => 0,
        }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Idle,
    Feature,
    ReplyWait,
    Warmup,
    Reward,
}

struct Inner {
    current_episode: u32,
    episode_start_tick: u64,
    delivered_count: u64,
    last_sequence: u64,

    stage: Stage,
    stage_deadline: Option<Instant>,
    metrics: LearningWindowMetrics,

    current_timeout: pb::timeout::Value,
    last_timeout: pb::timeout::Value,

    poll_generation: u64,
    poller_episode: u32,
    poller_decision: Option<pb::timeout::Value>,

    pending_reward: Option<(u32, WindowSnapshot, pb::timeout::Value)>,
}

/// The shared episode grid, converted to the monotonic clock once.
#[derive(Clone, Copy, Debug)]
struct Grid {
    anchor_unix_ms: u64,
    period: Duration,
    apply_offset: Duration,
    first_episode: u32,
    first_start: Instant,
}

impl Grid {
    fn start(&self, episode: u32) -> Instant {
        self.first_start + self.period * (episode - self.first_episode)
    }

    fn apply_unix_ms(&self, episode: u32) -> u64 {
        self.anchor_unix_ms + self.period.as_millis() as u64 * (episode as u64 - 1)
    }
}

/// The smallest episode e >= 1 whose start, `anchor + period * (e - 1) -
/// apply_offset`, is not before `now_unix`, and how far ahead of now it is.
fn first_grid_episode(
    anchor_unix_ms: u64,
    period: Duration,
    apply_offset: Duration,
    now_unix: Duration,
) -> Result<(u32, Duration)> {
    let period_ns = period.as_nanos() as i128;
    let first_start_ns = anchor_unix_ms as i128 * 1_000_000 - apply_offset.as_nanos() as i128;
    let behind_ns = now_unix.as_nanos() as i128 - first_start_ns;
    let skipped = if behind_ns <= 0 {
        0
    } else {
        (behind_ns + period_ns - 1) / period_ns
    };
    let episode = u32::try_from(1 + skipped).context("learning anchor is too far in the past")?;
    let ahead_ns = first_start_ns + skipped * period_ns - now_unix.as_nanos() as i128;
    Ok((episode, Duration::from_nanos(ahead_ns as u64)))
}

fn unix_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
}

pub struct LearningManager {
    cfg: LearningConfig,
    hooks: ProtocolHooks,
    client: AgentClient,
    inner: Mutex<Inner>,
    handle: tokio::runtime::Handle,
    grid: Grid,
}

impl LearningManager {
    /// Create the manager and start the episode driver. Must be called from
    /// within a tokio runtime; the driver and pollers are spawned on it.
    pub fn new(cfg: LearningConfig, hooks: ProtocolHooks) -> Result<Arc<Self>> {
        let period =
            cfg.feature_duration + cfg.reply_wait + cfg.warmup_duration + cfg.reward_duration;
        if period.is_zero() {
            bail!("learning episode period must be positive");
        }
        let apply_offset = cfg.feature_duration + cfg.reply_wait;
        let now_instant = Instant::now();
        let (first_episode, ahead) =
            first_grid_episode(cfg.anchor_unix_ms, period, apply_offset, unix_now())?;
        let grid = Grid {
            anchor_unix_ms: cfg.anchor_unix_ms,
            period,
            apply_offset,
            first_episode,
            first_start: now_instant + ahead,
        };
        let client = AgentClient::connect_lazy(&cfg.agent_target, cfg.rpc_timeout, hooks.protocol)?;
        let initial = hooks.initial_timeout.clone();
        learning_println!(
            "node {} target {} protocol={:?} initial_timeout_ms={} window_mode=wall-clock",
            cfg.node_id,
            cfg.agent_target,
            hooks.protocol,
            (hooks.timeout_ms)(&initial)
        );
        // The harness plot reads "applied timeouts:": once here, then on every apply.
        learning_println!("applied timeouts: timeout_delay_ms={}", (hooks.timeout_ms)(&initial));
        learning_println!(
            "wall-clock windows: feature={:?} reply_wait={:?} warmup={:?} reward={:?}",
            cfg.feature_duration,
            cfg.reply_wait,
            cfg.warmup_duration,
            cfg.reward_duration
        );
        learning_println!(
            "wall-clock grid: anchor_unix_ms={} period_ms={} apply_offset_ms={} first_episode={} first_start_unix_ms={}",
            grid.anchor_unix_ms,
            grid.period.as_millis(),
            grid.apply_offset.as_millis(),
            grid.first_episode,
            grid.apply_unix_ms(grid.first_episode) - grid.apply_offset.as_millis() as u64
        );
        let manager = Arc::new(Self {
            cfg,
            hooks,
            client,
            inner: Mutex::new(Inner {
                current_episode: 0,
                episode_start_tick: 0,
                delivered_count: 0,
                last_sequence: 0,
                stage: Stage::Idle,
                stage_deadline: None,
                metrics: LearningWindowMetrics::new(),
                current_timeout: initial.clone(),
                last_timeout: initial,
                poll_generation: 0,
                poller_episode: 0,
                poller_decision: None,
                pending_reward: None,
            }),
            handle: tokio::runtime::Handle::current(),
            grid,
        });
        let driver = Arc::clone(&manager);
        manager.handle.spawn(async move {
            driver.run_wall_clock().await;
        });
        Ok(manager)
    }

    /// Record one delivered consensus instance.
    pub fn record_consensus(self: &Arc<Self>, sample: LearningSample) {
        let mut inner = self.inner.lock().unwrap();
        inner.delivered_count += 1;
        inner.last_sequence = sample.sequence;

        let in_measured_stage = matches!(inner.stage, Stage::Feature | Stage::Reward);
        let before_deadline = inner
            .stage_deadline
            .map(|d| sample.decision_time <= d)
            .unwrap_or(true);
        if in_measured_stage && before_deadline {
            inner.metrics.record(&sample);
        }
    }

    pub fn record_view_change(&self) {
        let mut inner = self.inner.lock().unwrap();
        if matches!(inner.stage, Stage::Feature | Stage::Reward) {
            inner.metrics.record_view_change();
        }
    }

    pub fn record_no_progress_view_change(&self) {
        let mut inner = self.inner.lock().unwrap();
        if matches!(inner.stage, Stage::Feature | Stage::Reward) {
            inner.metrics.record_no_progress_view_change();
        }
    }

    async fn run_wall_clock(self: Arc<Self>) {
        let mut episode = self.grid.first_episode;
        loop {
            let mut episode_start = self.grid.start(episode);
            let now = Instant::now();
            // Overrun: the episode's start is past by more than the tolerance,
            // so join the next episode whose start is still ahead.
            if now > episode_start + EPISODE_OVERRUN_TOLERANCE {
                let behind_ns = (now - episode_start).as_nanos();
                let period_ns = self.grid.period.as_nanos();
                let skip = ((behind_ns + period_ns - 1) / period_ns) as u32;
                learning_println!(
                    "WARNING: episode {} start overran by {} ms; skipping to episode {}",
                    episode,
                    (now - episode_start).as_millis(),
                    episode + skip
                );
                episode += skip;
                episode_start = self.grid.start(episode);
            }
            if Instant::now() < episode_start {
                tokio::time::sleep_until(episode_start.into()).await;
            }
            self.begin_episode(episode, episode_start);

            let feature_end = episode_start + self.cfg.feature_duration;
            tokio::time::sleep_until(feature_end.into()).await;
            if !self.handle_feature_deadline(episode, feature_end) {
                return;
            }

            let apply_at = feature_end + self.cfg.reply_wait;
            tokio::time::sleep_until(apply_at.into()).await;
            if !self.handle_apply_deadline(episode, apply_at) {
                return;
            }

            let reward_start = apply_at + self.cfg.warmup_duration;
            tokio::time::sleep_until(reward_start.into()).await;
            if !self.handle_reward_start(episode, reward_start) {
                return;
            }

            let reward_end = reward_start + self.cfg.reward_duration;
            tokio::time::sleep_until(reward_end.into()).await;
            if !self.handle_reward_deadline(episode, reward_end) {
                return;
            }

            episode += 1;
        }
    }

    fn begin_episode(&self, episode: u32, start: Instant) {
        let mut inner = self.inner.lock().unwrap();
        inner.current_episode = episode;
        inner.episode_start_tick = inner.last_sequence;
        inner.metrics.reset_with_throughput_start(start);
        inner.metrics.timeout =
            Duration::from_millis((self.hooks.timeout_ms)(&inner.current_timeout) as u64);
        inner.stage = Stage::Feature;
        inner.stage_deadline = Some(start + self.cfg.feature_duration);
        inner.poller_decision = None;
        inner.poller_episode = 0;
    }

    fn handle_feature_deadline(self: &Arc<Self>, episode: u32, deadline: Instant) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.current_episode != episode || inner.stage != Stage::Feature {
            return false;
        }

        let snapshot = inner.metrics.snapshot_until(Some(deadline));
        let start_tick = inner.episode_start_tick;
        let report_seq = inner.last_sequence;
        let pending_reward = inner.pending_reward.take();
        inner.stage = Stage::ReplyWait;
        inner.stage_deadline = Some(deadline + self.cfg.reply_wait);
        self.start_polling_locked(&mut inner, episode);
        drop(inner);

        let reward = pending_reward.as_ref().map(|(ep, snap, used)| pb::Reward {
            value: Some((self.hooks.build_reward)(*ep, snap, used)),
        });
        let report = pb::ReportLocal {
            node_id: self.cfg.node_id,
            episode,
            protocol: self.hooks.protocol as i32,
            start_tick: saturating_u32(start_tick),
            report_seq: saturating_u32(report_seq),
            window_consensus_count: 0,
            state: Some((self.hooks.build_state)(&snapshot)),
            reward,
            signature: Vec::new(),
        };

        let manager = Arc::clone(self);
        self.handle.spawn(async move {
            let total_consensus = snapshot.total_consensus;
            let total_transactions = snapshot.total_transactions;
            let tps = snapshot.throughput_tps();
            match manager.client.send_report(report).await {
                Ok(()) => {
                    learning_println!(
                        "sent report: node={} episode={} start_tick={} report_seq={} window_mode=wall-clock total_consensus={} total_transactions={} throughput_tps={:.6}",
                        manager.cfg.node_id, episode, start_tick, report_seq,
                        total_consensus, total_transactions, tps
                    );
                    if let Some((reward_episode, reward_snap, _)) = pending_reward {
                        learning_println!(
                            "sent reward: node={} episode={} total_transactions={} throughput_tps={:.6}",
                            manager.cfg.node_id,
                            reward_episode,
                            reward_snap.total_transactions,
                            reward_snap.throughput_tps()
                        );
                    }
                }
                Err(err) => {
                    learning_println!(
                        "SendReport failed: episode={} target_node={} window_mode=wall-clock err={:#}",
                        episode, manager.cfg.node_id, err
                    );
                }
            }
        });
        true
    }

    fn handle_apply_deadline(&self, episode: u32, deadline: Instant) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.current_episode != episode || inner.stage != Stage::ReplyWait {
            return false;
        }

        let decision = if inner.poller_episode == episode {
            inner.poller_decision.take()
        } else {
            None
        };
        // Invalidate any still-running poller.
        inner.poll_generation += 1;
        inner.poller_episode = 0;
        inner.poller_decision = None;

        let mut applied = false;
        let apply_unix_ms = unix_now().as_millis() as i64;
        if let Some(value) = decision {
            match (self.hooks.apply_timeout)(&value) {
                Ok(()) => {
                    learning_println!("applied timeouts: timeout_delay_ms={}", (self.hooks.timeout_ms)(&value));
                    inner.current_timeout = value;
                    applied = true;
                }
                Err(err) => {
                    learning_println!(
                        "failed to apply wall-clock recommendation: episode={} timeout_ms={} err={:#}",
                        episode,
                        (self.hooks.timeout_ms)(&value),
                        err
                    );
                }
            }
        }
        inner.last_timeout = inner.current_timeout.clone();
        inner.stage = Stage::Warmup;
        inner.stage_deadline = Some(deadline + self.cfg.warmup_duration);
        let current_ms = (self.hooks.timeout_ms)(&inner.current_timeout);
        drop(inner);

        let grid_apply_unix_ms = self.grid.apply_unix_ms(episode);
        let lag_ms = apply_unix_ms - grid_apply_unix_ms as i64;
        if applied {
            learning_println!(
                "applied wall-clock recommendation: episode={} timeout_ms={} grid_apply_unix_ms={} lag_ms={}",
                episode,
                current_ms,
                grid_apply_unix_ms,
                lag_ms
            );
        } else {
            learning_println!(
                "wall-clock reply deadline reached without recommendation update: episode={} timeout_ms={} grid_apply_unix_ms={} lag_ms={}",
                episode,
                current_ms,
                grid_apply_unix_ms,
                lag_ms
            );
        }
        true
    }

    fn handle_reward_start(&self, episode: u32, start: Instant) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.current_episode != episode || inner.stage != Stage::Warmup {
            return false;
        }

        inner.metrics.reset_with_throughput_start(start);
        let last_ms = (self.hooks.timeout_ms)(&inner.last_timeout);
        inner.metrics.timeout = Duration::from_millis(last_ms as u64);
        inner.stage = Stage::Reward;
        inner.stage_deadline = Some(start + self.cfg.reward_duration);
        drop(inner);

        learning_println!(
            "started wall-clock reward measurement: episode={} duration={:?} timeout_ms={}",
            episode,
            self.cfg.reward_duration,
            last_ms
        );
        true
    }

    fn handle_reward_deadline(&self, episode: u32, end: Instant) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.current_episode != episode || inner.stage != Stage::Reward {
            return false;
        }

        let snapshot = inner.metrics.snapshot_until(Some(end));
        let used = inner.last_timeout.clone();
        let last_ms = (self.hooks.timeout_ms)(&used);
        learning_println!(
            "captured wall-clock reward: episode={} duration={:?} total_consensus={} total_transactions={} timeout_ms={}",
            episode,
            self.cfg.reward_duration,
            snapshot.total_consensus,
            snapshot.total_transactions,
            last_ms
        );
        inner.pending_reward = Some((episode, snapshot, used));

        // The driver starts the next episode on the grid.
        inner.stage = Stage::Idle;
        inner.stage_deadline = None;
        true
    }

    fn start_polling_locked(self: &Arc<Self>, inner: &mut Inner, episode: u32) {
        inner.poll_generation += 1;
        inner.poller_episode = episode;
        inner.poller_decision = None;
        let generation = inner.poll_generation;

        let manager = Arc::clone(self);
        self.handle.spawn(async move {
            manager.poll_for_timeout(generation, episode).await;
        });
    }

    async fn poll_for_timeout(self: Arc<Self>, generation: u64, episode: u32) {
        let mut ticker = tokio::time::interval(self.cfg.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            {
                let inner = self.inner.lock().unwrap();
                if inner.poll_generation != generation {
                    return;
                }
            }

            let status = match self.client.get_timeout(episode).await {
                Ok(status) => status,
                Err(_) => continue,
            };
            if status.status != pb::timeout_status::Status::Ready as i32 {
                continue;
            }
            let Some(value) = status.timeout.and_then(|t| t.value) else {
                continue;
            };
            // Wall-clock window validation, as in the Go poller: the echoed
            // window must itself be wall-clock shaped.
            if status.report_seq < status.start_tick || status.window_consensus_count != 0 {
                continue;
            }
            if (self.hooks.timeout_ms)(&value) == 0 {
                continue;
            }

            let mut inner = self.inner.lock().unwrap();
            if inner.poll_generation != generation || inner.poller_episode != episode {
                return;
            }
            if inner.poller_decision.is_none() {
                learning_println!(
                    "timeout READY: episode={} start_tick={} report_seq={} timeout_ms={}",
                    episode,
                    status.start_tick,
                    status.report_seq,
                    (self.hooks.timeout_ms)(&value)
                );
                inner.poller_decision = Some(value);
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeouts::TimeoutCell;

    #[test]
    fn first_grid_episode_joins_the_next_start() {
        let period = Duration::from_secs(20);
        let offset = Duration::from_secs(12);
        // Episode 1 starts at 100 s - 12 s = 88 s.
        let (episode, ahead) =
            first_grid_episode(100_000, period, offset, Duration::from_secs(80)).unwrap();
        assert_eq!((episode, ahead), (1, Duration::from_secs(8)));
        let (episode, ahead) =
            first_grid_episode(100_000, period, offset, Duration::from_secs(88)).unwrap();
        assert_eq!((episode, ahead), (1, Duration::ZERO));
        // A late joiner takes the next grid slot, numbered as everyone else.
        let (episode, ahead) =
            first_grid_episode(100_000, period, offset, Duration::from_millis(88_001)).unwrap();
        assert_eq!((episode, ahead), (2, Duration::from_millis(19_999)));
        let (episode, ahead) =
            first_grid_episode(100_000, period, offset, Duration::from_secs(150)).unwrap();
        assert_eq!((episode, ahead), (5, Duration::from_secs(18)));
    }

    #[test]
    fn hotstuff_hooks_roundtrip() {
        let cell = TimeoutCell::new(Duration::from_millis(800));
        let hooks = hotstuff_hooks(cell.clone());
        assert_eq!((hooks.timeout_ms)(&hooks.initial_timeout), 800);

        let recommendation = pb::timeout::Value::Hotstuff(pb::HotstuffTimeout {
            timeout_delay_milliseconds: 2000,
        });
        (hooks.apply_timeout)(&recommendation).unwrap();
        assert_eq!(cell.get(), Duration::from_millis(2000));

        // Zero timeouts must be rejected, not applied.
        let zero = pb::timeout::Value::Hotstuff(pb::HotstuffTimeout {
            timeout_delay_milliseconds: 0,
        });
        assert!((hooks.apply_timeout)(&zero).is_err());
        assert_eq!(cell.get(), Duration::from_millis(2000));

        // Reward echoes the exact applied value.
        let snap = WindowSnapshot::default();
        match (hooks.build_reward)(3, &snap, &recommendation) {
            pb::reward::Value::Hotstuff(reward) => {
                assert_eq!(reward.episode, 3);
                assert_eq!(
                    reward.timeout_used.unwrap().timeout_delay_milliseconds,
                    2000
                );
            }
            other => panic!("unexpected reward {:?}", other),
        }
    }
}
