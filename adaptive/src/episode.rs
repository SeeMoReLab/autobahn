//! Wall-clock learning episode loop, a port of the Go `learningManager`'s
//! wall-clock mode (SmartBFT/examples/smallbank/learning.go). Per episode:
//! collect features for `feature_duration`, send the report (with the previous
//! episode's reward attached), poll GetTimeout for up to `reply_wait`, apply
//! the recommendation, discard `warmup_duration`, measure the reward for
//! `reward_duration`, then start the next episode.
//!
//! The consensus-count window mode is intentionally not implemented yet; the
//! CloudLab harness drives the wall-clock mode.

use crate::agent::AgentClient;
use crate::metrics::{LearningSample, LearningWindowMetrics, WindowSnapshot};
use crate::pb;
use crate::saturating_u32;
use crate::timestamped_log_tag;
use anyhow::{bail, Result};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_FEATURE_DURATION: Duration = Duration::from_secs(10);
pub const DEFAULT_REPLY_WAIT: Duration = Duration::from_secs(2);
pub const DEFAULT_WARMUP_DURATION: Duration = Duration::from_secs(3);
pub const DEFAULT_REWARD_DURATION: Duration = Duration::from_secs(5);

macro_rules! learning_println {
    ($($arg:tt)*) => {
        println!("{} {}", timestamped_log_tag("learning"), format!($($arg)*))
    };
}

#[derive(Clone, Debug)]
pub struct LearningConfig {
    pub node_id: u32,
    pub agent_target: String,
    pub poll_interval: Duration,
    pub rpc_timeout: Duration,
    pub feature_duration: Duration,
    pub reply_wait: Duration,
    pub warmup_duration: Duration,
    pub reward_duration: Duration,
}

impl LearningConfig {
    pub fn new(node_id: u32, agent_target: String) -> Self {
        Self {
            node_id,
            agent_target,
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

/// Ready-made hooks for PBFT: a single election-timeout knob written to
/// `cell`, reports built by [`crate::report::build_pbft_report`].
pub fn pbft_hooks(cell: crate::timeouts::TimeoutCell) -> ProtocolHooks {
    let initial_ms = cell.get().as_millis().min(u32::MAX as u128) as u32;
    let apply_cell = cell.clone();
    ProtocolHooks {
        protocol: pb::Protocol::Pbft,
        initial_timeout: pb::timeout::Value::Pbft(pb::PbftTimeout {
            election_timeout_milliseconds: initial_ms,
        }),
        build_state: Box::new(|snap| {
            pb::report_local::State::PbftState(crate::report::build_pbft_report(snap))
        }),
        build_reward: Box::new(|episode, snap, used| {
            let timeout_used = match used {
                pb::timeout::Value::Pbft(t) => t.clone(),
                other => panic!("PBFT reward built with non-PBFT timeout {:?}", other),
            };
            pb::reward::Value::Pbft(pb::PbftReward {
                episode,
                report: Some(crate::report::build_pbft_report(snap)),
                timeout_used: Some(timeout_used),
            })
        }),
        apply_timeout: Box::new(move |value| match value {
            pb::timeout::Value::Pbft(t) => {
                if t.election_timeout_milliseconds == 0 {
                    bail!("non-positive election timeout");
                }
                apply_cell.set(Duration::from_millis(t.election_timeout_milliseconds as u64));
                Ok(())
            }
            other => bail!("expected PBFT timeout, got {:?}", other),
        }),
        timeout_ms: Box::new(|value| match value {
            pb::timeout::Value::Pbft(t) => t.election_timeout_milliseconds,
            _ => 0,
        }),
    }
}

/// Ready-made hooks for SBFT: three knobs (election, slow_path, batch);
/// `timeout_ms` reports the election timeout.
pub fn sbft_hooks(cells: crate::timeouts::SbftTimeoutCells) -> ProtocolHooks {
    let as_ms = |cell: &crate::timeouts::TimeoutCell| {
        cell.get().as_millis().min(u32::MAX as u128) as u32
    };
    let initial = pb::SbftTimeout {
        election_timeout_milliseconds: as_ms(&cells.election),
        slow_path_timeout_milliseconds: as_ms(&cells.slow_path),
        batch_timeout_milliseconds: as_ms(&cells.batch),
    };
    let apply_cells = cells.clone();
    ProtocolHooks {
        protocol: pb::Protocol::Sbft,
        initial_timeout: pb::timeout::Value::Sbft(initial),
        build_state: Box::new(|snap| {
            pb::report_local::State::SbftState(crate::report::build_sbft_report(snap))
        }),
        build_reward: Box::new(|episode, snap, used| {
            let timeout_used = match used {
                pb::timeout::Value::Sbft(t) => t.clone(),
                other => panic!("SBFT reward built with non-SBFT timeout {:?}", other),
            };
            pb::reward::Value::Sbft(pb::SbftReward {
                episode,
                report: Some(crate::report::build_sbft_report(snap)),
                timeout_used: Some(timeout_used),
            })
        }),
        apply_timeout: Box::new(move |value| match value {
            pb::timeout::Value::Sbft(t) => {
                if t.election_timeout_milliseconds == 0
                    || t.slow_path_timeout_milliseconds == 0
                    || t.batch_timeout_milliseconds == 0
                {
                    bail!("non-positive SBFT timeout component: {:?}", t);
                }
                apply_cells
                    .election
                    .set(Duration::from_millis(t.election_timeout_milliseconds as u64));
                apply_cells
                    .slow_path
                    .set(Duration::from_millis(t.slow_path_timeout_milliseconds as u64));
                apply_cells
                    .batch
                    .set(Duration::from_millis(t.batch_timeout_milliseconds as u64));
                Ok(())
            }
            other => bail!("expected SBFT timeout, got {:?}", other),
        }),
        timeout_ms: Box::new(|value| match value {
            pb::timeout::Value::Sbft(t) => t.election_timeout_milliseconds,
            _ => 0,
        }),
    }
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

/// Ready-made hooks for Autobahn: three knobs (timeout_delay, car_timeout,
/// fast_path_timeout); `timeout_ms` reports the view-change timeout_delay.
pub fn autobahn_hooks(cells: crate::timeouts::AutobahnTimeoutCells) -> ProtocolHooks {
    let as_ms = |cell: &crate::timeouts::TimeoutCell| {
        cell.get().as_millis().min(u32::MAX as u128) as u32
    };
    let initial = pb::AutobahnTimeout {
        timeout_delay_milliseconds: as_ms(&cells.timeout_delay),
        car_timeout_milliseconds: as_ms(&cells.car_timeout),
        fast_path_timeout_milliseconds: as_ms(&cells.fast_path_timeout),
    };
    let apply_cells = cells.clone();
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
                if t.timeout_delay_milliseconds == 0
                    || t.car_timeout_milliseconds == 0
                    || t.fast_path_timeout_milliseconds == 0
                {
                    bail!("non-positive Autobahn timeout component: {:?}", t);
                }
                apply_cells
                    .timeout_delay
                    .set(Duration::from_millis(t.timeout_delay_milliseconds as u64));
                apply_cells
                    .car_timeout
                    .set(Duration::from_millis(t.car_timeout_milliseconds as u64));
                apply_cells
                    .fast_path_timeout
                    .set(Duration::from_millis(t.fast_path_timeout_milliseconds as u64));
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

    driver_spawned: bool,
}

pub struct LearningManager {
    cfg: LearningConfig,
    hooks: ProtocolHooks,
    client: AgentClient,
    inner: Mutex<Inner>,
    handle: tokio::runtime::Handle,
}

impl LearningManager {
    /// Create the manager. Must be called from within a tokio runtime; the
    /// episode driver and pollers are spawned on it when the first consensus
    /// sample arrives.
    pub fn new(cfg: LearningConfig, hooks: ProtocolHooks) -> Result<Arc<Self>> {
        let client = AgentClient::connect_lazy(&cfg.agent_target, cfg.rpc_timeout, hooks.protocol)?;
        let initial = hooks.initial_timeout.clone();
        learning_println!(
            "node {} target {} protocol={:?} initial_timeout_ms={} window_mode=wall-clock",
            cfg.node_id,
            cfg.agent_target,
            hooks.protocol,
            (hooks.timeout_ms)(&initial)
        );
        learning_println!(
            "wall-clock windows: feature={:?} reply_wait={:?} warmup={:?} reward={:?}",
            cfg.feature_duration,
            cfg.reply_wait,
            cfg.warmup_duration,
            cfg.reward_duration
        );
        Ok(Arc::new(Self {
            cfg,
            hooks,
            client,
            inner: Mutex::new(Inner {
                current_episode: 1,
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
                driver_spawned: false,
            }),
            handle: tokio::runtime::Handle::current(),
        }))
    }

    /// The timeout value currently in force (primary knob, ms).
    pub fn current_timeout_ms(&self) -> u32 {
        let inner = self.inner.lock().unwrap();
        (self.hooks.timeout_ms)(&inner.current_timeout)
    }

    /// Record one delivered consensus instance. Starts the wall-clock episode
    /// loop on the first sample.
    pub fn record_consensus(self: &Arc<Self>, sample: LearningSample) {
        let mut inner = self.inner.lock().unwrap();
        inner.delivered_count += 1;
        inner.last_sequence = sample.sequence;

        if inner.stage == Stage::Idle && !inner.driver_spawned {
            let start_tick = sample.sequence.saturating_sub(1);
            inner.episode_start_tick = start_tick;
            inner.stage = Stage::Feature;
            let start = sample.decision_time;
            inner.stage_deadline = Some(start + self.cfg.feature_duration);
            inner.metrics.reset_with_throughput_start(start);
            inner.metrics.timeout =
                Duration::from_millis((self.hooks.timeout_ms)(&inner.current_timeout) as u64);
            inner.driver_spawned = true;
            let manager = Arc::clone(self);
            let episode = inner.current_episode;
            self.handle.spawn(async move {
                manager.run_wall_clock(episode, start).await;
            });
        }

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

    async fn run_wall_clock(self: Arc<Self>, mut episode: u32, mut episode_start: Instant) {
        loop {
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
            episode_start = reward_end;
        }
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
        if let Some(value) = decision {
            match (self.hooks.apply_timeout)(&value) {
                Ok(()) => {
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

        if applied {
            learning_println!(
                "applied wall-clock recommendation: episode={} timeout_ms={}",
                episode,
                current_ms
            );
        } else {
            learning_println!(
                "wall-clock reply deadline reached without recommendation update: episode={} timeout_ms={}",
                episode,
                current_ms
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

        // Start the next episode.
        inner.current_episode += 1;
        inner.episode_start_tick = inner.last_sequence;
        inner.metrics.reset_with_throughput_start(end);
        inner.metrics.timeout =
            Duration::from_millis((self.hooks.timeout_ms)(&inner.current_timeout) as u64);
        inner.stage = Stage::Feature;
        inner.stage_deadline = Some(end + self.cfg.feature_duration);
        inner.poller_decision = None;
        inner.poller_episode = 0;
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
    fn sbft_hooks_roundtrip() {
        let cells = crate::timeouts::SbftTimeoutCells::new(
            Duration::from_millis(5000),
            Duration::from_millis(1000),
            Duration::from_millis(100),
        );
        let hooks = sbft_hooks(cells.clone());
        assert_eq!((hooks.timeout_ms)(&hooks.initial_timeout), 5000);

        let recommendation = pb::timeout::Value::Sbft(pb::SbftTimeout {
            election_timeout_milliseconds: 900,
            slow_path_timeout_milliseconds: 400,
            batch_timeout_milliseconds: 150,
        });
        (hooks.apply_timeout)(&recommendation).unwrap();
        assert_eq!(cells.election.get(), Duration::from_millis(900));
        assert_eq!(cells.slow_path.get(), Duration::from_millis(400));
        assert_eq!(cells.batch.get(), Duration::from_millis(150));

        // A zero component must be rejected, not applied.
        let zero = pb::timeout::Value::Sbft(pb::SbftTimeout {
            election_timeout_milliseconds: 900,
            slow_path_timeout_milliseconds: 0,
            batch_timeout_milliseconds: 150,
        });
        assert!((hooks.apply_timeout)(&zero).is_err());
        assert_eq!(cells.slow_path.get(), Duration::from_millis(400));

        // Reward echoes the exact applied value.
        let snap = WindowSnapshot::default();
        match (hooks.build_reward)(2, &snap, &recommendation) {
            pb::reward::Value::Sbft(reward) => {
                assert_eq!(reward.episode, 2);
                let used = reward.timeout_used.unwrap();
                assert_eq!(used.election_timeout_milliseconds, 900);
                assert_eq!(used.slow_path_timeout_milliseconds, 400);
                assert_eq!(used.batch_timeout_milliseconds, 150);
            }
            other => panic!("unexpected reward {:?}", other),
        }
    }

    #[test]
    fn pbft_hooks_roundtrip() {
        let cell = TimeoutCell::new(Duration::from_millis(800));
        let hooks = pbft_hooks(cell.clone());
        assert_eq!((hooks.timeout_ms)(&hooks.initial_timeout), 800);

        let recommendation = pb::timeout::Value::Pbft(pb::PbftTimeout {
            election_timeout_milliseconds: 1800,
        });
        (hooks.apply_timeout)(&recommendation).unwrap();
        assert_eq!(cell.get(), Duration::from_millis(1800));

        // Zero timeouts must be rejected, not applied.
        let zero = pb::timeout::Value::Pbft(pb::PbftTimeout {
            election_timeout_milliseconds: 0,
        });
        assert!((hooks.apply_timeout)(&zero).is_err());
        assert_eq!(cell.get(), Duration::from_millis(1800));

        // Reward echoes the exact applied value.
        let snap = WindowSnapshot::default();
        match (hooks.build_reward)(3, &snap, &recommendation) {
            pb::reward::Value::Pbft(reward) => {
                assert_eq!(reward.episode, 3);
                assert_eq!(
                    reward.timeout_used.unwrap().election_timeout_milliseconds,
                    1800
                );
            }
            other => panic!("unexpected reward {:?}", other),
        }
    }
}
