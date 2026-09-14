//! Protocol-specific failure injection: the proposal-delay controller, a port
//! of SmartBFT/examples/smallbank/failure.go. It reads the shared failure-spec
//! XML (the `<hotstuff><proposalDelay>` or `<autobahn><proposalDelay>`
//! section), anchored to the harness-wide `--failure-start-unix-ms`
//! timestamp, and answers "how long should this replica delay its proposal
//! right now".
//!
//! Semantics mirrored from the Go reference:
//! - `warmUpTime`/`warmUpTimeMs` shifts all phases.
//! - Phase start comes from `startAtMs`/`atTimeMs`/`startAt`/`atTime`/`time`
//!   (first present wins, in that order); phases sort by start then document
//!   order.
//! - `interval`/`intervalMs` repeats a phase every interval until the next
//!   phase's start (or `count` repetitions); with `<id>leader</id>` the leader
//!   window is re-resolved (pinned) once per interval tick.
//! - The leader window is the leader plus the next `(n-1)/3 - 1` replicas in
//!   ascending id order (window size `(n-1)/3`, i.e. f).
//! - Explicit replica ids take precedence over the leader-window rule.
//! - Replica ids in the spec are global 0-based ids.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const LEADER_REPLICA_TOKEN: &str = "leader";

/// Which protocol section of the spec to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolSection {
    Hotstuff,
    Autobahn,
}

#[derive(Debug, Deserialize)]
struct FailureSpecXml {
    #[serde(rename = "warmUpTime")]
    warm_up_time: Option<f64>,
    #[serde(rename = "warmUpTimeMs")]
    warm_up_time_ms: Option<i64>,
    phases: Option<PhasesXml>,
}

#[derive(Debug, Deserialize)]
struct PhasesXml {
    #[serde(rename = "phase", default)]
    phases: Vec<PhaseXml>,
}

#[derive(Debug, Deserialize)]
struct PhaseXml {
    #[serde(rename = "startAt")]
    start_at: Option<f64>,
    #[serde(rename = "startAtMs")]
    start_at_ms: Option<i64>,
    #[serde(rename = "atTime")]
    at_time: Option<f64>,
    #[serde(rename = "atTimeMs")]
    at_time_ms: Option<i64>,
    time: Option<f64>,
    hotstuff: Option<ProtocolSectionXml>,
    autobahn: Option<ProtocolSectionXml>,
}

#[derive(Debug, Default, Deserialize)]
struct ProtocolSectionXml {
    #[serde(rename = "proposalDelay")]
    proposal_delay: Option<ProposalDelayXml>,
}

#[derive(Debug, Default, Deserialize)]
struct ProposalDelayXml {
    #[serde(rename = "delayMs")]
    delay_ms: Option<i64>,
    interval: Option<f64>,
    #[serde(rename = "intervalMs")]
    interval_ms: Option<i64>,
    count: Option<i64>,
    replicas: Option<ReplicasXml>,
}

#[derive(Debug, Default, Deserialize)]
struct ReplicasXml {
    #[serde(rename = "replica", default)]
    replicas: Vec<ReplicaXml>,
    #[serde(rename = "id", default)]
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReplicaXml {
    id: String,
    #[serde(rename = "delayMs")]
    delay_ms: Option<i64>,
}

#[derive(Clone, Debug, Default)]
struct ProposalDelayRule {
    replica_delays: HashMap<u32, Duration>,
    leader_window_delay: Duration,
    has_leader_window_rule: bool,
}

#[derive(Clone, Debug)]
struct FailurePhase {
    start_offset: Duration,
    interval: Duration,
    order: usize,
    rule: ProposalDelayRule,
}

pub struct ProposalDelayController {
    enabled: bool,
    start_unix_ms: u64,
    warm_up: Duration,
    phases: Vec<FailurePhase>,
    last_logged_phase: AtomicI64,
    pinned_replicas: Mutex<HashMap<i64, HashMap<u32, Duration>>>,
}

impl ProposalDelayController {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            start_unix_ms: 0,
            warm_up: Duration::ZERO,
            phases: Vec::new(),
            last_logged_phase: AtomicI64::new(-2),
            pinned_replicas: Mutex::new(HashMap::new()),
        }
    }

    pub fn load(spec_xml: &str, start_unix_ms: u64, section: ProtocolSection) -> Result<Self> {
        let spec: FailureSpecXml =
            quick_xml::de::from_str(spec_xml).context("failed to parse failure spec XML")?;

        let warm_up = if let Some(ms) = spec.warm_up_time_ms {
            non_negative_ms(ms)
        } else if let Some(s) = spec.warm_up_time {
            non_negative_secs(s)
        } else {
            Duration::ZERO
        };

        let mut raw_phases: Vec<(Duration, usize, ProposalDelayXml)> = Vec::new();
        for (order, phase) in spec
            .phases
            .map(|p| p.phases)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
        {
            let start = phase_start(&phase);
            let section_xml = match section {
                ProtocolSection::Hotstuff => phase.hotstuff,
                ProtocolSection::Autobahn => phase.autobahn,
            };
            let delay = section_xml
                .unwrap_or_default()
                .proposal_delay
                .unwrap_or_default();
            raw_phases.push((start, order, delay));
        }
        raw_phases.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        let mut phases: Vec<FailurePhase> = Vec::new();
        for i in 0..raw_phases.len() {
            let next_start = raw_phases.get(i + 1).map(|p| p.0);
            let (start, order, delay) = &raw_phases[i];
            append_proposal_delay_phases(&mut phases, *start, *order, delay, next_start)?;
        }
        phases.sort_by(|a, b| a.start_offset.cmp(&b.start_offset).then(a.order.cmp(&b.order)));

        Ok(Self {
            enabled: true,
            start_unix_ms,
            warm_up,
            phases,
            last_logged_phase: AtomicI64::new(-2),
            pinned_replicas: Mutex::new(HashMap::new()),
        })
    }

    pub fn load_file(path: &str, start_unix_ms: u64, section: ProtocolSection) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read failure spec {}", path))?;
        Self::load(&raw, start_unix_ms, section)
    }

    fn elapsed_since_warmup(&self) -> Option<Duration> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_millis() as u64;
        let elapsed_ms = now_ms.checked_sub(self.start_unix_ms)?;
        Duration::from_millis(elapsed_ms).checked_sub(self.warm_up)
    }

    fn active_phase(&self, elapsed_since_warmup: Option<Duration>) -> i64 {
        let Some(elapsed) = elapsed_since_warmup else {
            return -1;
        };
        let mut active: i64 = -1;
        for (idx, phase) in self.phases.iter().enumerate() {
            if elapsed >= phase.start_offset {
                active = idx as i64;
            } else {
                break;
            }
        }
        active
    }

    fn pin_key(&self, active_phase: i64, elapsed_since_warmup: Duration) -> (i64, i64) {
        let Some(phase) = usize::try_from(active_phase)
            .ok()
            .and_then(|i| self.phases.get(i))
        else {
            return (active_phase, 0);
        };
        let mut tick = 0i64;
        if phase.interval > Duration::ZERO && elapsed_since_warmup >= phase.start_offset {
            tick = ((elapsed_since_warmup - phase.start_offset).as_nanos()
                / phase.interval.as_nanos()) as i64;
        }
        ((active_phase << 32) | tick, tick)
    }

    fn log_phase_change(&self, active_phase: i64) {
        let previous = self.last_logged_phase.load(Ordering::Relaxed);
        if previous == active_phase {
            return;
        }
        if self
            .last_logged_phase
            .compare_exchange(previous, active_phase, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        if active_phase < 0 {
            log::info!("proposal-delay injection phase changed: inactive");
        } else {
            let phase = &self.phases[active_phase as usize];
            log::info!(
                "proposal-delay injection phase changed: index={} start_offset_ms={}",
                active_phase,
                phase.start_offset.as_millis()
            );
        }
    }

    /// Observe the current leader; pins the leader window for the active
    /// phase/interval tick if a leader-window rule is active. Call whenever
    /// the local replica learns the leader (e.g. on view change and
    /// periodically while stable). `replica_ids` are 0-based global ids of
    /// all replicas; `leader` is the current leader's id.
    pub fn observe_leader(&self, leader: u32, replica_ids: &[u32]) {
        if !self.enabled {
            return;
        }
        let elapsed = self.elapsed_since_warmup();
        let active_phase = self.active_phase(elapsed);
        self.log_phase_change(active_phase);
        if active_phase < 0 {
            return;
        }
        let (pin_key, tick) = self.pin_key(active_phase, elapsed.unwrap());
        self.pin_leader_window(active_phase, pin_key, tick, leader, replica_ids);
    }

    /// The delay for this replica from the active phase's explicit rules and
    /// the already-pinned leader window, without re-resolving the leader.
    /// Use when the caller does not know the current leader (a separate
    /// component must call [`Self::observe_leader`] to maintain the pins).
    pub fn delay_for(&self, replica_id: u32) -> Duration {
        if !self.enabled {
            return Duration::ZERO;
        }
        let elapsed = self.elapsed_since_warmup();
        let active_phase = self.active_phase(elapsed);
        self.log_phase_change(active_phase);
        if active_phase < 0 {
            return Duration::ZERO;
        }
        let rule = &self.phases[active_phase as usize].rule;
        if let Some(delay) = rule.replica_delays.get(&replica_id) {
            return *delay;
        }
        if !rule.has_leader_window_rule {
            return Duration::ZERO;
        }
        let (pin_key, _) = self.pin_key(active_phase, elapsed.unwrap());
        self.pinned_replicas
            .lock()
            .unwrap()
            .get(&pin_key)
            .and_then(|window| window.get(&replica_id))
            .copied()
            .unwrap_or(Duration::ZERO)
    }

    /// The delay this replica must add before its proposal right now.
    pub fn delay_for_proposal(&self, replica_id: u32, leader: u32, replica_ids: &[u32]) -> Duration {
        if !self.enabled {
            return Duration::ZERO;
        }
        // Keep the pinned window fresh even if the caller forgets to call
        // observe_leader separately.
        self.observe_leader(leader, replica_ids);

        let elapsed = self.elapsed_since_warmup();
        let active_phase = self.active_phase(elapsed);
        if active_phase < 0 {
            return Duration::ZERO;
        }
        let rule = &self.phases[active_phase as usize].rule;
        if let Some(delay) = rule.replica_delays.get(&replica_id) {
            return *delay;
        }
        if !rule.has_leader_window_rule {
            return Duration::ZERO;
        }
        let (pin_key, _) = self.pin_key(active_phase, elapsed.unwrap());
        self.pinned_replicas
            .lock()
            .unwrap()
            .get(&pin_key)
            .and_then(|window| window.get(&replica_id))
            .copied()
            .unwrap_or(Duration::ZERO)
    }

    fn pin_leader_window(
        &self,
        active_phase: i64,
        pin_key: i64,
        tick: i64,
        leader: u32,
        replica_ids: &[u32],
    ) {
        let mut pinned = self.pinned_replicas.lock().unwrap();
        if pinned.get(&pin_key).map(|m| !m.is_empty()).unwrap_or(false) {
            return;
        }
        let Some(phase) = usize::try_from(active_phase)
            .ok()
            .and_then(|i| self.phases.get(i))
        else {
            return;
        };
        if !phase.rule.has_leader_window_rule {
            return;
        }

        let mut nodes: Vec<u32> = replica_ids.to_vec();
        nodes.sort_unstable();
        let Some(leader_pos) = nodes.iter().position(|id| *id == leader) else {
            return;
        };

        // Window size f = (n-1)/3: the leader plus the next f-1 replicas in id
        // order.
        let window_size = ((nodes.len().saturating_sub(1)) / 3).min(nodes.len());
        let mut resolved = HashMap::new();
        let mut targets = Vec::with_capacity(window_size);
        for offset in 0..window_size {
            let target = nodes[(leader_pos + offset) % nodes.len()];
            resolved.insert(target, phase.rule.leader_window_delay);
            targets.push(target);
        }

        pinned.insert(pin_key, resolved);
        log::info!(
            "resolved leader proposal delay window: phase={} interval_tick={} leader_replica={} delay_ms={} targets={:?}",
            phase.order,
            tick,
            leader,
            phase.rule.leader_window_delay.as_millis(),
            targets
        );
    }
}

fn phase_start(phase: &PhaseXml) -> Duration {
    if let Some(ms) = phase.start_at_ms {
        return non_negative_ms(ms);
    }
    if let Some(ms) = phase.at_time_ms {
        return non_negative_ms(ms);
    }
    if let Some(s) = phase.start_at {
        return non_negative_secs(s);
    }
    if let Some(s) = phase.at_time {
        return non_negative_secs(s);
    }
    if let Some(s) = phase.time {
        return non_negative_secs(s);
    }
    Duration::ZERO
}

fn append_proposal_delay_phases(
    phases: &mut Vec<FailurePhase>,
    start: Duration,
    order: usize,
    delay: &ProposalDelayXml,
    next_start: Option<Duration>,
) -> Result<()> {
    let rule = parse_proposal_delay_rule(delay)?;
    let interval = if let Some(ms) = delay.interval_ms {
        non_negative_ms(ms)
    } else if let Some(s) = delay.interval {
        non_negative_secs(s)
    } else {
        Duration::ZERO
    };

    if interval == Duration::ZERO {
        phases.push(FailurePhase {
            start_offset: start,
            interval: Duration::ZERO,
            order,
            rule,
        });
        return Ok(());
    }

    let count = delay.count.filter(|c| *c > 0).unwrap_or(0) as usize;
    let max_start = next_start.filter(|next| *next > start);

    let mut added = 0usize;
    let mut phase_start = start;
    loop {
        if let Some(max) = max_start {
            if phase_start >= max {
                break;
            }
        }
        if count > 0 && added >= count {
            break;
        }
        phases.push(FailurePhase {
            start_offset: phase_start,
            interval,
            order,
            rule: rule.clone(),
        });
        added += 1;
        if max_start.is_none() && count == 0 {
            break;
        }
        phase_start += interval;
    }

    if added == 0 {
        phases.push(FailurePhase {
            start_offset: start,
            interval: Duration::ZERO,
            order,
            rule,
        });
    }
    Ok(())
}

fn parse_proposal_delay_rule(delay: &ProposalDelayXml) -> Result<ProposalDelayRule> {
    let mut rule = ProposalDelayRule::default();
    let default_delay = delay.delay_ms.map(non_negative_ms);
    let replicas = delay.replicas.as_ref();

    let replica_entries = replicas.map(|r| r.replicas.as_slice()).unwrap_or_default();
    for replica in replica_entries {
        let id_text = replica.id.trim();
        if id_text.is_empty() {
            continue;
        }
        let replica_delay = match replica.delay_ms.map(non_negative_ms).or(default_delay) {
            Some(d) => d,
            None => continue,
        };
        if id_text.eq_ignore_ascii_case(LEADER_REPLICA_TOKEN) {
            rule.leader_window_delay = replica_delay;
            rule.has_leader_window_rule = true;
            continue;
        }
        let replica_id: u32 = id_text
            .parse()
            .with_context(|| format!("invalid replica id {:?} in proposalDelay", id_text))?;
        rule.replica_delays.insert(replica_id, replica_delay);
    }

    if !replica_entries.is_empty() {
        return Ok(rule);
    }
    let Some(default_delay) = default_delay else {
        return Ok(rule);
    };

    for raw_id in replicas.map(|r| r.ids.as_slice()).unwrap_or_default() {
        let id_text = raw_id.trim();
        if id_text.is_empty() {
            continue;
        }
        if id_text.eq_ignore_ascii_case(LEADER_REPLICA_TOKEN) {
            rule.leader_window_delay = default_delay;
            rule.has_leader_window_rule = true;
            continue;
        }
        let replica_id: u32 = id_text
            .parse()
            .with_context(|| format!("invalid replica id {:?} in proposalDelay", id_text))?;
        rule.replica_delays.insert(replica_id, default_delay);
    }
    Ok(rule)
}

fn non_negative_ms(value: i64) -> Duration {
    Duration::from_millis(value.max(0) as u64)
}

fn non_negative_secs(value: f64) -> Duration {
    if value <= 0.0 {
        return Duration::ZERO;
    }
    Duration::from_secs_f64(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"<?xml version="1.0"?>
<failureSpec>
    <schemaVersion>4</schemaVersion>
    <replicaIdType>global</replicaIdType>
    <warmUpTime>10</warmUpTime>
    <globalNetworkDelay><delayMs>5</delayMs></globalNetworkDelay>
    <phases>
        <phase>
            <atTime>0</atTime>
            <network>
                <directedEdges>true</directedEdges>
                <global><delayMs>0</delayMs><burstDurationMs>0</burstDurationMs><burstIntervalMs>0</burstIntervalMs></global>
            </network>
            <hotstuff>
                <proposalDelay>
                    <replicas></replicas>
                </proposalDelay>
            </hotstuff>
        </phase>
        <phase>
            <atTime>60</atTime>
            <hotstuff>
                <proposalDelay>
                    <interval>30</interval>
                    <replicas>
                        <replica><id>leader</id><delayMs>3000</delayMs></replica>
                    </replicas>
                </proposalDelay>
            </hotstuff>
        </phase>
        <phase>
            <atTime>120</atTime>
            <hotstuff>
                <proposalDelay>
                    <replicas>
                        <replica><id>2</id><delayMs>500</delayMs></replica>
                    </replicas>
                </proposalDelay>
            </hotstuff>
        </phase>
    </phases>
</failureSpec>"#;

    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn controller_at(offset_from_warmup: Duration) -> ProposalDelayController {
        // Position "now" at warmUp + offset past start.
        let start = now_unix_ms() - 10_000 - offset_from_warmup.as_millis() as u64;
        ProposalDelayController::load(SPEC, start, ProtocolSection::Hotstuff).unwrap()
    }

    #[test]
    fn parses_real_spec_shape() {
        let ctrl = ProposalDelayController::load(SPEC, now_unix_ms(), ProtocolSection::Hotstuff).unwrap();
        // Phase 1 repeats every 30s until phase 2 at 120s: entries at 60 and
        // 90, plus phase 0 and phase 2.
        assert_eq!(ctrl.phases.len(), 4);
        assert_eq!(ctrl.warm_up, Duration::from_secs(10));
        assert!(ctrl.phases[1].rule.has_leader_window_rule);
        assert_eq!(
            ctrl.phases[1].rule.leader_window_delay,
            Duration::from_millis(3000)
        );
        assert_eq!(
            ctrl.phases[3].rule.replica_delays.get(&2),
            Some(&Duration::from_millis(500))
        );
    }

    #[test]
    fn warmup_disables_injection() {
        // Now is before warm-up completes.
        let ctrl =
            ProposalDelayController::load(SPEC, now_unix_ms(), ProtocolSection::Hotstuff).unwrap();
        let all: Vec<u32> = (0..4).collect();
        assert_eq!(ctrl.delay_for_proposal(0, 0, &all), Duration::ZERO);
    }

    #[test]
    fn leader_window_targets_leader_and_successors() {
        // 100s past warm-up: inside the leader-delay phase (60..120).
        let ctrl = controller_at(Duration::from_secs(100));
        let all: Vec<u32> = (0..7).collect(); // n=7 -> f=2 -> window {leader, leader+1}
        assert_eq!(
            ctrl.delay_for_proposal(3, 3, &all),
            Duration::from_millis(3000)
        );
        assert_eq!(
            ctrl.delay_for_proposal(4, 3, &all),
            Duration::from_millis(3000)
        );
        assert_eq!(ctrl.delay_for_proposal(5, 3, &all), Duration::ZERO);
        assert_eq!(ctrl.delay_for_proposal(2, 3, &all), Duration::ZERO);
    }

    #[test]
    fn leader_window_pins_within_interval_tick() {
        let ctrl = controller_at(Duration::from_secs(100));
        let all: Vec<u32> = (0..4).collect(); // n=4 -> f=1 -> window {leader}
        // First resolution pins leader 1.
        assert_eq!(
            ctrl.delay_for_proposal(1, 1, &all),
            Duration::from_millis(3000)
        );
        // Later leader change within the same tick does not re-pin: replica 2
        // is not delayed even though it now leads.
        assert_eq!(ctrl.delay_for_proposal(2, 2, &all), Duration::ZERO);
        // The originally pinned replica stays delayed.
        assert_eq!(
            ctrl.delay_for_proposal(1, 2, &all),
            Duration::from_millis(3000)
        );
    }

    #[test]
    fn explicit_replica_rule_applies() {
        let ctrl = controller_at(Duration::from_secs(200)); // phase at 120s
        let all: Vec<u32> = (0..4).collect();
        assert_eq!(
            ctrl.delay_for_proposal(2, 0, &all),
            Duration::from_millis(500)
        );
        assert_eq!(ctrl.delay_for_proposal(0, 0, &all), Duration::ZERO);
    }

    #[test]
    fn disabled_controller_returns_zero() {
        let ctrl = ProposalDelayController::disabled();
        assert_eq!(ctrl.delay_for_proposal(0, 0, &[0, 1, 2, 3]), Duration::ZERO);
    }

    #[test]
    fn missing_section_yields_no_delays() {
        let ctrl = controller_at(Duration::from_secs(100));
        // Same instant but reading the autobahn section of a hotstuff-only spec.
        let start = now_unix_ms() - 110_000;
        let autobahn =
            ProposalDelayController::load(SPEC, start, ProtocolSection::Autobahn).unwrap();
        let all: Vec<u32> = (0..4).collect();
        assert_eq!(autobahn.delay_for_proposal(1, 1, &all), Duration::ZERO);
        // Sanity: the hotstuff view of the same time window does delay.
        assert_ne!(ctrl.delay_for_proposal(1, 1, &all), Duration::ZERO);
    }
}
