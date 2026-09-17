//! Protocol-level fault injection, driven by the shared failure-spec XML and
//! anchored to the harness-wide `--failure-start-unix-ms` timestamp. The
//! network faults in the same file are applied by
//! `scripts/apply_network_failures.py`; this module handles the faults a
//! replica inflicts from inside the protocol.
//!
//! Faults are always keyed by explicit global replica id. Both supported
//! protocols rotate leaders (HotStuff per round, Autobahn per slot with
//! several slots open at once), so "the leader" names no single replica over
//! a phase; the `leader` token is rejected at load time. A fixed replica id
//! is the well-defined slow-leader fault: that replica leads one turn in n,
//! and the view-change timeout caps the damage of each of its turns.
//!
//! Two fault kinds, per protocol section:
//!
//! - `<proposalDelay>`: the replica delays the consensus proposals it leads.
//!   In HotStuff that is the block proposal. In Autobahn `<messages>` selects
//!   which leader-originated phases are held (`prepare` by default, so the
//!   fault means the same thing as in HotStuff; `confirm` and `commit` are
//!   available for a leader that is slow in every phase), and
//!   `<forceSlowPath>` makes the leader ignore a unanimous Prepare QC and
//!   take the slow path after its own fast-path wait, which to followers is
//!   indistinguishable from an honest leader stuck behind a silent voter.
//! - `<voteDelay>` (Autobahn only): the replica delays its consensus votes
//!   and nothing else. This is the fault that isolates `fast_path_timeout`:
//!   the late vote defeats unanimity without making the replica's own
//!   proposals late.
//!
//! A delay is either `<delayMs>` (fixed) or `<delayRelativeToTimeoutMs>`
//! (the replica's current view-change timeout plus a signed offset, clamped
//! at zero). The relative form is the worst-case legal leader: it stretches
//! every turn to just under the timeout and is never deposed.
//!
//! Phases sort by start then document order; `warmUpTime`/`warmUpTimeMs`
//! shifts all of them. The old `<interval>`/`<count>` repetition existed only
//! to re-resolve the `leader` token per tick and is rejected too.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LEADER_TOKEN: &str = "leader";

/// Which protocol section of the spec to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolSection {
    Hotstuff,
    Autobahn,
}

impl ProtocolSection {
    fn tag(self) -> &'static str {
        match self {
            ProtocolSection::Hotstuff => "hotstuff",
            ProtocolSection::Autobahn => "autobahn",
        }
    }
}

/// How long a targeted replica holds a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultDelay {
    /// A fixed delay.
    Fixed(Duration),
    /// The replica's current view-change timeout plus `offset_ms`, clamped
    /// at zero. Negative offsets give the "just under the timeout" leader.
    RelativeToTimeout { offset_ms: i64 },
}

impl FaultDelay {
    /// The concrete delay to apply given the replica's live view-change
    /// timeout.
    pub fn resolve(&self, current_timeout: Duration) -> Duration {
        match *self {
            FaultDelay::Fixed(d) => d,
            FaultDelay::RelativeToTimeout { offset_ms } => {
                let base = current_timeout.as_millis() as i64;
                Duration::from_millis(base.saturating_add(offset_ms).max(0) as u64)
            }
        }
    }
}

/// Which leader-originated Autobahn consensus messages a proposal delay
/// holds. HotStuff has a single proposal per turn and ignores this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalMessages {
    pub prepare: bool,
    pub confirm: bool,
    pub commit: bool,
}

impl Default for ProposalMessages {
    fn default() -> Self {
        Self {
            prepare: true,
            confirm: false,
            commit: false,
        }
    }
}

impl ProposalMessages {
    fn parse(text: &str) -> Result<Self> {
        let mut set = Self {
            prepare: false,
            confirm: false,
            commit: false,
        };
        for raw in text.split(',') {
            match raw.trim().to_ascii_lowercase().as_str() {
                "" => continue,
                "prepare" => set.prepare = true,
                "confirm" => set.confirm = true,
                "commit" => set.commit = true,
                other => bail!(
                    "invalid <messages> entry {:?} in proposalDelay (expected prepare, confirm, commit)",
                    other
                ),
            }
        }
        if !(set.prepare || set.confirm || set.commit) {
            bail!("<messages> in proposalDelay selects no message");
        }
        Ok(set)
    }
}

/// The proposal-side fault active for one replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalFault {
    pub delay: FaultDelay,
    pub messages: ProposalMessages,
    pub force_slow_path: bool,
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
    #[serde(rename = "voteDelay")]
    vote_delay: Option<VoteDelayXml>,
}

#[derive(Debug, Default, Deserialize)]
struct ProposalDelayXml {
    #[serde(rename = "delayMs")]
    delay_ms: Option<i64>,
    #[serde(rename = "delayRelativeToTimeoutMs")]
    delay_relative_to_timeout_ms: Option<i64>,
    messages: Option<String>,
    #[serde(rename = "forceSlowPath")]
    force_slow_path: Option<bool>,
    interval: Option<f64>,
    #[serde(rename = "intervalMs")]
    interval_ms: Option<i64>,
    count: Option<i64>,
    replicas: Option<ReplicasXml>,
}

#[derive(Debug, Default, Deserialize)]
struct VoteDelayXml {
    #[serde(rename = "delayMs")]
    delay_ms: Option<i64>,
    #[serde(rename = "delayRelativeToTimeoutMs")]
    delay_relative_to_timeout_ms: Option<i64>,
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
    #[serde(rename = "delayRelativeToTimeoutMs")]
    delay_relative_to_timeout_ms: Option<i64>,
}

#[derive(Clone, Debug, Default)]
struct FaultRule {
    proposal: HashMap<u32, ProposalFault>,
    vote: HashMap<u32, FaultDelay>,
}

#[derive(Clone, Debug)]
struct FaultPhase {
    start_offset: Duration,
    rule: FaultRule,
}

#[derive(Debug)]
pub struct FaultController {
    enabled: bool,
    start_unix_ms: u64,
    warm_up: Duration,
    phases: Vec<FaultPhase>,
    last_logged_phase: AtomicI64,
}

impl FaultController {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            start_unix_ms: 0,
            warm_up: Duration::ZERO,
            phases: Vec::new(),
            last_logged_phase: AtomicI64::new(-2),
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

        let mut raw: Vec<(Duration, usize, FaultRule)> = Vec::new();
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
            }
            .unwrap_or_default();
            let rule = parse_rule(&section_xml, section)
                .with_context(|| format!("phase #{} (<{}> section)", order, section.tag()))?;
            raw.push((start, order, rule));
        }
        raw.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        Ok(Self {
            enabled: true,
            start_unix_ms,
            warm_up,
            phases: raw
                .into_iter()
                .map(|(start_offset, _, rule)| FaultPhase { start_offset, rule })
                .collect(),
            last_logged_phase: AtomicI64::new(-2),
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

    fn active_phase(&self) -> Option<&FaultPhase> {
        if !self.enabled {
            return None;
        }
        let mut active: i64 = -1;
        if let Some(elapsed) = self.elapsed_since_warmup() {
            for (idx, phase) in self.phases.iter().enumerate() {
                if elapsed >= phase.start_offset {
                    active = idx as i64;
                } else {
                    break;
                }
            }
        }
        self.log_phase_change(active);
        usize::try_from(active).ok().and_then(|i| self.phases.get(i))
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
            log::info!("fault injection phase changed: inactive");
        } else {
            let phase = &self.phases[active_phase as usize];
            log::info!(
                "fault injection phase changed: index={} start_offset_ms={} proposal_targets={:?} vote_targets={:?}",
                active_phase,
                phase.start_offset.as_millis(),
                sorted_keys(&phase.rule.proposal),
                sorted_keys(&phase.rule.vote),
            );
        }
    }

    /// The proposal-delay fault this replica must apply right now, if the
    /// active phase targets it.
    pub fn proposal_fault(&self, replica_id: u32) -> Option<ProposalFault> {
        self.active_phase()
            .and_then(|phase| phase.rule.proposal.get(&replica_id).copied())
    }

    /// The vote delay this replica must apply right now, if the active phase
    /// targets it.
    pub fn vote_delay(&self, replica_id: u32) -> Option<FaultDelay> {
        self.active_phase()
            .and_then(|phase| phase.rule.vote.get(&replica_id).copied())
    }
}

fn sorted_keys<V>(map: &HashMap<u32, V>) -> Vec<u32> {
    let mut keys: Vec<u32> = map.keys().copied().collect();
    keys.sort_unstable();
    keys
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

fn parse_rule(section: &ProtocolSectionXml, protocol: ProtocolSection) -> Result<FaultRule> {
    let mut rule = FaultRule::default();

    if let Some(pd) = &section.proposal_delay {
        if pd.interval.is_some() || pd.interval_ms.is_some() || pd.count.is_some() {
            bail!(
                "<interval>/<intervalMs>/<count> are no longer supported in proposalDelay; \
                 faults target fixed replica ids and need no per-tick re-resolution"
            );
        }
        let mut messages = ProposalMessages::default();
        let mut force_slow_path = false;
        match protocol {
            ProtocolSection::Autobahn => {
                if let Some(text) = &pd.messages {
                    messages = ProposalMessages::parse(text)?;
                }
                force_slow_path = pd.force_slow_path.unwrap_or(false);
            }
            ProtocolSection::Hotstuff => {
                if pd.messages.is_some() {
                    bail!("<messages> in proposalDelay is Autobahn-only; HotStuff has one proposal per round");
                }
                if pd.force_slow_path.is_some() {
                    bail!("<forceSlowPath> in proposalDelay is Autobahn-only; HotStuff has no fast path");
                }
            }
        }
        let default_delay = parse_delay(pd.delay_ms, pd.delay_relative_to_timeout_ms, "proposalDelay")?;
        for (id, delay) in parse_targets(pd.replicas.as_ref(), default_delay, "proposalDelay")? {
            rule.proposal.insert(
                id,
                ProposalFault {
                    delay,
                    messages,
                    force_slow_path,
                },
            );
        }
    }

    if let Some(vd) = &section.vote_delay {
        if protocol == ProtocolSection::Hotstuff {
            bail!("<voteDelay> is Autobahn-only; HotStuff has no fast path for a late vote to defeat");
        }
        let default_delay = parse_delay(vd.delay_ms, vd.delay_relative_to_timeout_ms, "voteDelay")?;
        for (id, delay) in parse_targets(vd.replicas.as_ref(), default_delay, "voteDelay")? {
            rule.vote.insert(id, delay);
        }
    }

    Ok(rule)
}

/// The delay given by a `<delayMs>` / `<delayRelativeToTimeoutMs>` pair;
/// None if neither is present.
fn parse_delay(fixed_ms: Option<i64>, relative_ms: Option<i64>, what: &str) -> Result<Option<FaultDelay>> {
    match (fixed_ms, relative_ms) {
        (Some(_), Some(_)) => bail!(
            "{} gives both <delayMs> and <delayRelativeToTimeoutMs>; use exactly one",
            what
        ),
        (Some(ms), None) => Ok(Some(FaultDelay::Fixed(non_negative_ms(ms)))),
        (None, Some(offset_ms)) => Ok(Some(FaultDelay::RelativeToTimeout { offset_ms })),
        (None, None) => Ok(None),
    }
}

/// Resolve the `<replicas>` block of a fault into (replica id, delay) pairs.
/// Supports both `<replica><id/><delayMs/></replica>` entries (per-replica
/// delay, falling back to the rule default) and the bare `<id>` list (rule
/// default required).
fn parse_targets(
    replicas: Option<&ReplicasXml>,
    default_delay: Option<FaultDelay>,
    what: &str,
) -> Result<Vec<(u32, FaultDelay)>> {
    let mut out = Vec::new();
    let Some(replicas) = replicas else {
        return Ok(out);
    };

    for replica in &replicas.replicas {
        let id_text = replica.id.trim();
        if id_text.is_empty() {
            continue;
        }
        let id = parse_replica_id(id_text, what)?;
        let delay = parse_delay(replica.delay_ms, replica.delay_relative_to_timeout_ms, what)?
            .or(default_delay)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} targets replica {} without a delay (set <delayMs> or <delayRelativeToTimeoutMs> on the replica or the rule)",
                    what, id
                )
            })?;
        out.push((id, delay));
    }

    for raw_id in &replicas.ids {
        let id_text = raw_id.trim();
        if id_text.is_empty() {
            continue;
        }
        let id = parse_replica_id(id_text, what)?;
        let delay = default_delay.ok_or_else(|| {
            anyhow::anyhow!(
                "{} lists replica {} by bare <id> but sets no rule-level delay",
                what, id
            )
        })?;
        out.push((id, delay));
    }

    Ok(out)
}

fn parse_replica_id(id_text: &str, what: &str) -> Result<u32> {
    if id_text.eq_ignore_ascii_case(LEADER_TOKEN) {
        bail!(
            "<id>leader</id> is not supported in {}: both HotStuff and Autobahn rotate leaders, \
             so name a fixed global replica id instead",
            what
        );
    }
    id_text
        .parse()
        .with_context(|| format!("invalid replica id {:?} in {}", id_text, what))
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
            <autobahn>
                <proposalDelay>
                    <replicas></replicas>
                </proposalDelay>
            </autobahn>
        </phase>
        <phase>
            <atTime>60</atTime>
            <autobahn>
                <proposalDelay>
                    <messages>prepare,confirm</messages>
                    <forceSlowPath>true</forceSlowPath>
                    <replicas>
                        <replica><id>3</id><delayMs>3000</delayMs></replica>
                    </replicas>
                </proposalDelay>
                <voteDelay>
                    <replicas>
                        <replica><id>1</id><delayMs>800</delayMs></replica>
                    </replicas>
                </voteDelay>
            </autobahn>
            <hotstuff>
                <proposalDelay>
                    <delayMs>2500</delayMs>
                    <replicas>
                        <id>3</id>
                    </replicas>
                </proposalDelay>
            </hotstuff>
        </phase>
        <phase>
            <atTime>120</atTime>
            <autobahn>
                <proposalDelay>
                    <replicas>
                        <replica><id>2</id><delayRelativeToTimeoutMs>-100</delayRelativeToTimeoutMs></replica>
                    </replicas>
                </proposalDelay>
            </autobahn>
        </phase>
    </phases>
</failureSpec>"#;

    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// A controller whose "now" sits `offset_from_warmup` past the end of
    /// the 10 s warm-up.
    fn controller_at(offset_from_warmup: Duration, section: ProtocolSection) -> FaultController {
        let start = now_unix_ms() - 10_000 - offset_from_warmup.as_millis() as u64;
        FaultController::load(SPEC, start, section).unwrap()
    }

    #[test]
    fn parses_real_spec_shape() {
        let ctrl = FaultController::load(SPEC, now_unix_ms(), ProtocolSection::Autobahn).unwrap();
        assert_eq!(ctrl.phases.len(), 3);
        assert_eq!(ctrl.warm_up, Duration::from_secs(10));
        let phase1 = &ctrl.phases[1].rule;
        assert_eq!(
            phase1.proposal.get(&3),
            Some(&ProposalFault {
                delay: FaultDelay::Fixed(Duration::from_millis(3000)),
                messages: ProposalMessages {
                    prepare: true,
                    confirm: true,
                    commit: false
                },
                force_slow_path: true,
            })
        );
        assert_eq!(
            phase1.vote.get(&1),
            Some(&FaultDelay::Fixed(Duration::from_millis(800)))
        );
        assert!(phase1.vote.get(&3).is_none());
    }

    #[test]
    fn hotstuff_section_reads_bare_id_list_with_rule_default() {
        let ctrl = controller_at(Duration::from_secs(100), ProtocolSection::Hotstuff);
        assert_eq!(
            ctrl.proposal_fault(3),
            Some(ProposalFault {
                delay: FaultDelay::Fixed(Duration::from_millis(2500)),
                messages: ProposalMessages::default(),
                force_slow_path: false,
            })
        );
        assert!(ctrl.proposal_fault(1).is_none());
        // The autobahn-only vote fault never leaks into the hotstuff view.
        assert!(ctrl.vote_delay(1).is_none());
    }

    #[test]
    fn warmup_disables_injection() {
        let ctrl = FaultController::load(SPEC, now_unix_ms(), ProtocolSection::Autobahn).unwrap();
        assert!(ctrl.proposal_fault(3).is_none());
        assert!(ctrl.vote_delay(1).is_none());
    }

    #[test]
    fn faults_follow_the_active_phase() {
        // 30 s past warm-up: phase 0, no targets.
        let ctrl = controller_at(Duration::from_secs(30), ProtocolSection::Autobahn);
        assert!(ctrl.proposal_fault(3).is_none());
        // 100 s: phase 1 targets 3 (proposal) and 1 (vote).
        let ctrl = controller_at(Duration::from_secs(100), ProtocolSection::Autobahn);
        assert!(ctrl.proposal_fault(3).is_some());
        assert!(ctrl.proposal_fault(2).is_none());
        assert!(ctrl.vote_delay(1).is_some());
        // 200 s: phase 2 targets 2 only.
        let ctrl = controller_at(Duration::from_secs(200), ProtocolSection::Autobahn);
        assert!(ctrl.proposal_fault(3).is_none());
        assert!(ctrl.vote_delay(1).is_none());
        assert_eq!(
            ctrl.proposal_fault(2).map(|f| f.delay),
            Some(FaultDelay::RelativeToTimeout { offset_ms: -100 })
        );
    }

    #[test]
    fn relative_delay_resolves_against_the_live_timeout() {
        let d = FaultDelay::RelativeToTimeout { offset_ms: -100 };
        assert_eq!(d.resolve(Duration::from_millis(600)), Duration::from_millis(500));
        assert_eq!(d.resolve(Duration::from_millis(50)), Duration::ZERO);
        let f = FaultDelay::Fixed(Duration::from_millis(3000));
        assert_eq!(f.resolve(Duration::from_millis(600)), Duration::from_millis(3000));
    }

    #[test]
    fn disabled_controller_has_no_faults() {
        let ctrl = FaultController::disabled();
        assert!(ctrl.proposal_fault(0).is_none());
        assert!(ctrl.vote_delay(0).is_none());
    }

    fn spec_with(section: &str, body: &str) -> String {
        format!(
            r#"<?xml version="1.0"?><failureSpec><warmUpTime>0</warmUpTime><phases><phase><atTime>0</atTime><{s}>{b}</{s}></phase></phases></failureSpec>"#,
            s = section,
            b = body
        )
    }

    #[test]
    fn leader_token_is_rejected() {
        let xml = spec_with(
            "hotstuff",
            "<proposalDelay><replicas><replica><id>leader</id><delayMs>300</delayMs></replica></replicas></proposalDelay>",
        );
        let err = FaultController::load(&xml, 0, ProtocolSection::Hotstuff).unwrap_err();
        assert!(format!("{:#}", err).contains("leader"), "{:#}", err);
    }

    #[test]
    fn interval_is_rejected() {
        let xml = spec_with(
            "autobahn",
            "<proposalDelay><interval>60</interval><replicas><replica><id>1</id><delayMs>300</delayMs></replica></replicas></proposalDelay>",
        );
        let err = FaultController::load(&xml, 0, ProtocolSection::Autobahn).unwrap_err();
        assert!(format!("{:#}", err).contains("interval"), "{:#}", err);
    }

    #[test]
    fn autobahn_only_fields_are_rejected_for_hotstuff() {
        let vote = spec_with(
            "hotstuff",
            "<voteDelay><replicas><replica><id>1</id><delayMs>300</delayMs></replica></replicas></voteDelay>",
        );
        assert!(FaultController::load(&vote, 0, ProtocolSection::Hotstuff).is_err());
        let msgs = spec_with(
            "hotstuff",
            "<proposalDelay><messages>prepare</messages><replicas><replica><id>1</id><delayMs>300</delayMs></replica></replicas></proposalDelay>",
        );
        assert!(FaultController::load(&msgs, 0, ProtocolSection::Hotstuff).is_err());
        // The same body is fine under the autobahn section.
        let ok = spec_with(
            "autobahn",
            "<proposalDelay><messages>prepare</messages><replicas><replica><id>1</id><delayMs>300</delayMs></replica></replicas></proposalDelay>",
        );
        assert!(FaultController::load(&ok, 0, ProtocolSection::Autobahn).is_ok());
    }

    #[test]
    fn missing_or_conflicting_delays_are_rejected() {
        let none = spec_with(
            "autobahn",
            "<proposalDelay><replicas><replica><id>1</id></replica></replicas></proposalDelay>",
        );
        assert!(FaultController::load(&none, 0, ProtocolSection::Autobahn).is_err());
        let both = spec_with(
            "autobahn",
            "<proposalDelay><replicas><replica><id>1</id><delayMs>1</delayMs><delayRelativeToTimeoutMs>-1</delayRelativeToTimeoutMs></replica></replicas></proposalDelay>",
        );
        assert!(FaultController::load(&both, 0, ProtocolSection::Autobahn).is_err());
        let bad_msgs = spec_with(
            "autobahn",
            "<proposalDelay><messages>prepare,vote</messages><replicas><replica><id>1</id><delayMs>1</delayMs></replica></replicas></proposalDelay>",
        );
        assert!(FaultController::load(&bad_msgs, 0, ProtocolSection::Autobahn).is_err());
    }

    #[test]
    fn missing_section_yields_no_faults() {
        let xml = spec_with(
            "autobahn",
            "<proposalDelay><replicas><replica><id>1</id><delayMs>300</delayMs></replica></replicas></proposalDelay>",
        );
        let hotstuff = FaultController::load(&xml, 0, ProtocolSection::Hotstuff).unwrap();
        assert!(hotstuff.proposal_fault(1).is_none());
        let autobahn = FaultController::load(&xml, 0, ProtocolSection::Autobahn).unwrap();
        assert!(autobahn.proposal_fault(1).is_some());
    }
}
