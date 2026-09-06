//! Per-learning-window metrics, a port of the Go `learningWindowMetrics`
//! (SmartBFT/examples/smallbank/learning_metrics.go). One instance accumulates
//! consensus samples for the current feature or reward window and is reset at
//! each window boundary.

use std::time::{Duration, Instant};

/// One delivered consensus instance, as observed by the local replica.
#[derive(Clone, Debug)]
pub struct LearningSample {
    /// Consensus sequence/round number of the decision.
    pub sequence: u64,
    /// View / regency the decision was committed in.
    pub view: u64,
    /// Leader of that view, as a 1-based id (0 means unknown; matches the Go
    /// harness where leader ids are 1-based and 0 is skipped).
    pub leader_id: u64,
    /// Number of transactions in the committed batch.
    pub batch_size: usize,
    /// When the decision was made locally.
    pub decision_time: Instant,
    /// Consensus latencies (proposal-to-commit) attributed to this decision.
    pub latencies: Vec<Duration>,
    /// The timeout in force when the decision committed (0 = unchanged).
    pub timeout: Duration,
}

#[derive(Default)]
pub struct LearningWindowMetrics {
    latencies: Vec<Duration>,
    batch_sizes: Vec<usize>,
    total_transactions: u64,
    total_consensus: u64,
    leader_change_count: u64,
    regency_change_count: u64,
    previous_leader: u64,
    previous_regency: u64,
    have_previous_leader: bool,
    have_previous_regency: bool,
    first_decision_time: Option<Instant>,
    last_decision_time: Option<Instant>,
    throughput_start_time: Option<Instant>,
    previous_decision_time: Option<Instant>,
    inter_commit_gaps: Vec<Duration>,
    pub timeout: Duration,
    view_change_count: u64,
    no_progress_view_change_count: u64,
}

/// Plain-data snapshot of one window, consumed by the per-protocol report
/// builders in [`crate::report`].
#[derive(Clone, Debug, Default)]
pub struct WindowSnapshot {
    pub total_transactions: u64,
    pub total_consensus: u64,
    pub latencies: Vec<Duration>,
    pub batch_sizes: Vec<usize>,
    pub inter_commit_gaps: Vec<Duration>,
    pub leader_change_count: u64,
    pub regency_change_count: u64,
    pub view_change_count: u64,
    pub no_progress_view_change_count: u64,
    pub timeout: Duration,
    /// Wall duration used for throughput (window start to `end`).
    pub throughput_duration: Duration,
}

impl WindowSnapshot {
    pub fn throughput_tps(&self) -> f32 {
        if self.throughput_duration > Duration::ZERO {
            (self.total_transactions as f64 / self.throughput_duration.as_secs_f64()) as f32
        } else {
            0.0
        }
    }
}

impl LearningWindowMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset_with_throughput_start(&mut self, start: Instant) {
        *self = Self::default();
        self.throughput_start_time = Some(start);
    }

    pub fn total_consensus(&self) -> u64 {
        self.total_consensus
    }

    pub fn total_transactions(&self) -> u64 {
        self.total_transactions
    }

    pub fn record(&mut self, sample: &LearningSample) {
        self.total_consensus += 1;
        self.total_transactions += sample.batch_size as u64;
        self.batch_sizes.push(sample.batch_size);

        if sample.leader_id > 0 {
            if self.have_previous_leader && self.previous_leader != sample.leader_id {
                self.leader_change_count += 1;
            }
            self.previous_leader = sample.leader_id;
            self.have_previous_leader = true;
        }
        if self.have_previous_regency && self.previous_regency != sample.view {
            self.regency_change_count += 1;
        }
        self.previous_regency = sample.view;
        self.have_previous_regency = true;

        if self.first_decision_time.is_none() {
            self.first_decision_time = Some(sample.decision_time);
        }
        if let Some(previous) = self.previous_decision_time {
            if sample.decision_time > previous {
                self.inter_commit_gaps.push(sample.decision_time - previous);
            }
        }
        self.previous_decision_time = Some(sample.decision_time);
        self.last_decision_time = Some(sample.decision_time);

        if sample.timeout > Duration::ZERO {
            self.timeout = sample.timeout;
        }
        self.latencies.extend(sample.latencies.iter().copied());
    }

    pub fn record_view_change(&mut self) {
        self.view_change_count += 1;
    }

    pub fn record_no_progress_view_change(&mut self) {
        self.no_progress_view_change_count += 1;
    }

    /// Snapshot the window, using `end` (if given) as the throughput window
    /// end; otherwise the last decision time is used, matching the Go
    /// `calculateThroughputUntil`.
    pub fn snapshot_until(&self, end: Option<Instant>) -> WindowSnapshot {
        let start = self.throughput_start_time.or(self.first_decision_time);
        let end = end.or(self.last_decision_time);
        let throughput_duration = match (start, end) {
            (Some(start), Some(end)) if end > start => end - start,
            _ => Duration::ZERO,
        };
        WindowSnapshot {
            total_transactions: self.total_transactions,
            total_consensus: self.total_consensus,
            latencies: self.latencies.clone(),
            batch_sizes: self.batch_sizes.clone(),
            inter_commit_gaps: self.inter_commit_gaps.clone(),
            leader_change_count: self.leader_change_count,
            regency_change_count: self.regency_change_count,
            view_change_count: self.view_change_count,
            no_progress_view_change_count: self.no_progress_view_change_count,
            timeout: self.timeout,
            throughput_duration,
        }
    }
}

/// Average of a duration list in milliseconds (0 when empty).
pub fn avg_duration_ms(values: &[Duration]) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    let total: Duration = values.iter().sum();
    (total.as_secs_f64() * 1000.0 / values.len() as f64) as f32
}

/// Percentile of a duration list in milliseconds, using the Go harness's
/// ceil-rank convention (`percentileIndex`).
pub fn percentile_duration_ms(values: &[Duration], percentile: f64) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<Duration> = values.to_vec();
    sorted.sort_unstable();
    (sorted[percentile_index(sorted.len(), percentile)].as_secs_f64() * 1000.0) as f32
}

/// Percentile of an integer list, same rank convention.
pub fn percentile_usize(values: &[usize], percentile: f64) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<usize> = values.to_vec();
    sorted.sort_unstable();
    sorted[percentile_index(sorted.len(), percentile)] as f32
}

fn percentile_index(length: usize, percentile: f64) -> usize {
    if length <= 1 {
        return 0;
    }
    let target = (percentile * length as f64).ceil() as isize - 1;
    target.clamp(0, length as isize - 1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_matches_go_convention() {
        let values: Vec<Duration> = (1..=10).map(Duration::from_millis).collect();
        // Go: index = ceil(p * n) - 1.
        assert_eq!(percentile_duration_ms(&values, 0.50), 5.0);
        assert_eq!(percentile_duration_ms(&values, 0.95), 10.0);
        assert_eq!(percentile_duration_ms(&values, 0.99), 10.0);
        assert_eq!(percentile_duration_ms(&values[..1], 0.95), 1.0);
        assert_eq!(percentile_duration_ms(&[], 0.95), 0.0);
    }

    #[test]
    fn window_counts_and_gaps() {
        let mut m = LearningWindowMetrics::new();
        let t0 = Instant::now();
        m.reset_with_throughput_start(t0);
        for i in 0..3u64 {
            m.record(&LearningSample {
                sequence: i,
                view: i / 2, // one regency change (0,0,1)
                leader_id: 1 + i / 2,
                batch_size: 10,
                decision_time: t0 + Duration::from_millis(100 * (i + 1)),
                latencies: vec![Duration::from_millis(50)],
                timeout: Duration::from_millis(800),
            });
        }
        let snap = m.snapshot_until(Some(t0 + Duration::from_secs(1)));
        assert_eq!(snap.total_consensus, 3);
        assert_eq!(snap.total_transactions, 30);
        assert_eq!(snap.leader_change_count, 1);
        assert_eq!(snap.regency_change_count, 1);
        assert_eq!(snap.inter_commit_gaps.len(), 2);
        assert_eq!(snap.timeout, Duration::from_millis(800));
        assert_eq!(snap.throughput_duration, Duration::from_secs(1));
        assert_eq!(snap.throughput_tps(), 30.0);
    }
}
