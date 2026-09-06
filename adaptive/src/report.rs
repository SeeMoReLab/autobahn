//! Per-protocol report builders: turn a [`WindowSnapshot`] into the protocol's
//! report message from agent.proto. The PBFT builder mirrors the Go
//! `learningWindowMetrics.buildReportUntil` field for field so PBFT runs are
//! comparable with SmartBFT's under the same agent models.

use crate::metrics::{avg_duration_ms, percentile_duration_ms, percentile_usize, WindowSnapshot};
use crate::pb;
use crate::saturating_u32;
use std::time::Duration;

pub fn build_pbft_report(snap: &WindowSnapshot) -> pb::PbftReport {
    let avg_batch_size = if snap.total_consensus > 0 {
        (snap.total_transactions as f64 / snap.total_consensus as f64) as f32
    } else {
        0.0
    };
    pb::PbftReport {
        total_transactions: saturating_u32(snap.total_transactions),
        total_consensus_instances: saturating_u32(snap.total_consensus),
        avg_consensus_latency_ms: avg_duration_ms(&snap.latencies),
        p50_consensus_latency_ms: percentile_duration_ms(&snap.latencies, 0.50),
        p95_consensus_latency_ms: percentile_duration_ms(&snap.latencies, 0.95),
        throughput_tps: snap.throughput_tps(),
        avg_batch_size,
        p95_batch_size: percentile_usize(&snap.batch_sizes, 0.95),
        leader_change_count: saturating_u32(snap.leader_change_count),
        regency_change_count: saturating_u32(snap.regency_change_count),
        timeout_ms: saturating_u32(snap.timeout.as_millis().min(u64::MAX as u128) as u64),
        avg_inter_commit_gap_ms: avg_duration_ms(&snap.inter_commit_gaps),
        p50_inter_commit_gap_ms: percentile_duration_ms(&snap.inter_commit_gaps, 0.50),
        p95_inter_commit_gap_ms: percentile_duration_ms(&snap.inter_commit_gaps, 0.95),
        view_change_count: saturating_u32(snap.view_change_count),
        no_progress_view_change_count: saturating_u32(snap.no_progress_view_change_count),
    }
}

/// SBFT report. `timeout_violation_rate` is the fraction of consensus
/// latencies in the window that exceeded the election timeout in force.
pub fn build_sbft_report(snap: &WindowSnapshot) -> pb::SbftReport {
    let avg_batch_size = if snap.total_consensus > 0 {
        (snap.total_transactions as f64 / snap.total_consensus as f64) as f32
    } else {
        0.0
    };
    pb::SbftReport {
        total_transactions: saturating_u32(snap.total_transactions),
        total_consensus_instances: saturating_u32(snap.total_consensus),
        avg_consensus_latency_ms: avg_duration_ms(&snap.latencies),
        p95_consensus_latency_ms: percentile_duration_ms(&snap.latencies, 0.95),
        p99_consensus_latency_ms: percentile_duration_ms(&snap.latencies, 0.99),
        throughput_tps: snap.throughput_tps(),
        timeout_violation_rate: timeout_violation_rate(&snap.latencies, snap.timeout),
        avg_batch_size,
        p95_batch_size: percentile_usize(&snap.batch_sizes, 0.95),
        leader_change_count: saturating_u32(snap.leader_change_count),
        regency_change_count: saturating_u32(snap.regency_change_count),
    }
}

/// HotStuff report: identical field mapping to PBFT (see the proto comments
/// for the semantic notes on view/leader counters).
pub fn build_hotstuff_report(snap: &WindowSnapshot) -> pb::HotstuffReport {
    let p = build_pbft_report(snap);
    pb::HotstuffReport {
        total_transactions: p.total_transactions,
        total_consensus_instances: p.total_consensus_instances,
        avg_consensus_latency_ms: p.avg_consensus_latency_ms,
        p50_consensus_latency_ms: p.p50_consensus_latency_ms,
        p95_consensus_latency_ms: p.p95_consensus_latency_ms,
        throughput_tps: p.throughput_tps,
        avg_batch_size: p.avg_batch_size,
        p95_batch_size: p.p95_batch_size,
        leader_change_count: p.leader_change_count,
        regency_change_count: p.regency_change_count,
        timeout_ms: p.timeout_ms,
        avg_inter_commit_gap_ms: p.avg_inter_commit_gap_ms,
        p50_inter_commit_gap_ms: p.p50_inter_commit_gap_ms,
        p95_inter_commit_gap_ms: p.p95_inter_commit_gap_ms,
        view_change_count: p.view_change_count,
        no_progress_view_change_count: p.no_progress_view_change_count,
    }
}

/// Autobahn report: identical field mapping to PBFT; batch sizes count
/// payload digests per committed header.
pub fn build_autobahn_report(snap: &WindowSnapshot) -> pb::AutobahnReport {
    let p = build_pbft_report(snap);
    pb::AutobahnReport {
        total_transactions: p.total_transactions,
        total_consensus_instances: p.total_consensus_instances,
        avg_consensus_latency_ms: p.avg_consensus_latency_ms,
        p50_consensus_latency_ms: p.p50_consensus_latency_ms,
        p95_consensus_latency_ms: p.p95_consensus_latency_ms,
        throughput_tps: p.throughput_tps,
        avg_batch_size: p.avg_batch_size,
        p95_batch_size: p.p95_batch_size,
        leader_change_count: p.leader_change_count,
        regency_change_count: p.regency_change_count,
        timeout_ms: p.timeout_ms,
        avg_inter_commit_gap_ms: p.avg_inter_commit_gap_ms,
        p50_inter_commit_gap_ms: p.p50_inter_commit_gap_ms,
        p95_inter_commit_gap_ms: p.p95_inter_commit_gap_ms,
        view_change_count: p.view_change_count,
        no_progress_view_change_count: p.no_progress_view_change_count,
    }
}

fn timeout_violation_rate(latencies: &[Duration], timeout: Duration) -> f32 {
    if latencies.is_empty() || timeout == Duration::ZERO {
        return 0.0;
    }
    let violations = latencies.iter().filter(|l| **l > timeout).count();
    violations as f32 / latencies.len() as f32
}
