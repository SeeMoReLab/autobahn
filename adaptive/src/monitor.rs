//! Client-side benchmark metrics and the per-interval `Monitor` line, a port
//! of SmartBFT/examples/smallbank/metrics.go. The output format is consumed by
//! the harness's log filter and plotting scripts and must not change:
//!
//! `[client <ts>] Monitor duration=%.3fs trxs=%d succ=%d err=%d tps=%.3f
//!  avg_ms=%.3f p50=%d p95=%d p99=%d max=%d`

use crate::timestamped_log_tag;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub struct BenchmarkMetrics {
    success: AtomicI64,
    errors: AtomicI64,
    /// Broadcast-mode retransmissions sent (see the client's retry timeout).
    retries: AtomicI64,
    total_latency_ns: AtomicI64,
    max_latency_ms: i64,
    histogram: Mutex<HashMap<i64, i64>>,
}

#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    pub success: i64,
    pub errors: i64,
    pub retries: i64,
    pub total_latency_ns: i64,
    pub max_latency_ms: i64,
    pub histogram: HashMap<i64, i64>,
}

impl BenchmarkMetrics {
    pub fn new(request_timeout: Duration) -> Self {
        Self {
            success: AtomicI64::new(0),
            errors: AtomicI64::new(0),
            retries: AtomicI64::new(0),
            total_latency_ns: AtomicI64::new(0),
            max_latency_ms: latency_cap_ms(request_timeout),
            histogram: Mutex::new(HashMap::new()),
        }
    }

    pub fn record(&self, success: bool, latency: Duration) {
        if success {
            self.success.fetch_add(1, Ordering::Relaxed);
            self.total_latency_ns
                .fetch_add(latency.as_nanos().min(i64::MAX as u128) as i64, Ordering::Relaxed);
            let bucket = (latency.as_millis() as i64).min(self.max_latency_ms);
            *self.histogram.lock().unwrap().entry(bucket).or_insert(0) += 1;
        } else {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_retry(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let histogram = self.histogram.lock().unwrap().clone();
        MetricsSnapshot {
            success: self.success.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            total_latency_ns: self.total_latency_ns.load(Ordering::Relaxed),
            max_latency_ms: self.max_latency_ms,
            histogram,
        }
    }
}

pub fn diff_snapshot(before: &MetricsSnapshot, after: &MetricsSnapshot) -> MetricsSnapshot {
    let mut histogram = HashMap::new();
    for (bucket, after_count) in &after.histogram {
        let delta = after_count - before.histogram.get(bucket).copied().unwrap_or(0);
        if delta > 0 {
            histogram.insert(*bucket, delta);
        }
    }
    MetricsSnapshot {
        success: after.success - before.success,
        errors: after.errors - before.errors,
        retries: after.retries - before.retries,
        total_latency_ns: after.total_latency_ns - before.total_latency_ns,
        max_latency_ms: after.max_latency_ms,
        histogram,
    }
}

/// Render one result line. `label == "Monitor"` produces the per-interval
/// line; any other label produces the block-delimited final summary.
pub fn format_results(label: &str, duration: Duration, snap: &MetricsSnapshot) -> String {
    let total = snap.success + snap.errors;
    let seconds = duration.as_secs_f64();
    let tps = if seconds > 0.0 { total as f64 / seconds } else { 0.0 };
    let avg_ms = if snap.success > 0 {
        snap.total_latency_ns as f64 / 1_000_000.0 / snap.success as f64
    } else {
        0.0
    };
    let p50 = percentile(&snap.histogram, snap.success, snap.max_latency_ms, 0.50);
    let p95 = percentile(&snap.histogram, snap.success, snap.max_latency_ms, 0.95);
    let p99 = percentile(&snap.histogram, snap.success, snap.max_latency_ms, 0.99);
    let max_latency = maximum_latency(&snap.histogram, snap.success);

    let stats = format!(
        "duration={:.3}s trxs={} succ={} err={} tps={:.3} avg_ms={:.3} p50={} p95={} p99={} max={} retries={}",
        seconds, total, snap.success, snap.errors, tps, avg_ms, p50, p95, p99, max_latency, snap.retries
    );
    if label == "Monitor" {
        format!("{} {} {}", timestamped_log_tag("client"), label, stats)
    } else {
        format!(
            "======================================================================\n{} results:\n{}\n======================================================================",
            label, stats
        )
    }
}

fn percentile(hist: &HashMap<i64, i64>, successes: i64, max_latency_ms: i64, pct: f64) -> i64 {
    if successes <= 0 {
        return 0;
    }
    let target = (successes as f64 * pct).ceil() as i64;
    let mut buckets: Vec<i64> = hist.keys().copied().collect();
    buckets.sort_unstable();
    let mut cumulative = 0i64;
    for bucket in buckets {
        cumulative += hist[&bucket];
        if cumulative >= target {
            return bucket;
        }
    }
    max_latency_ms
}

fn maximum_latency(hist: &HashMap<i64, i64>, successes: i64) -> i64 {
    if successes <= 0 {
        return 0;
    }
    hist.iter()
        .filter(|(_, count)| **count > 0)
        .map(|(bucket, _)| *bucket)
        .max()
        .unwrap_or(0)
}

fn latency_cap_ms(request_timeout: Duration) -> i64 {
    if request_timeout == Duration::ZERO {
        return i64::MAX;
    }
    let cap_ms = ((request_timeout + Duration::from_millis(1) - Duration::from_nanos(1))
        .as_millis()) as i64;
    cap_ms.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_line_format() {
        let metrics = BenchmarkMetrics::new(Duration::from_secs(5));
        for i in 1..=100u64 {
            metrics.record(true, Duration::from_millis(i));
        }
        metrics.record(false, Duration::ZERO);
        let snap = metrics.snapshot();
        let line = format_results("Monitor", Duration::from_secs(1), &snap);
        // "[client <ts>] Monitor duration=1.000s trxs=101 succ=100 err=1 ..."
        assert!(line.contains("] Monitor duration=1.000s trxs=101 succ=100 err=1 tps=101.000"));
        assert!(line.contains("p50=50 p95=95 p99=99 max=100"));
        assert!(line.starts_with("[client "));
    }

    #[test]
    fn latencies_capped_at_request_timeout() {
        let metrics = BenchmarkMetrics::new(Duration::from_millis(100));
        metrics.record(true, Duration::from_secs(9));
        let snap = metrics.snapshot();
        assert_eq!(snap.histogram.keys().copied().max(), Some(100));
    }

    #[test]
    fn diff_isolates_interval() {
        let metrics = BenchmarkMetrics::new(Duration::from_secs(1));
        metrics.record(true, Duration::from_millis(10));
        let before = metrics.snapshot();
        metrics.record(true, Duration::from_millis(20));
        metrics.record(false, Duration::ZERO);
        let after = metrics.snapshot();
        let diff = diff_snapshot(&before, &after);
        assert_eq!(diff.success, 1);
        assert_eq!(diff.errors, 1);
        assert_eq!(diff.histogram.len(), 1);
        assert_eq!(diff.histogram[&20], 1);
    }
}
