//! Shared adaptive-timer instrumentation for both workspaces (autobahn and
//! baselines): learning-agent gRPC client, episode loop, runtime timeout
//! channels, protocol-specific failure injection, and benchmark metrics.
//!
//! The reference semantics for the episode loop, report fields, Monitor line
//! format, and proposal-delay injection are the SmartBFT smallbank harness
//! (SmartBFT/examples/smallbank/{learning,learning_metrics,metrics,failure}.go
//! in the adaptive-timer parent repo). Behavior here deliberately mirrors that
//! implementation so PBFT runs can share the same agent models, schedules, and
//! failure specs.

pub mod ack;
pub mod agent;
pub mod client;
pub mod episode;
pub mod failure;
pub mod front;
pub mod metrics;
pub mod monitor;
pub mod report;
pub mod shadow;
pub mod timeouts;

/// Generated types and gRPC client stubs for `proto/agent.proto`.
///
/// The proto file is vendored from the adaptive-timer parent repo, whose
/// `proto/agent.proto` is the source of truth; the run scripts verify the two
/// copies are identical before deploying.
pub mod pb {
    // agent.proto declares no `package`, so prost emits the root module "_".
    tonic::include_proto!("_");
}

/// `[component 2006-01-02T15:04:05.000Z07:00]` log tag, matching the Go
/// harness's `timestampedLogTag` so downstream log parsing works unchanged.
pub fn timestamped_log_tag(component: &str) -> String {
    let now = chrono::Local::now();
    let offset = now.format("%:z").to_string();
    let offset = if offset == "+00:00" { "Z".to_string() } else { offset };
    format!("[{} {}{}]", component, now.format("%Y-%m-%dT%H:%M:%S%.3f"), offset)
}

pub(crate) fn saturating_u32(value: u64) -> u32 {
    value.min(u32::MAX as u64) as u32
}
