//! Runtime-adjustable timeout values, applied by the learning episode loop and
//! read by consensus timers each time they re-arm.

use std::time::Duration;
use tokio::sync::watch;

/// A single timeout knob backed by a watch channel. Consensus code keeps a
/// clone and calls [`TimeoutCell::get`] whenever it arms the corresponding
/// timer; the episode loop calls [`TimeoutCell::set`] when the agent's
/// recommendation is applied.
#[derive(Clone, Debug)]
pub struct TimeoutCell {
    tx: watch::Sender<Duration>,
}

impl TimeoutCell {
    pub fn new(initial: Duration) -> Self {
        let (tx, _rx) = watch::channel(initial);
        Self { tx }
    }

    pub fn get(&self) -> Duration {
        *self.tx.borrow()
    }

    pub fn set(&self, value: Duration) {
        // send_replace never fails and updates even without receivers.
        self.tx.send_replace(value);
    }

    /// Subscribe for change notifications (e.g. to re-arm a pending timer
    /// immediately instead of on its next natural re-arm).
    pub fn subscribe(&self) -> watch::Receiver<Duration> {
        self.tx.subscribe()
    }
}

/// The three Autobahn knobs from `AutobahnTimeout` in agent.proto.
#[derive(Clone, Debug)]
pub struct AutobahnTimeoutCells {
    pub timeout_delay: TimeoutCell,
    pub car_timeout: TimeoutCell,
    pub fast_path_timeout: TimeoutCell,
}

impl AutobahnTimeoutCells {
    pub fn new(timeout_delay: Duration, car_timeout: Duration, fast_path_timeout: Duration) -> Self {
        Self {
            timeout_delay: TimeoutCell::new(timeout_delay),
            car_timeout: TimeoutCell::new(car_timeout),
            fast_path_timeout: TimeoutCell::new(fast_path_timeout),
        }
    }
}

/// The three SBFT knobs from `SbftTimeout` in agent.proto.
#[derive(Clone, Debug)]
pub struct SbftTimeoutCells {
    pub election: TimeoutCell,
    pub slow_path: TimeoutCell,
    pub batch: TimeoutCell,
}

impl SbftTimeoutCells {
    pub fn new(election: Duration, slow_path: Duration, batch: Duration) -> Self {
        Self {
            election: TimeoutCell::new(election),
            slow_path: TimeoutCell::new(slow_path),
            batch: TimeoutCell::new(batch),
        }
    }
}
