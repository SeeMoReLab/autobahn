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

