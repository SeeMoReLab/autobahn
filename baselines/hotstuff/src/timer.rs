use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::time::{sleep, Duration, Instant, Sleep};

#[cfg(test)]
#[path = "tests/timer_tests.rs"]
pub mod timer_tests;

pub struct Timer {
    duration: u64,
    sleep: Pin<Box<Sleep>>,
}

impl Timer {
    pub fn new(duration: u64) -> Self {
        let sleep = Box::pin(sleep(Duration::from_millis(duration)));
        Self { duration, sleep }
    }

    pub fn reset(&mut self) {
        self.sleep
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(self.duration));
    }

    /// Re-arm with a new duration (used by the adaptive timeout cell, which
    /// can change between rounds).
    pub fn reset_after(&mut self, duration_ms: u64) {
        self.duration = duration_ms;
        self.sleep
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(duration_ms));
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.sleep.as_mut().poll(cx)
    }
}
