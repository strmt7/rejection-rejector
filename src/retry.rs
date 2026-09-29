use rand::Rng;
use std::time::{Duration, Instant};

const MAX_PROVIDER_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitTransition {
    None,
    Opened,
    Closed,
}

/// Bounded scheduled-operation retry gate with exponential backoff, jitter and
/// an explicit open/half-open circuit after repeated failures.
///
/// Manual/operator-triggered actions deliberately do not have to consult this
/// gate; they are explicit probes. Scheduled callers should call `ready` before
/// probing, `failure` after a retryable failure, and `success` after a real
/// successful dependency interaction.
#[derive(Debug)]
pub struct RetryGate {
    failures: u32,
    base: Duration,
    cap: Duration,
    open_after: u32,
    open_for: Duration,
    next_allowed: Instant,
    open: bool,
}

impl RetryGate {
    pub fn new(
        now: Instant,
        base: Duration,
        cap: Duration,
        open_after: u32,
        open_for: Duration,
    ) -> Self {
        debug_assert!(base > Duration::ZERO);
        debug_assert!(cap >= base);
        debug_assert!(open_after > 0);
        Self {
            failures: 0,
            base,
            cap,
            open_after,
            open_for,
            next_allowed: now,
            open: false,
        }
    }

    pub fn ready(&self, now: Instant) -> bool {
        now >= self.next_allowed
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn success(&mut self, now: Instant) -> CircuitTransition {
        let transition = if self.open {
            CircuitTransition::Closed
        } else {
            CircuitTransition::None
        };
        self.failures = 0;
        self.open = false;
        self.next_allowed = now;
        transition
    }

    pub fn failure(
        &mut self,
        now: Instant,
        retry_after: Option<Duration>,
    ) -> (Duration, CircuitTransition) {
        self.failures = self.failures.saturating_add(1);
        let shift = self.failures.saturating_sub(1).min(10);
        let factor = 1u32 << shift;
        let exponential = self.base.saturating_mul(factor).min(self.cap);
        let jittered = jitter(exponential, self.cap);

        let provider_delay = retry_after
            .unwrap_or(Duration::ZERO)
            .min(MAX_PROVIDER_RETRY_AFTER);
        let mut delay = jittered.max(provider_delay);
        let was_open = self.open;
        if self.failures >= self.open_after {
            self.open = true;
            delay = delay.max(self.open_for);
        }
        self.next_allowed = now + delay;
        let transition = if self.open && !was_open {
            CircuitTransition::Opened
        } else {
            CircuitTransition::None
        };
        (delay, transition)
    }
}

fn jitter(delay: Duration, cap: Duration) -> Duration {
    let spread_seconds = delay.as_secs() / 5;
    if spread_seconds == 0 || delay >= cap {
        return delay.min(cap);
    }
    let extra = rand::thread_rng().gen_range(0..=spread_seconds);
    delay.saturating_add(Duration::from_secs(extra)).min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_failures_open_and_success_closes_circuit() {
        let now = Instant::now();
        let mut gate = RetryGate::new(
            now,
            Duration::from_secs(10),
            Duration::from_secs(120),
            3,
            Duration::from_secs(90),
        );
        let (_, first) = gate.failure(now, None);
        assert_eq!(first, CircuitTransition::None);
        let (_, second) = gate.failure(now, None);
        assert_eq!(second, CircuitTransition::None);
        let (delay, third) = gate.failure(now, None);
        assert_eq!(third, CircuitTransition::Opened);
        assert!(delay >= Duration::from_secs(90));
        assert!(!gate.ready(now));
        assert_eq!(gate.failures(), 3);

        let later = now + delay;
        assert!(gate.ready(later));
        assert_eq!(gate.success(later), CircuitTransition::Closed);
        assert_eq!(gate.failures(), 0);
    }

    #[test]
    fn provider_retry_after_is_respected_and_bounded() {
        let now = Instant::now();
        let mut gate = RetryGate::new(
            now,
            Duration::from_secs(10),
            Duration::from_secs(60),
            10,
            Duration::from_secs(60),
        );
        let (delay, _) = gate.failure(now, Some(Duration::from_secs(300)));
        assert!(delay >= Duration::from_secs(300));
        let (bounded, _) = gate.failure(now, Some(Duration::from_secs(24 * 60 * 60)));
        assert!(bounded <= MAX_PROVIDER_RETRY_AFTER);
    }
}
