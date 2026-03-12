use argus_common::{
    ArgusEvent, CqCompletionEvent, IrqEntryEvent, NapiPollEvent, SlabAllocEvent, SlabFreeEvent,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::time::Duration;
use tokio::time::sleep;

use super::{EventSource, EventSourceError};

/// Generates synthetic events with configurable profiles for testing.
pub struct MockEventSource {
    config: MockConfig,
    event_count: u64,
    base_timestamp: u64,
    rng: StdRng,
}

#[derive(Debug, Clone)]
pub struct MockConfig {
    pub num_cpus: u32,
    pub event_interval: Duration,
    pub irq_skew_cpu: Option<u32>,
    pub irq_skew_pct: f64,
    pub slab_latency_base_ns: u64,
    pub slab_latency_spike_factor: f64,
    pub cq_latency_base_ns: u64,
    pub cq_latency_spike_factor: f64,
    pub cq_error_rate: f64,
    pub max_events: Option<u64>,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            num_cpus: 4,
            event_interval: Duration::from_millis(10),
            irq_skew_cpu: None,
            irq_skew_pct: 0.25,
            slab_latency_base_ns: 500,
            slab_latency_spike_factor: 1.0,
            cq_latency_base_ns: 2000,
            cq_latency_spike_factor: 1.0,
            cq_error_rate: 0.001,
            max_events: None,
        }
    }
}

impl MockConfig {
    #[must_use]
    pub fn healthy() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn interrupt_skew() -> Self {
        Self {
            irq_skew_cpu: Some(0),
            irq_skew_pct: 0.80,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn rdma_latency_spike() -> Self {
        Self {
            cq_latency_spike_factor: 8.0,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn slab_pressure() -> Self {
        Self {
            slab_latency_spike_factor: 10.0,
            ..Self::default()
        }
    }
}

impl MockEventSource {
    #[must_use]
    pub fn new(config: MockConfig) -> Self {
        Self {
            config,
            event_count: 0,
            base_timestamp: 1_000_000_000,
            rng: StdRng::from_entropy(),
        }
    }

    #[must_use]
    pub fn with_seed(config: MockConfig, seed: u64) -> Self {
        Self {
            config,
            event_count: 0,
            base_timestamp: 1_000_000_000,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    fn current_timestamp(&self) -> u64 {
        self.base_timestamp + self.event_count * 1_000_000
    }

    fn pick_cpu(&mut self) -> u32 {
        if let Some(skew_cpu) = self.config.irq_skew_cpu {
            if self.rng.gen::<f64>() < self.config.irq_skew_pct {
                return skew_cpu;
            }
        }
        self.rng.gen_range(0..self.config.num_cpus)
    }

    fn generate_event(&mut self) -> ArgusEvent {
        let ts = self.current_timestamp();
        let choice = self.rng.gen_range(0..5);

        match choice {
            0 => {
                let cpu = self.pick_cpu();
                let jitter = self.rng.gen_range(0.8..1.2);
                let spike = self.config.slab_latency_spike_factor;
                let latency = (self.config.slab_latency_base_ns as f64 * spike * jitter) as u64;
                ArgusEvent::SlabAlloc(SlabAllocEvent {
                    timestamp_ns: ts,
                    cpu,
                    bytes_req: self.rng.gen_range(32..4096),
                    bytes_alloc: self.rng.gen_range(32..4096),
                    latency_ns: latency,
                    numa_node: 0,
                })
            }
            1 => ArgusEvent::SlabFree(SlabFreeEvent {
                timestamp_ns: ts,
                cpu: self.pick_cpu(),
                bytes_freed: self.rng.gen_range(32..4096),
            }),
            2 => ArgusEvent::IrqEntry(IrqEntryEvent {
                timestamp_ns: ts,
                cpu: self.pick_cpu(),
                irq: self.rng.gen_range(30..50),
                handler_name_hash: 0xdeadbeef,
            }),
            3 => {
                let budget = 64;
                let work = self.rng.gen_range(0..budget);
                ArgusEvent::NapiPoll(NapiPollEvent {
                    timestamp_ns: ts,
                    cpu: self.pick_cpu(),
                    budget,
                    work_done: work,
                    dev_name_hash: 0xcafebabe,
                })
            }
            _ => {
                let jitter = self.rng.gen_range(0.8..1.2);
                let spike = self.config.cq_latency_spike_factor;
                let latency = (self.config.cq_latency_base_ns as f64 * spike * jitter) as u64;
                let is_error = self.rng.gen::<f64>() < self.config.cq_error_rate;
                ArgusEvent::CqCompletion(CqCompletionEvent {
                    timestamp_ns: ts,
                    cpu: self.pick_cpu(),
                    latency_ns: latency,
                    queue_pair_num: self.rng.gen_range(1..100),
                    is_error,
                    opcode: 0,
                })
            }
        }
    }
}

impl EventSource for MockEventSource {
    async fn next_event(&mut self) -> Result<ArgusEvent, EventSourceError> {
        if let Some(max) = self.config.max_events {
            if self.event_count >= max {
                return Err(EventSourceError::Exhausted);
            }
        }

        if self.event_count > 0 {
            sleep(self.config.event_interval).await;
        }

        let event = self.generate_event();
        self.event_count += 1;
        Ok(event)
    }

    fn name(&self) -> &str {
        "mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_produces_events() {
        let mut source = MockEventSource::new(MockConfig {
            max_events: Some(10),
            event_interval: Duration::ZERO,
            ..MockConfig::default()
        });

        let mut count = 0u64;
        loop {
            match source.next_event().await {
                Ok(_) => count += 1,
                Err(EventSourceError::Exhausted) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert_eq!(count, 10);
    }

    #[tokio::test]
    async fn mock_timestamps_increase() {
        let mut source = MockEventSource::new(MockConfig {
            max_events: Some(5),
            event_interval: Duration::ZERO,
            ..MockConfig::default()
        });

        let mut prev_ts = 0u64;
        for _ in 0..5 {
            let event = source.next_event().await.unwrap();
            let ts = event.timestamp_ns();
            assert!(ts >= prev_ts, "timestamps must be monotonically increasing");
            prev_ts = ts;
        }
    }

    #[tokio::test]
    async fn mock_skew_profile_biases_cpu() {
        let mut source = MockEventSource::new(MockConfig {
            max_events: Some(1000),
            event_interval: Duration::ZERO,
            irq_skew_cpu: Some(0),
            irq_skew_pct: 0.90,
            ..MockConfig::default()
        });

        let mut cpu0_count = 0u64;
        let mut total = 0u64;
        for _ in 0..1000 {
            if let Ok(ArgusEvent::IrqEntry(e)) = source.next_event().await {
                total += 1;
                if e.cpu == 0 {
                    cpu0_count += 1;
                }
            }
        }

        if total > 50 {
            let ratio = cpu0_count as f64 / total as f64;
            assert!(ratio > 0.5, "expected skew toward CPU 0, got {ratio:.2}");
        }
    }
}
