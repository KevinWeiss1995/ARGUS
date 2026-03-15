use argus_common::{ArgusEvent, TestScenario};
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

use super::{EventSource, EventSourceError};

/// Replays events from a JSON file, preserving relative timing between events.
pub struct ReplayEventSource {
    events: Vec<ArgusEvent>,
    index: usize,
    time_scale: f64,
}

impl ReplayEventSource {
    pub fn from_file(path: &Path) -> Result<Self, EventSourceError> {
        let contents = std::fs::read_to_string(path)?;
        let events: Vec<ArgusEvent> = serde_json::from_str(&contents)?;
        Ok(Self {
            events,
            index: 0,
            time_scale: 1.0,
        })
    }

    pub fn from_scenario_file(
        path: &Path,
    ) -> Result<(Self, Vec<argus_common::ExpectedStateTransition>), EventSourceError> {
        let contents = std::fs::read_to_string(path)?;
        let scenario: TestScenario = serde_json::from_str(&contents)?;
        let source = Self {
            events: scenario.events,
            index: 0,
            time_scale: 1.0,
        };
        Ok((source, scenario.expected_states))
    }

    pub fn from_events(events: Vec<ArgusEvent>) -> Self {
        Self {
            events,
            index: 0,
            time_scale: 1.0,
        }
    }

    /// Speed multiplier: 2.0 = double speed, 0.5 = half speed, 0.0 = instant.
    pub fn with_time_scale(mut self, scale: f64) -> Self {
        self.time_scale = scale;
        self
    }

    #[must_use]
    pub fn total_events(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn remaining_events(&self) -> usize {
        self.events.len().saturating_sub(self.index)
    }
}

impl EventSource for ReplayEventSource {
    async fn next_event(&mut self) -> Result<ArgusEvent, EventSourceError> {
        if self.index >= self.events.len() {
            return Err(EventSourceError::Exhausted);
        }

        if self.index > 0 && self.time_scale > 0.0 {
            let prev_ts = self.events[self.index - 1].timestamp_ns();
            let curr_ts = self.events[self.index].timestamp_ns();
            if curr_ts > prev_ts {
                let delta_ns = curr_ts - prev_ts;
                let scaled = (delta_ns as f64 / self.time_scale) as u64;
                if scaled > 0 {
                    sleep(Duration::from_nanos(scaled)).await;
                }
            }
        }

        let event = self.events[self.index].clone();
        self.index += 1;
        Ok(event)
    }

    fn try_next(&mut self) -> Option<ArgusEvent> {
        if self.index >= self.events.len() {
            return None;
        }
        let event = self.events[self.index].clone();
        self.index += 1;
        Some(event)
    }

    fn name(&self) -> &str {
        "replay"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::{IrqEntryEvent, SlabAllocEvent};
    use tempfile::NamedTempFile;

    fn sample_events() -> Vec<ArgusEvent> {
        vec![
            ArgusEvent::SlabAlloc(SlabAllocEvent {
                timestamp_ns: 1_000_000,
                cpu: 0,
                bytes_req: 64,
                bytes_alloc: 64,
                latency_ns: 150,
                numa_node: 0,
            }),
            ArgusEvent::IrqEntry(IrqEntryEvent {
                timestamp_ns: 2_000_000,
                cpu: 1,
                irq: 33,
                handler_name_hash: 0xaabb,
            }),
            ArgusEvent::SlabAlloc(SlabAllocEvent {
                timestamp_ns: 3_000_000,
                cpu: 0,
                bytes_req: 128,
                bytes_alloc: 128,
                latency_ns: 200,
                numa_node: 0,
            }),
        ]
    }

    #[tokio::test]
    async fn replay_from_events() {
        let mut source = ReplayEventSource::from_events(sample_events()).with_time_scale(0.0);

        let e1 = source.next_event().await.unwrap();
        assert_eq!(e1.timestamp_ns(), 1_000_000);

        let e2 = source.next_event().await.unwrap();
        assert_eq!(e2.timestamp_ns(), 2_000_000);

        let e3 = source.next_event().await.unwrap();
        assert_eq!(e3.timestamp_ns(), 3_000_000);

        assert!(matches!(
            source.next_event().await,
            Err(EventSourceError::Exhausted)
        ));
    }

    #[tokio::test]
    async fn replay_from_file() {
        let events = sample_events();
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_string(&events).unwrap()).unwrap();

        let mut source = ReplayEventSource::from_file(file.path())
            .unwrap()
            .with_time_scale(0.0);

        for expected in &events {
            let got = source.next_event().await.unwrap();
            assert_eq!(got.timestamp_ns(), expected.timestamp_ns());
        }
    }

    #[test]
    fn remaining_events_count() {
        let source = ReplayEventSource::from_events(sample_events());
        assert_eq!(source.total_events(), 3);
        assert_eq!(source.remaining_events(), 3);
    }
}
