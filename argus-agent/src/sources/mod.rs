#![allow(clippy::module_name_repetitions)]

#[cfg(target_os = "linux")]
pub mod ebpf;
pub mod ebpf_parse;
pub mod hwcounters;
#[cfg(target_os = "linux")]
pub mod kallsyms;
pub mod mock;
pub mod process_resolver;
pub mod replay;
#[cfg(target_os = "linux")]
pub mod tracepoint_format;

use argus_common::ArgusEvent;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EventSourceError {
    #[error("event source exhausted")]
    Exhausted,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("deserialization error: {0}")]
    Deserialize(#[from] serde_json::Error),
    #[error("source error: {0}")]
    Other(String),
}

/// Abstraction boundary between eBPF (Linux) and everything else.
/// Implementations: live eBPF, mock generator, file replay, scenario player.
#[allow(async_fn_in_trait)]
pub trait EventSource: Send {
    async fn next_event(&mut self) -> Result<ArgusEvent, EventSourceError>;

    /// Drain up to `max` events in one call. Returns at least 1 event or an error.
    /// Default implementation delegates to next_event() one at a time.
    async fn next_batch(&mut self, max: usize) -> Result<Vec<ArgusEvent>, EventSourceError> {
        let first = self.next_event().await?;
        let mut batch = Vec::with_capacity(max.min(64));
        batch.push(first);
        // Drain any immediately-available events without blocking
        while batch.len() < max {
            match self.try_next() {
                Some(evt) => batch.push(evt),
                None => break,
            }
        }
        Ok(batch)
    }

    /// Non-blocking: return an event if one is immediately available.
    fn try_next(&mut self) -> Option<ArgusEvent> {
        None
    }

    fn name(&self) -> &str;
}

/// Enum dispatch for event sources (mock/replay only — live uses BPF maps directly).
pub enum AnyEventSource {
    Mock(mock::MockEventSource),
    Replay(replay::ReplayEventSource),
}

impl AnyEventSource {
    pub async fn next_event(&mut self) -> Result<ArgusEvent, EventSourceError> {
        match self {
            Self::Mock(s) => s.next_event().await,
            Self::Replay(s) => s.next_event().await,
        }
    }

    pub async fn next_batch(&mut self, max: usize) -> Result<Vec<ArgusEvent>, EventSourceError> {
        match self {
            Self::Mock(s) => s.next_batch(max).await,
            Self::Replay(s) => s.next_batch(max).await,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Mock(s) => s.name(),
            Self::Replay(s) => s.name(),
        }
    }
}
