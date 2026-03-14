#![allow(clippy::module_name_repetitions)]

#[cfg(target_os = "linux")]
pub mod ebpf;
pub mod ebpf_parse;
pub mod hwcounters;
pub mod mock;
pub mod replay;

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
    fn name(&self) -> &str;
}

/// Enum dispatch for event sources - avoids dyn trait object issues with async.
pub enum AnyEventSource {
    Mock(mock::MockEventSource),
    Replay(replay::ReplayEventSource),
    #[cfg(target_os = "linux")]
    Ebpf(ebpf::EbpfEventSource),
}

impl AnyEventSource {
    pub async fn next_event(&mut self) -> Result<ArgusEvent, EventSourceError> {
        match self {
            Self::Mock(s) => s.next_event().await,
            Self::Replay(s) => s.next_event().await,
            #[cfg(target_os = "linux")]
            Self::Ebpf(s) => s.next_event().await,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Mock(s) => s.name(),
            Self::Replay(s) => s.name(),
            #[cfg(target_os = "linux")]
            Self::Ebpf(s) => s.name(),
        }
    }
}
