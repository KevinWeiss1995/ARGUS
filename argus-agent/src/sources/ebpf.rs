//! Live eBPF event source - only compiles and runs on Linux.
//!
//! Loads compiled eBPF programs, attaches tracepoints, and reads events
//! from the shared ring buffer.
//!
//! # Safety
//! This module is the kernel/eBPF FFI boundary. It allows `unsafe_code`
//! because reading from the eBPF ring buffer requires interpreting raw bytes
//! from kernel memory. All unsafe blocks are size-checked before access.

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod inner {
    use aya::maps::RingBuf;
    use aya::programs::TracePoint;
    use aya::{Ebpf, EbpfLoader};
    use aya_log::EbpfLogger;
    use std::path::Path;
    use tracing::{info, warn};

    use argus_common::*;
    use crate::sources::{EventSource, EventSourceError};

    const EVENT_TYPE_SLAB_ALLOC: u32 = 1;
    const EVENT_TYPE_SLAB_FREE: u32 = 2;
    const EVENT_TYPE_IRQ_ENTRY: u32 = 3;
    const EVENT_TYPE_NAPI_POLL: u32 = 4;

    fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
        data.get(offset..offset + 4)
            .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
        data.get(offset..offset + 8)
            .map(|b| u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Parse a slab alloc event from raw ring buffer bytes.
    /// Layout: event_type(4) + pad(4) + timestamp(8) + cpu(4) + bytes_req(4) + bytes_alloc(4) + pad2(4) + latency(8) = 40 bytes
    fn parse_slab_alloc(data: &[u8]) -> Option<ArgusEvent> {
        if data.len() < 40 {
            return None;
        }
        Some(ArgusEvent::SlabAlloc(SlabAllocEvent {
            timestamp_ns: read_u64(data, 8)?,
            cpu: read_u32(data, 16)?,
            bytes_req: read_u32(data, 20)?,
            bytes_alloc: read_u32(data, 24)?,
            latency_ns: read_u64(data, 32)?,
            numa_node: 0,
        }))
    }

    /// Layout: event_type(4) + pad(4) + timestamp(8) + cpu(4) + bytes_freed(4) = 24 bytes
    fn parse_slab_free(data: &[u8]) -> Option<ArgusEvent> {
        if data.len() < 24 {
            return None;
        }
        Some(ArgusEvent::SlabFree(SlabFreeEvent {
            timestamp_ns: read_u64(data, 8)?,
            cpu: read_u32(data, 16)?,
            bytes_freed: read_u32(data, 20)?,
        }))
    }

    /// Layout: event_type(4) + pad(4) + timestamp(8) + cpu(4) + irq(4) = 24 bytes
    fn parse_irq_entry(data: &[u8]) -> Option<ArgusEvent> {
        if data.len() < 24 {
            return None;
        }
        Some(ArgusEvent::IrqEntry(IrqEntryEvent {
            timestamp_ns: read_u64(data, 8)?,
            cpu: read_u32(data, 16)?,
            irq: read_u32(data, 20)?,
            handler_name_hash: 0,
        }))
    }

    /// Layout: event_type(4) + pad(4) + timestamp(8) + cpu(4) + budget(4) + work_done(4) + pad2(4) = 32 bytes
    fn parse_napi_poll(data: &[u8]) -> Option<ArgusEvent> {
        if data.len() < 32 {
            return None;
        }
        Some(ArgusEvent::NapiPoll(NapiPollEvent {
            timestamp_ns: read_u64(data, 8)?,
            cpu: read_u32(data, 16)?,
            budget: read_u32(data, 20)?,
            work_done: read_u32(data, 24)?,
            dev_name_hash: 0,
        }))
    }

    pub struct EbpfEventSource {
        #[allow(dead_code)]
        ebpf: Ebpf,
        ring_buf: RingBuf<aya::maps::MapData>,
        pending_events: Vec<ArgusEvent>,
    }

    impl EbpfEventSource {
        /// Load the eBPF program and attach tracepoints.
        pub fn new(ebpf_path: &Path) -> Result<Self, EventSourceError> {
            let mut ebpf = EbpfLoader::new()
                .load_file(ebpf_path)
                .map_err(|e| EventSourceError::Other(format!("failed to load eBPF: {e}")))?;

            if let Err(e) = EbpfLogger::init(&mut ebpf) {
                warn!("Failed to init eBPF logger: {e}");
            }

            Self::attach_tracepoint(&mut ebpf, "trace_kmem_cache_alloc", "kmem", "kmem_cache_alloc")?;
            Self::attach_tracepoint(&mut ebpf, "trace_kmem_cache_free", "kmem", "kmem_cache_free")?;
            Self::attach_tracepoint(&mut ebpf, "trace_irq_handler_entry", "irq", "irq_handler_entry")?;
            Self::attach_tracepoint(&mut ebpf, "trace_napi_poll", "napi", "napi_poll")?;

            let events_map = ebpf
                .take_map("EVENTS")
                .ok_or_else(|| EventSourceError::Other("EVENTS map not found".into()))?;
            let ring_buf = RingBuf::try_from(events_map)
                .map_err(|e| EventSourceError::Other(format!("EVENTS is not a RingBuf: {e}")))?;

            info!("eBPF probes attached successfully");

            Ok(Self {
                ebpf,
                ring_buf,
                pending_events: Vec::new(),
            })
        }

        fn attach_tracepoint(
            ebpf: &mut Ebpf,
            prog_name: &str,
            category: &str,
            name: &str,
        ) -> Result<(), EventSourceError> {
            let prog: &mut TracePoint = ebpf
                .program_mut(prog_name)
                .ok_or_else(|| {
                    EventSourceError::Other(format!("program {prog_name} not found in eBPF object"))
                })?
                .try_into()
                .map_err(|e| EventSourceError::Other(format!("not a tracepoint: {e}")))?;

            prog.load()
                .map_err(|e| EventSourceError::Other(format!("failed to load {prog_name}: {e}")))?;
            prog.attach(category, name)
                .map_err(|e| EventSourceError::Other(format!("failed to attach {prog_name} to {category}/{name}: {e}")))?;

            info!(prog_name, category, name, "tracepoint attached");
            Ok(())
        }

        fn drain_ring_buffer(&mut self) {
            while let Some(item) = self.ring_buf.next() {
                let data = item.as_ref();
                if data.len() < 8 {
                    continue;
                }

                let event_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

                let event = match event_type {
                    EVENT_TYPE_SLAB_ALLOC => parse_slab_alloc(data),
                    EVENT_TYPE_SLAB_FREE => parse_slab_free(data),
                    EVENT_TYPE_IRQ_ENTRY => parse_irq_entry(data),
                    EVENT_TYPE_NAPI_POLL => parse_napi_poll(data),
                    _ => None,
                };

                if let Some(evt) = event {
                    self.pending_events.push(evt);
                }
            }
        }
    }

    impl EventSource for EbpfEventSource {
        async fn next_event(&mut self) -> Result<ArgusEvent, EventSourceError> {
            loop {
                if let Some(event) = self.pending_events.pop() {
                    return Ok(event);
                }

                tokio::time::sleep(std::time::Duration::from_micros(100)).await;
                self.drain_ring_buffer();
            }
        }

        fn name(&self) -> &str {
            "ebpf"
        }
    }
}

#[cfg(target_os = "linux")]
pub use inner::EbpfEventSource;
