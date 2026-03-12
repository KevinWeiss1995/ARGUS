//! Live eBPF event source - only compiles and runs on Linux.
//!
//! Loads compiled eBPF programs, attaches tracepoints, and reads events
//! from the shared ring buffer.

#[cfg(target_os = "linux")]
mod inner {
    use aya::maps::RingBuf;
    use aya::programs::TracePoint;
    use aya::{Ebpf, EbpfLoader};
    use aya_log::EbpfLogger;
    use std::path::Path;
    use tokio::io::unix::AsyncFd;
    use tracing::{info, warn};

    use argus_common::*;
    use crate::sources::{EventSource, EventSourceError};

    const EVENT_TYPE_SLAB_ALLOC: u32 = 1;
    const EVENT_TYPE_SLAB_FREE: u32 = 2;
    const EVENT_TYPE_IRQ_ENTRY: u32 = 3;
    const EVENT_TYPE_NAPI_POLL: u32 = 4;

    /// Ring buffer event header - must match eBPF-side layout.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RingEventHeader {
        event_type: u32,
        _pad: u32,
        timestamp_ns: u64,
        cpu: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SlabAllocRingEvent {
        event_type: u32,
        _pad: u32,
        timestamp_ns: u64,
        cpu: u32,
        bytes_req: u32,
        bytes_alloc: u32,
        _pad2: u32,
        latency_ns: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SlabFreeRingEvent {
        event_type: u32,
        _pad: u32,
        timestamp_ns: u64,
        cpu: u32,
        bytes_freed: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IrqEntryRingEvent {
        event_type: u32,
        _pad: u32,
        timestamp_ns: u64,
        cpu: u32,
        irq: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NapiPollRingEvent {
        event_type: u32,
        _pad: u32,
        timestamp_ns: u64,
        cpu: u32,
        budget: u32,
        work_done: u32,
        _pad2: u32,
    }

    pub struct EbpfEventSource {
        ebpf: Ebpf,
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

            // Attach tracepoints
            Self::attach_tracepoint(&mut ebpf, "trace_kmem_cache_alloc", "kmem", "kmem_cache_alloc")?;
            Self::attach_tracepoint(&mut ebpf, "trace_kmem_cache_free", "kmem", "kmem_cache_free")?;
            Self::attach_tracepoint(&mut ebpf, "trace_irq_handler_entry", "irq", "irq_handler_entry")?;
            Self::attach_tracepoint(&mut ebpf, "trace_napi_poll", "napi", "napi_poll")?;

            info!("eBPF probes attached successfully");

            Ok(Self {
                ebpf,
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

        fn drain_ring_buffer(&mut self) -> Result<(), EventSourceError> {
            let ring_buf = self.ebpf
                .map_mut("EVENTS")
                .ok_or_else(|| EventSourceError::Other("EVENTS map not found".into()))?;
            let ring_buf: &mut RingBuf<_> = ring_buf
                .try_into()
                .map_err(|e| EventSourceError::Other(format!("not a ring buffer: {e}")))?;

            while let Some(item) = ring_buf.next() {
                let data = item.as_ref();
                if data.len() < 4 {
                    continue;
                }

                let event_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

                let event = match event_type {
                    EVENT_TYPE_SLAB_ALLOC if data.len() >= core::mem::size_of::<SlabAllocRingEvent>() => {
                        let raw = unsafe { &*(data.as_ptr() as *const SlabAllocRingEvent) };
                        Some(ArgusEvent::SlabAlloc(SlabAllocEvent {
                            timestamp_ns: raw.timestamp_ns,
                            cpu: raw.cpu,
                            bytes_req: raw.bytes_req,
                            bytes_alloc: raw.bytes_alloc,
                            latency_ns: raw.latency_ns,
                            numa_node: 0,
                        }))
                    }
                    EVENT_TYPE_SLAB_FREE if data.len() >= core::mem::size_of::<SlabFreeRingEvent>() => {
                        let raw = unsafe { &*(data.as_ptr() as *const SlabFreeRingEvent) };
                        Some(ArgusEvent::SlabFree(SlabFreeEvent {
                            timestamp_ns: raw.timestamp_ns,
                            cpu: raw.cpu,
                            bytes_freed: raw.bytes_freed,
                        }))
                    }
                    EVENT_TYPE_IRQ_ENTRY if data.len() >= core::mem::size_of::<IrqEntryRingEvent>() => {
                        let raw = unsafe { &*(data.as_ptr() as *const IrqEntryRingEvent) };
                        Some(ArgusEvent::IrqEntry(IrqEntryEvent {
                            timestamp_ns: raw.timestamp_ns,
                            cpu: raw.cpu,
                            irq: raw.irq,
                            handler_name_hash: 0,
                        }))
                    }
                    EVENT_TYPE_NAPI_POLL if data.len() >= core::mem::size_of::<NapiPollRingEvent>() => {
                        let raw = unsafe { &*(data.as_ptr() as *const NapiPollRingEvent) };
                        Some(ArgusEvent::NapiPoll(NapiPollEvent {
                            timestamp_ns: raw.timestamp_ns,
                            cpu: raw.cpu,
                            budget: raw.budget,
                            work_done: raw.work_done,
                            dev_name_hash: 0,
                        }))
                    }
                    _ => None,
                };

                if let Some(evt) = event {
                    self.pending_events.push(evt);
                }
            }

            Ok(())
        }
    }

    impl EventSource for EbpfEventSource {
        async fn next_event(&mut self) -> Result<ArgusEvent, EventSourceError> {
            loop {
                if let Some(event) = self.pending_events.pop() {
                    return Ok(event);
                }

                // Small sleep to avoid busy-spinning, then drain
                tokio::time::sleep(std::time::Duration::from_micros(100)).await;
                self.drain_ring_buffer()?;
            }
        }

        fn name(&self) -> &str {
            "ebpf"
        }
    }
}

// Re-export on Linux
#[cfg(target_os = "linux")]
pub use inner::EbpfEventSource;
