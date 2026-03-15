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

    use crate::sources::ebpf_parse;
    use crate::sources::tracepoint_format;
    use crate::sources::{EventSource, EventSourceError};
    use argus_common::*;

    pub struct EbpfEventSource {
        #[allow(dead_code)]
        ebpf: Ebpf,
        ring_buf: RingBuf<aya::maps::MapData>,
        pending_events: Vec<ArgusEvent>,
        dropped_events: u64,
        attached_probes: Vec<String>,
    }

    impl EbpfEventSource {
        /// Load the eBPF program and attach tracepoints.
        pub fn new(ebpf_path: &Path) -> Result<Self, EventSourceError> {
            let mut ebpf = EbpfLoader::new()
                .load_file(ebpf_path)
                .map_err(|e| EventSourceError::Other(format!("failed to load eBPF: {e}")))?;

            if let Err(e) = EbpfLogger::init(&mut ebpf) {
                warn!("Failed to init eBPF logger (non-fatal): {e}");
            }

            Self::populate_offsets(&mut ebpf)?;

            let probes: &[(&str, &str, &str)] = &[
                ("trace_kmem_cache_alloc", "kmem", "kmem_cache_alloc"),
                ("trace_kmem_cache_free", "kmem", "kmem_cache_free"),
                ("trace_irq_handler_entry", "irq", "irq_handler_entry"),
                ("trace_napi_poll", "napi", "napi_poll"),
            ];

            let mut attached = 0u32;
            let mut failures: Vec<String> = Vec::new();
            let mut attached_probes: Vec<String> = Vec::new();
            for &(prog, category, name) in probes {
                match Self::attach_tracepoint(&mut ebpf, prog, category, name) {
                    Ok(()) => {
                        info!("{category}/{name} attached");
                        attached += 1;
                        attached_probes.push(format!("{category}/{name}"));
                    }
                    Err(e) => {
                        let msg = format!("{category}/{name}: {e}");
                        warn!("skipping {msg}");
                        failures.push(msg);
                    }
                }
            }

            if attached == 0 {
                let detail = failures.join("\n  ");
                return Err(EventSourceError::Other(format!(
                    "no eBPF probes could be attached ({} tried, all failed):\n  {detail}",
                    probes.len()
                )));
            }

            if !failures.is_empty() {
                info!(
                    attached,
                    skipped = failures.len(),
                    "eBPF probes partially attached"
                );
            } else {
                info!(attached, "all eBPF probes attached");
            }

            let events_map = ebpf
                .take_map("EVENTS")
                .ok_or_else(|| EventSourceError::Other("EVENTS map not found".into()))?;
            let ring_buf = RingBuf::try_from(events_map)
                .map_err(|e| EventSourceError::Other(format!("EVENTS is not a RingBuf: {e}")))?;

            Ok(Self {
                ebpf,
                ring_buf,
                pending_events: Vec::new(),
                dropped_events: 0,
                attached_probes,
            })
        }

        /// Read tracepoint format files from tracefs and populate the BPF OFFSETS map
        /// so probes read fields at the correct kernel-specific byte offsets.
        fn populate_offsets(ebpf: &mut Ebpf) -> Result<(), EventSourceError> {
            let offsets = tracepoint_format::discover_offsets();
            if offsets.is_empty() {
                warn!("no tracepoint offsets discovered — probes will skip events until offsets are populated");
                return Ok(());
            }

            let offsets_map = ebpf
                .map_mut("OFFSETS")
                .ok_or_else(|| EventSourceError::Other("OFFSETS map not found in eBPF object".into()))?;
            let mut arr: aya::maps::Array<_, u32> = offsets_map
                .try_into()
                .map_err(|e| EventSourceError::Other(format!("OFFSETS is not an Array: {e}")))?;

            for (idx, val) in &offsets {
                arr.set(*idx, *val, 0)
                    .map_err(|e| EventSourceError::Other(format!("failed to set OFFSETS[{idx}]={val}: {e}")))?;
            }

            info!(count = offsets.len(), "tracepoint field offsets populated from tracefs");
            Ok(())
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
            prog.attach(category, name).map_err(|e| {
                EventSourceError::Other(format!(
                    "failed to attach {prog_name} to {category}/{name}: {e}"
                ))
            })?;

            info!(prog_name, category, name, "tracepoint attached");
            Ok(())
        }

        fn drain_ring_buffer(&mut self) {
            while let Some(item) = self.ring_buf.next() {
                let data = item.as_ref();
                match ebpf_parse::parse_event(data) {
                    Some(evt) => self.pending_events.push(evt),
                    None => self.dropped_events += 1,
                }
            }
        }
    }

    impl EbpfEventSource {
        /// Returns the list of successfully attached tracepoint probes.
        pub fn attached_probes(&self) -> &[String] {
            &self.attached_probes
        }

        /// Returns the count of ring buffer items that were too small to parse.
        pub fn dropped_events(&self) -> u64 {
            self.dropped_events
        }

        /// Returns true if the given tracepoint category/name is attached.
        pub fn has_probe(&self, probe: &str) -> bool {
            self.attached_probes.iter().any(|p| p == probe)
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
