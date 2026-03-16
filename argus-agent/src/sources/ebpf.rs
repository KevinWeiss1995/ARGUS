//! Live eBPF event source - only compiles and runs on Linux.
//!
//! Loads compiled eBPF programs, attaches tracepoints, and provides
//! aggregated metrics from in-kernel per-CPU BPF maps.
//!
//! # Architecture
//! High-frequency tracepoints (IRQ, slab, NAPI) write to per-CPU BPF array
//! maps in kernel space. Userspace reads these maps on a timer (once per
//! aggregation window) — no ring buffer polling, no per-event overhead.
//!
//! # Safety
//! This module is the kernel/eBPF FFI boundary. It allows `unsafe_code`
//! because BPF map operations require `Pod` trait implementations.

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod inner {
    use aya::maps::PerCpuArray;
    use aya::programs::TracePoint;
    use aya::{Ebpf, EbpfLoader, Pod};
    use std::path::Path;
    use tracing::{info, warn};

    use crate::sources::tracepoint_format;
    use crate::sources::EventSourceError;

    /// Aggregated BPF map data for one window, computed as deltas from previous read.
    #[derive(Debug, Clone, Default)]
    pub struct BpfMapSnapshot {
        pub per_cpu_irq_deltas: Vec<u64>,
        pub total_irq_count: u64,
        pub slab_alloc_count: u64,
        pub slab_free_count: u64,
        pub slab_total_bytes_req: u64,
        pub slab_total_bytes_alloc: u64,
        pub napi_poll_count: u64,
        pub napi_total_work: u64,
        pub napi_total_budget: u64,
    }

    // SAFETY: [u64; 4] and [u64; 3] are plain arrays of Pod types, trivially safe.
    unsafe impl Pod for SlabStatsArray {}
    unsafe impl Pod for NapiStatsArray {}

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct SlabStatsArray([u64; 4]);
    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct NapiStatsArray([u64; 3]);

    pub struct EbpfEventSource {
        #[allow(dead_code)]
        ebpf: Ebpf,
        attached_probes: Vec<String>,
        irq_counts_map: PerCpuArray<aya::maps::MapData, u64>,
        slab_stats_map: PerCpuArray<aya::maps::MapData, SlabStatsArray>,
        napi_stats_map: PerCpuArray<aya::maps::MapData, NapiStatsArray>,
        prev_irq_per_cpu: Vec<u64>,
        prev_slab_totals: [u64; 4],
        prev_napi_totals: [u64; 3],
        read_count: u32,
    }

    impl EbpfEventSource {
        /// Load the eBPF program and attach tracepoints.
        pub fn new(ebpf_path: &Path) -> Result<Self, EventSourceError> {
            let mut ebpf = EbpfLoader::new()
                .load_file(ebpf_path)
                .map_err(|e| EventSourceError::Other(format!("failed to load eBPF: {e}")))?;

            if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
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

            let irq_map = ebpf
                .take_map("IRQ_COUNTS")
                .ok_or_else(|| EventSourceError::Other("IRQ_COUNTS map not found".into()))?;
            let irq_counts_map: PerCpuArray<_, u64> = irq_map.try_into().map_err(|e| {
                EventSourceError::Other(format!("IRQ_COUNTS not a PerCpuArray: {e}"))
            })?;

            let slab_map = ebpf
                .take_map("SLAB_STATS")
                .ok_or_else(|| EventSourceError::Other("SLAB_STATS map not found".into()))?;
            let slab_stats_map: PerCpuArray<_, SlabStatsArray> =
                slab_map.try_into().map_err(|e| {
                    EventSourceError::Other(format!("SLAB_STATS not a PerCpuArray: {e}"))
                })?;

            let napi_map = ebpf
                .take_map("NAPI_STATS")
                .ok_or_else(|| EventSourceError::Other("NAPI_STATS map not found".into()))?;
            let napi_stats_map: PerCpuArray<_, NapiStatsArray> =
                napi_map.try_into().map_err(|e| {
                    EventSourceError::Other(format!("NAPI_STATS not a PerCpuArray: {e}"))
                })?;

            Ok(Self {
                ebpf,
                attached_probes,
                irq_counts_map,
                slab_stats_map,
                napi_stats_map,
                prev_irq_per_cpu: Vec::new(),
                prev_slab_totals: [0; 4],
                prev_napi_totals: [0; 3],
                read_count: 0,
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

            let offsets_map = ebpf.map_mut("OFFSETS").ok_or_else(|| {
                EventSourceError::Other("OFFSETS map not found in eBPF object".into())
            })?;
            let mut arr: aya::maps::Array<_, u32> = offsets_map
                .try_into()
                .map_err(|e| EventSourceError::Other(format!("OFFSETS is not an Array: {e}")))?;

            for (idx, val) in &offsets {
                arr.set(*idx, *val, 0).map_err(|e| {
                    EventSourceError::Other(format!("failed to set OFFSETS[{idx}]={val}: {e}"))
                })?;
            }

            info!(
                count = offsets.len(),
                "tracepoint field offsets populated from tracefs"
            );
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

        /// Read all per-CPU BPF maps and return aggregated deltas since last read.
        /// Called once per aggregation window from the main loop timer.
        pub fn read_bpf_snapshot(&mut self) -> BpfMapSnapshot {
            let mut snap = BpfMapSnapshot::default();
            self.read_count += 1;
            let diagnostic = self.read_count <= 3;

            // --- IRQ counts (per-CPU) ---
            match self.irq_counts_map.get(&0, 0) {
                Ok(percpu_vals) => {
                    let current: Vec<u64> = percpu_vals.iter().copied().collect();
                    if diagnostic {
                        info!(
                            read = self.read_count,
                            ?current,
                            "IRQ_COUNTS raw per-cpu values"
                        );
                    }

                    if self.prev_irq_per_cpu.is_empty() {
                        self.prev_irq_per_cpu = vec![0; current.len()];
                    }

                    let mut deltas = Vec::with_capacity(current.len());
                    for (i, &cur) in current.iter().enumerate() {
                        let prev = self.prev_irq_per_cpu.get(i).copied().unwrap_or(0);
                        deltas.push(cur.saturating_sub(prev));
                    }
                    snap.total_irq_count = deltas.iter().sum();
                    snap.per_cpu_irq_deltas = deltas;
                    self.prev_irq_per_cpu = current;
                }
                Err(e) => {
                    warn!("IRQ_COUNTS map read failed: {e}");
                }
            }

            // --- Slab stats ---
            match self.slab_stats_map.get(&0, 0) {
                Ok(percpu_vals) => {
                    let mut totals = [0u64; 4];
                    for val in percpu_vals.iter() {
                        for (i, t) in totals.iter_mut().enumerate() {
                            *t += val.0[i];
                        }
                    }
                    if diagnostic {
                        info!(read = self.read_count, ?totals, "SLAB_STATS summed totals");
                    }

                    let prev = &self.prev_slab_totals;
                    snap.slab_alloc_count = totals[0].saturating_sub(prev[0]);
                    snap.slab_free_count = totals[1].saturating_sub(prev[1]);
                    snap.slab_total_bytes_req = totals[2].saturating_sub(prev[2]);
                    snap.slab_total_bytes_alloc = totals[3].saturating_sub(prev[3]);
                    self.prev_slab_totals = totals;
                }
                Err(e) => {
                    warn!("SLAB_STATS map read failed: {e}");
                }
            }

            // --- NAPI stats ---
            match self.napi_stats_map.get(&0, 0) {
                Ok(percpu_vals) => {
                    let mut totals = [0u64; 3];
                    for val in percpu_vals.iter() {
                        for (i, t) in totals.iter_mut().enumerate() {
                            *t += val.0[i];
                        }
                    }

                    let prev = &self.prev_napi_totals;
                    snap.napi_poll_count = totals[0].saturating_sub(prev[0]);
                    snap.napi_total_work = totals[1].saturating_sub(prev[1]);
                    snap.napi_total_budget = totals[2].saturating_sub(prev[2]);
                    self.prev_napi_totals = totals;
                }
                Err(e) => {
                    warn!("NAPI_STATS map read failed: {e}");
                }
            }

            snap
        }

        /// Returns the list of successfully attached tracepoint probes.
        pub fn attached_probes(&self) -> &[String] {
            &self.attached_probes
        }

        /// Returns true if the given tracepoint category/name is attached.
        pub fn has_probe(&self, probe: &str) -> bool {
            self.attached_probes.iter().any(|p| p == probe)
        }
    }
}

#[cfg(target_os = "linux")]
pub use inner::{BpfMapSnapshot, EbpfEventSource};
