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
    use aya::maps::{HashMap as AyaHashMap, PerCpuArray, PerCpuValues};
    use aya::programs::{KProbe, TracePoint};
    use aya::{Ebpf, EbpfLoader, Pod};
    use std::path::Path;
    use tracing::{info, warn};

    use crate::sources::kallsyms;
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
        // CQ jitter fields
        pub cq_completion_count: u64,
        pub cq_total_latency_ns: u64,
        pub cq_max_latency_ns: u64,
        pub cq_stall_count: u64,
    }

    // SAFETY: [u64; 4] and [u64; 3] are plain arrays of Pod types, trivially safe.
    unsafe impl Pod for SlabStatsArray {}
    unsafe impl Pod for NapiStatsArray {}
    unsafe impl Pod for CqJitterStatsArray {}

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct SlabStatsArray([u64; 4]);
    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct NapiStatsArray([u64; 3]);
    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct CqJitterStatsArray([u64; 4]);

    pub struct EbpfEventSource {
        #[allow(dead_code)]
        ebpf: Ebpf,
        attached_probes: Vec<String>,
        irq_counts_map: PerCpuArray<aya::maps::MapData, u64>,
        slab_stats_map: PerCpuArray<aya::maps::MapData, SlabStatsArray>,
        napi_stats_map: PerCpuArray<aya::maps::MapData, NapiStatsArray>,
        cq_jitter_stats_map: Option<PerCpuArray<aya::maps::MapData, CqJitterStatsArray>>,
        qp_owners_map: Option<AyaHashMap<aya::maps::MapData, u32, u32>>,
        prev_irq_per_cpu: Vec<u64>,
        prev_slab_totals: [u64; 4],
        prev_napi_totals: [u64; 3],
        prev_cq_totals: [u64; 4],
        read_count: u32,
    }

    impl EbpfEventSource {
        /// Load the eBPF program and attach tracepoints + kprobes.
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

            // Attach CQ jitter kprobes (optional — graceful degradation)
            let kprobe_targets = kallsyms::discover_kprobe_targets();
            let mut cq_kprobes_attached = false;
            if kprobe_targets.is_available() {
                let submit_fn = kprobe_targets.wr_submit.as_deref().unwrap();
                let poll_fn = kprobe_targets.cq_poll.as_deref().unwrap();

                match Self::attach_kprobe(&mut ebpf, "kprobe_wr_submit", submit_fn) {
                    Ok(()) => {
                        info!(func = submit_fn, "WR submit kprobe attached");
                        attached += 1;
                        attached_probes.push(format!("kprobe/{submit_fn}"));
                    }
                    Err(e) => {
                        warn!(func = submit_fn, "WR submit kprobe failed: {e}");
                        failures.push(format!("kprobe/{submit_fn}: {e}"));
                    }
                }

                // CQ poll uses an entry kprobe + kretprobe pair
                let mut poll_entry_ok = false;
                match Self::attach_kprobe(&mut ebpf, "kprobe_cq_poll_entry", poll_fn) {
                    Ok(()) => {
                        info!(func = poll_fn, "CQ poll entry kprobe attached");
                        attached += 1;
                        attached_probes.push(format!("kprobe/{poll_fn}"));
                        poll_entry_ok = true;
                    }
                    Err(e) => {
                        warn!(func = poll_fn, "CQ poll entry kprobe failed: {e}");
                        failures.push(format!("kprobe/{poll_fn}: {e}"));
                    }
                }

                if poll_entry_ok {
                    match Self::attach_kretprobe(&mut ebpf, "kretprobe_cq_poll", poll_fn) {
                        Ok(()) => {
                            info!(func = poll_fn, "CQ poll kretprobe attached");
                            attached += 1;
                            attached_probes.push(format!("kretprobe/{poll_fn}"));
                            cq_kprobes_attached = true;
                        }
                        Err(e) => {
                            warn!(func = poll_fn, "CQ poll kretprobe failed: {e}");
                            failures.push(format!("kretprobe/{poll_fn}: {e}"));
                        }
                    }
                }
            } else {
                info!("CQ jitter kprobe targets not available — micro-stall detection disabled");
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

            // CQ jitter maps (only if kprobes were attached)
            let cq_jitter_stats_map = if cq_kprobes_attached {
                ebpf.take_map("CQ_JITTER_STATS").and_then(|m| {
                    let arr: Result<PerCpuArray<_, CqJitterStatsArray>, _> = m.try_into();
                    match arr {
                        Ok(a) => Some(a),
                        Err(e) => {
                            warn!("CQ_JITTER_STATS map error: {e}");
                            None
                        }
                    }
                })
            } else {
                None
            };

            let qp_owners_map = if cq_kprobes_attached {
                ebpf.take_map("QP_OWNERS").and_then(|m| {
                    let hm: Result<AyaHashMap<_, u32, u32>, _> = m.try_into();
                    match hm {
                        Ok(h) => Some(h),
                        Err(e) => {
                            warn!("QP_OWNERS map error: {e}");
                            None
                        }
                    }
                })
            } else {
                None
            };

            Ok(Self {
                ebpf,
                attached_probes,
                irq_counts_map,
                slab_stats_map,
                napi_stats_map,
                cq_jitter_stats_map,
                qp_owners_map,
                prev_irq_per_cpu: Vec::new(),
                prev_slab_totals: [0; 4],
                prev_napi_totals: [0; 3],
                prev_cq_totals: [0; 4],
                read_count: 0,
            })
        }

        /// Read tracepoint format files from tracefs and populate the BPF OFFSETS map
        /// so probes read fields at the correct kernel-specific byte offsets.
        /// Also populates struct field offsets (ib_qp, ib_wc) from BTF/fallback.
        fn populate_offsets(ebpf: &mut Ebpf) -> Result<(), EventSourceError> {
            let mut offsets = tracepoint_format::discover_offsets();

            // Discover kprobe struct field offsets (ib_qp.qp_num, ib_wc.qp)
            let field_offsets = kallsyms::discover_kprobe_field_offsets();
            if let Some(off) = field_offsets.ib_qp_qp_num {
                info!(offset = off, "ib_qp.qp_num offset");
                offsets.push((tracepoint_format::OFF_IB_QP_QP_NUM, off));
            }
            if let Some(off) = field_offsets.ib_wc_qp {
                info!(offset = off, "ib_wc.qp offset");
                offsets.push((tracepoint_format::OFF_IB_WC_QP, off));
            }

            if offsets.is_empty() {
                warn!(
                    "no offsets discovered — probes will skip events until offsets are populated"
                );
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
                "field offsets populated (tracefs + BTF)"
            );
            Ok(())
        }

        fn attach_kprobe(
            ebpf: &mut Ebpf,
            prog_name: &str,
            func_name: &str,
        ) -> Result<(), EventSourceError> {
            let prog: &mut KProbe = ebpf
                .program_mut(prog_name)
                .ok_or_else(|| {
                    EventSourceError::Other(format!("program {prog_name} not found in eBPF object"))
                })?
                .try_into()
                .map_err(|e| EventSourceError::Other(format!("not a kprobe: {e}")))?;

            prog.load()
                .map_err(|e| EventSourceError::Other(format!("failed to load {prog_name}: {e}")))?;
            prog.attach(func_name, 0).map_err(|e| {
                EventSourceError::Other(format!("failed to attach {prog_name} to {func_name}: {e}"))
            })?;

            Ok(())
        }

        fn attach_kretprobe(
            ebpf: &mut Ebpf,
            prog_name: &str,
            func_name: &str,
        ) -> Result<(), EventSourceError> {
            let prog: &mut KProbe = ebpf
                .program_mut(prog_name)
                .ok_or_else(|| {
                    EventSourceError::Other(format!("program {prog_name} not found in eBPF object"))
                })?
                .try_into()
                .map_err(|e| EventSourceError::Other(format!("not a kretprobe: {e}")))?;

            prog.load()
                .map_err(|e| EventSourceError::Other(format!("failed to load {prog_name}: {e}")))?;
            prog.attach(func_name, 0).map_err(|e| {
                EventSourceError::Other(format!("failed to attach {prog_name} to {func_name}: {e}"))
            })?;

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

            // --- CQ jitter stats (optional) ---
            // max_latency_ns accumulates in-kernel as a per-CPU max. We read the
            // cross-CPU max for this window, then rearm by zeroing index 2 on
            // each CPU so the next window starts fresh. counts/totals stay
            // cumulative so delta math below remains correct.
            if let Some(ref mut map) = self.cq_jitter_stats_map {
                match map.get(&0, 0) {
                    Ok(percpu_vals) => {
                        let mut totals = [0u64; 4];
                        let mut rearmed: Vec<CqJitterStatsArray> =
                            Vec::with_capacity(percpu_vals.len());
                        for val in percpu_vals.iter() {
                            for (i, t) in totals.iter_mut().enumerate() {
                                if i == 2 {
                                    *t = (*t).max(val.0[i]);
                                } else {
                                    *t += val.0[i];
                                }
                            }
                            let mut zeroed_max = *val;
                            zeroed_max.0[2] = 0;
                            rearmed.push(zeroed_max);
                        }

                        let prev = &self.prev_cq_totals;
                        snap.cq_completion_count = totals[0].saturating_sub(prev[0]);
                        snap.cq_total_latency_ns = totals[1].saturating_sub(prev[1]);
                        snap.cq_max_latency_ns = totals[2];
                        snap.cq_stall_count = totals[3].saturating_sub(prev[3]);
                        self.prev_cq_totals = [totals[0], totals[1], 0, totals[3]];

                        match PerCpuValues::try_from(rearmed) {
                            Ok(values) => {
                                if let Err(e) = map.set(0, values, 0) {
                                    warn!("CQ_JITTER_STATS max rearm failed: {e}");
                                }
                            }
                            Err(e) => {
                                warn!("CQ_JITTER_STATS PerCpuValues build failed: {e}");
                            }
                        }

                        if diagnostic && snap.cq_completion_count > 0 {
                            info!(
                                read = self.read_count,
                                completions = snap.cq_completion_count,
                                stalls = snap.cq_stall_count,
                                max_ns = snap.cq_max_latency_ns,
                                "CQ_JITTER_STATS"
                            );
                        }
                    }
                    Err(e) => {
                        warn!("CQ_JITTER_STATS map read failed: {e}");
                    }
                }
            }

            snap
        }

        /// Read the QP→PID mapping from the BPF HashMap.
        /// Returns a mapping of QP numbers to PIDs for blast radius attribution.
        pub fn read_qp_owners(&self) -> std::collections::HashMap<u32, u32> {
            let mut owners = std::collections::HashMap::new();
            if let Some(ref map) = self.qp_owners_map {
                for item in map.iter() {
                    if let Ok((qp, pid)) = item {
                        owners.insert(qp, pid);
                    }
                }
            }
            owners
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
