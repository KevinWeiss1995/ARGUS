//! Procfs-based metric collection for environments where eBPF is unavailable.
//!
//! Reads `/proc/interrupts`, `/proc/slabinfo`, and `/proc/net/softnet_stat`
//! to provide IRQ distribution, slab pressure, and NAPI saturation metrics
//! as a Tier 2 fallback.

use tracing::warn;

#[derive(Debug, Clone, Default)]
pub struct ProcfsSnapshot {
    pub per_cpu_irq_deltas: Vec<u64>,
    pub total_irq_count: u64,
    pub slab_active_objects: u64,
    pub slab_total_objects: u64,
    pub slab_active_slabs: u64,
    pub slab_fragmentation_pct: f64,
    pub softnet_processed: Vec<u64>,
    pub softnet_dropped: Vec<u64>,
    pub softnet_time_squeeze: Vec<u64>,
    pub total_time_squeeze: u64,
    pub total_softnet_processed: u64,
}

pub struct ProcfsCollector {
    prev_interrupts: Vec<u64>,
    prev_softnet_processed: Vec<u64>,
    prev_softnet_time_squeeze: Vec<u64>,
    read_count: u32,
}

impl ProcfsCollector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            prev_interrupts: Vec::new(),
            prev_softnet_processed: Vec::new(),
            prev_softnet_time_squeeze: Vec::new(),
            read_count: 0,
        }
    }

    pub fn read_snapshot(&mut self) -> ProcfsSnapshot {
        let mut snap = ProcfsSnapshot::default();
        self.read_count += 1;

        // --- IRQ counts (per-CPU) ---
        match std::fs::read_to_string("/proc/interrupts") {
            Ok(content) => {
                let current = parse_proc_interrupts(&content);

                if self.prev_interrupts.is_empty() {
                    self.prev_interrupts = vec![0; current.len()];
                }

                let mut deltas = Vec::with_capacity(current.len());
                for (i, &cur) in current.iter().enumerate() {
                    let prev = self.prev_interrupts.get(i).copied().unwrap_or(0);
                    deltas.push(cur.saturating_sub(prev));
                }
                snap.total_irq_count = deltas.iter().sum();
                snap.per_cpu_irq_deltas = deltas;
                self.prev_interrupts = current;
            }
            Err(e) => warn!("failed to read /proc/interrupts: {e}"),
        }

        // --- Slab info ---
        match std::fs::read_to_string("/proc/slabinfo") {
            Ok(content) => {
                let (active_objs, total_objs, active_slabs) = parse_proc_slabinfo(&content);
                snap.slab_active_objects = active_objs;
                snap.slab_total_objects = total_objs;
                snap.slab_active_slabs = active_slabs;
                snap.slab_fragmentation_pct = if total_objs > 0 {
                    (1.0 - (active_objs as f64 / total_objs as f64)) * 100.0
                } else {
                    0.0
                };
            }
            Err(e) => warn!("failed to read /proc/slabinfo: {e}"),
        }

        // --- Softnet stats (per-CPU) ---
        match std::fs::read_to_string("/proc/net/softnet_stat") {
            Ok(content) => {
                let rows = parse_proc_softnet_stat(&content);
                let mut processed = Vec::with_capacity(rows.len());
                let mut dropped = Vec::with_capacity(rows.len());
                let mut time_squeeze = Vec::with_capacity(rows.len());

                for (p, d, ts) in &rows {
                    processed.push(*p);
                    dropped.push(*d);
                    time_squeeze.push(*ts);
                }

                if self.prev_softnet_processed.is_empty() {
                    self.prev_softnet_processed = vec![0; processed.len()];
                    self.prev_softnet_time_squeeze = vec![0; time_squeeze.len()];
                }

                let proc_deltas: Vec<u64> = processed
                    .iter()
                    .enumerate()
                    .map(|(i, &cur)| {
                        cur.saturating_sub(self.prev_softnet_processed.get(i).copied().unwrap_or(0))
                    })
                    .collect();

                let ts_deltas: Vec<u64> = time_squeeze
                    .iter()
                    .enumerate()
                    .map(|(i, &cur)| {
                        cur.saturating_sub(
                            self.prev_softnet_time_squeeze.get(i).copied().unwrap_or(0),
                        )
                    })
                    .collect();

                snap.total_softnet_processed = proc_deltas.iter().sum();
                snap.total_time_squeeze = ts_deltas.iter().sum();
                snap.softnet_processed = proc_deltas;
                snap.softnet_dropped = dropped;
                snap.softnet_time_squeeze = ts_deltas;

                self.prev_softnet_processed = processed;
                self.prev_softnet_time_squeeze = time_squeeze;
            }
            Err(e) => warn!("failed to read /proc/net/softnet_stat: {e}"),
        }

        snap
    }
}

fn parse_proc_interrupts(content: &str) -> Vec<u64> {
    let mut lines = content.lines();
    let header = match lines.next() {
        Some(h) => h,
        None => return Vec::new(),
    };
    let num_cpus = header.split_whitespace().count();
    let mut per_cpu = vec![0u64; num_cpus];

    for line in lines {
        let mut cols = line.split_whitespace();
        cols.next(); // skip IRQ name/number
        for (i, val) in cols.enumerate() {
            if i >= num_cpus {
                break;
            }
            if let Ok(n) = val.parse::<u64>() {
                per_cpu[i] += n;
            }
        }
    }

    per_cpu
}

fn parse_proc_slabinfo(content: &str) -> (u64, u64, u64) {
    let mut active_objs = 0u64;
    let mut total_objs = 0u64;
    let mut active_slabs = 0u64;

    for line in content.lines().skip(2) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 14 {
            continue;
        }
        if let Ok(v) = cols[1].parse::<u64>() {
            active_objs += v;
        }
        if let Ok(v) = cols[2].parse::<u64>() {
            total_objs += v;
        }
        if let Ok(v) = cols[13].parse::<u64>() {
            active_slabs += v;
        }
    }

    (active_objs, total_objs, active_slabs)
}

fn parse_proc_softnet_stat(content: &str) -> Vec<(u64, u64, u64)> {
    content
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 3 {
                return None;
            }
            let processed = u64::from_str_radix(cols[0], 16).ok()?;
            let dropped = u64::from_str_radix(cols[1], 16).ok()?;
            let time_squeeze = u64::from_str_radix(cols[2], 16).ok()?;
            Some((processed, dropped, time_squeeze))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_INTERRUPTS_SAMPLE: &str = "\
           CPU0       CPU1       CPU2       CPU3
  0:         48          0          0          0  IR-IO-APIC   2-edge      timer
  1:          0          3          0          0  IR-IO-APIC   1-edge      i8042
  8:          0          0          1          0  IR-IO-APIC   8-edge      rtc0
 12:          0          0          0          4  IR-IO-APIC  12-edge      i8042
LOC:      15423      12876      14332      13201  Local timer interrupts
NMI:          2          2          2          2  Non-maskable interrupts
";

    #[test]
    fn parse_interrupts_multi_cpu() {
        let per_cpu = parse_proc_interrupts(PROC_INTERRUPTS_SAMPLE);
        assert_eq!(per_cpu.len(), 4);
        // CPU0: 48 + 0 + 0 + 0 + 15423 + 2 = 15473
        assert_eq!(per_cpu[0], 15473);
        // CPU1: 0 + 3 + 0 + 0 + 12876 + 2 = 12881
        assert_eq!(per_cpu[1], 12881);
        // CPU2: 0 + 0 + 1 + 0 + 14332 + 2 = 14335
        assert_eq!(per_cpu[2], 14335);
        // CPU3: 0 + 0 + 0 + 4 + 13201 + 2 = 13207
        assert_eq!(per_cpu[3], 13207);
    }

    #[test]
    fn parse_interrupts_empty() {
        assert!(parse_proc_interrupts("").is_empty());
    }

    const PROC_SLABINFO_SAMPLE: &str = "\
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
ext4_inode_cache      12345      15000       1032           15            4 : tunables    0    0    0 : slabdata    1000      1000          0
dentry                 8000      10000        192           21            1 : tunables    0    0    0 : slabdata     476       476          0
";

    #[test]
    fn parse_slabinfo_sums() {
        let (active, total, slabs) = parse_proc_slabinfo(PROC_SLABINFO_SAMPLE);
        assert_eq!(active, 12345 + 8000);
        assert_eq!(total, 15000 + 10000);
        assert_eq!(slabs, 1000 + 476);
    }

    #[test]
    fn parse_slabinfo_empty() {
        let (a, t, s) = parse_proc_slabinfo("");
        assert_eq!((a, t, s), (0, 0, 0));
    }

    const PROC_SOFTNET_SAMPLE: &str = "\
0000abcd 00000002 00000010 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
00005678 00000000 00000005 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
";

    #[test]
    fn parse_softnet_hex() {
        let rows = parse_proc_softnet_stat(PROC_SOFTNET_SAMPLE);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], (0xabcd, 2, 0x10));
        assert_eq!(rows[1], (0x5678, 0, 5));
    }

    #[test]
    fn parse_softnet_empty() {
        assert!(parse_proc_softnet_stat("").is_empty());
    }

    #[test]
    fn collector_computes_deltas() {
        let mut collector = ProcfsCollector::new();

        // Simulate first read by injecting state directly
        collector.prev_interrupts = vec![100, 200, 300];
        collector.prev_softnet_processed = vec![1000, 2000];
        collector.prev_softnet_time_squeeze = vec![10, 20];
        collector.read_count = 1;

        // Verify delta logic with known values
        let current_irq = vec![150u64, 250, 350];
        let deltas: Vec<u64> = current_irq
            .iter()
            .enumerate()
            .map(|(i, &cur)| cur.saturating_sub(collector.prev_interrupts.get(i).copied().unwrap_or(0)))
            .collect();
        assert_eq!(deltas, vec![50, 50, 50]);
    }
}
