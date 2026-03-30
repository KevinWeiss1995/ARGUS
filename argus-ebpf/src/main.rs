#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod interrupts;
mod rdma_jitter;
mod slab;

use aya_ebpf::{
    macros::map,
    maps::{Array, LruHashMap, PerCpuArray},
};

/// Field offsets, populated by userspace before probes are attached.
/// Zero means "not configured" — probes skip events when their offsets are zero.
///
/// Index assignments (must match argus-agent/src/sources/tracepoint_format.rs):
///   0 = irq/irq_handler_entry → "irq" field
///   1 = napi/napi_poll → "work" field
///   2 = napi/napi_poll → "budget" field
///   3 = kmem/kmem_cache_alloc → "bytes_req" field
///   4 = kmem/kmem_cache_alloc → "bytes_alloc" field
///   5 = struct ib_qp → "qp_num" field (byte offset, from BTF)
///   6 = struct ib_wc → "qp" pointer field (byte offset, from BTF)
#[map]
static OFFSETS: Array<u32> = Array::with_max_entries(8, 0);

/// Per-CPU IRQ event count. Userspace sums across CPUs for per-CPU distribution.
/// Single entry (index 0): each CPU increments its own counter.
#[map]
static IRQ_COUNTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU slab allocation statistics.
/// Layout: [alloc_count, free_count, total_bytes_req, total_bytes_alloc]
#[map]
static SLAB_STATS: PerCpuArray<[u64; 4]> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU NAPI poll statistics.
/// Layout: [poll_count, total_work, total_budget]
#[map]
static NAPI_STATS: PerCpuArray<[u64; 3]> = PerCpuArray::with_max_entries(1, 0);

// ---------------------------------------------------------------------------
// RDMA CQ Jitter maps (Phase 1: micro-stall detection)
// ---------------------------------------------------------------------------

/// Work Request submit timestamps keyed by QP number.
/// LRU eviction prevents unbounded growth under heavy QP load.
#[map]
static WR_TIMESTAMPS: LruHashMap<u64, u64> = LruHashMap::with_max_entries(4096, 0);

/// Per-CPU CQ completion latency stats.
/// Layout: [completion_count, total_latency_ns, max_latency_ns, stall_count(>50us)]
#[map]
static CQ_JITTER_STATS: PerCpuArray<[u64; 4]> = PerCpuArray::with_max_entries(1, 0);

/// QP number → PID mapping for blast radius attribution.
/// Updated on every work request submit with the calling process's TGID.
#[map]
static QP_OWNERS: LruHashMap<u32, u32> = LruHashMap::with_max_entries(4096, 0);

/// Scratch space for CQ poll entry→return correlation.
/// Key = pid_tgid (identifies the thread calling poll_cq).
/// Value = wc pointer (saved at function entry, read at function return).
#[map]
static CQ_POLL_SCRATCH: LruHashMap<u64, u64> = LruHashMap::with_max_entries(256, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
