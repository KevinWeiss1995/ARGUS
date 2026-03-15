#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod slab;
mod interrupts;

use aya_ebpf::{
    macros::map,
    maps::{Array, PerCpuArray},
};

/// Tracepoint field offsets, populated by userspace before probes are attached.
/// Zero means "not configured" — probes skip events when their offsets are zero.
///
/// Index assignments (must match argus-agent/src/sources/tracepoint_format.rs):
///   0 = irq/irq_handler_entry → "irq" field
///   1 = napi/napi_poll → "work" field
///   2 = napi/napi_poll → "budget" field
///   3 = kmem/kmem_cache_alloc → "bytes_req" field
///   4 = kmem/kmem_cache_alloc → "bytes_alloc" field
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
