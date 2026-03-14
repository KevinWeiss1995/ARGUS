#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod slab;
mod interrupts;

use aya_ebpf::{
    macros::map,
    maps::{Array, RingBuf},
};

/// Shared ring buffer for all event types. Userspace reads events tagged by type.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
