use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::tracepoint,
    programs::TracePointContext,
};

use super::EVENTS;

/// Type tag 1 = SlabAlloc, 2 = SlabFree
#[repr(C)]
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
struct SlabFreeRingEvent {
    event_type: u32,
    _pad: u32,
    timestamp_ns: u64,
    cpu: u32,
    bytes_freed: u32,
}

/// Tracepoint: kmem/kmem_cache_alloc
/// Fires when the kernel allocates from a slab cache.
#[tracepoint(category = "kmem", name = "kmem_cache_alloc")]
pub fn trace_kmem_cache_alloc(ctx: TracePointContext) -> u32 {
    match try_trace_kmem_cache_alloc(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_kmem_cache_alloc(ctx: &TracePointContext) -> Result<u32, i64> {
    let ts = unsafe { bpf_ktime_get_ns() };
    let cpu = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };

    let bytes_req: u32 = unsafe { ctx.read_at(16).unwrap_or(0) };
    let bytes_alloc: u32 = unsafe { ctx.read_at(20).unwrap_or(0) };

    if let Some(mut entry) = EVENTS.reserve::<SlabAllocRingEvent>(0) {
        let event = SlabAllocRingEvent {
            event_type: 1,
            _pad: 0,
            timestamp_ns: ts,
            cpu,
            bytes_req,
            bytes_alloc,
            _pad2: 0,
            latency_ns: 0,
        };
        unsafe {
            core::ptr::write_unaligned(entry.as_mut_ptr().cast(), event);
        }
        entry.submit(0);
    }

    Ok(0)
}

/// Tracepoint: kmem/kmem_cache_free
#[tracepoint(category = "kmem", name = "kmem_cache_free")]
pub fn trace_kmem_cache_free(ctx: TracePointContext) -> u32 {
    match try_trace_kmem_cache_free(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_kmem_cache_free(_ctx: &TracePointContext) -> Result<u32, i64> {
    let ts = unsafe { bpf_ktime_get_ns() };
    let cpu = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };

    if let Some(mut entry) = EVENTS.reserve::<SlabFreeRingEvent>(0) {
        let event = SlabFreeRingEvent {
            event_type: 2,
            _pad: 0,
            timestamp_ns: ts,
            cpu,
            bytes_freed: 0,
        };
        unsafe {
            core::ptr::write_unaligned(entry.as_mut_ptr().cast(), event);
        }
        entry.submit(0);
    }

    Ok(0)
}
