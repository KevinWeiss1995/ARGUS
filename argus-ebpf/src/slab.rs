use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

use super::EVENTS;

/// Per-CPU timestamp tracking for latency calculation.
/// Key: CPU ID, Value: start timestamp in nanoseconds.
#[map]
static ALLOC_START: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

/// Event header written to the ring buffer.
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
#[tracepoint]
pub fn trace_kmem_cache_alloc(ctx: TracePointContext) -> u32 {
    match try_trace_kmem_cache_alloc(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_kmem_cache_alloc(ctx: &TracePointContext) -> Result<u32, i64> {
    let ts = unsafe { bpf_ktime_get_ns() };
    let cpu = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };

    // Read tracepoint arguments.
    // kmem_cache_alloc format: bytes_req, bytes_alloc, ...
    // Offsets depend on kernel version; these are typical for 5.15+
    let bytes_req: u32 = unsafe { ctx.read_at(16)? };
    let bytes_alloc: u32 = unsafe { ctx.read_at(20)? };

    // Calculate latency if we recorded a start time for this CPU
    let latency_ns = match unsafe { ALLOC_START.get(&cpu) } {
        Some(&start) => ts.saturating_sub(start),
        None => 0,
    };

    // Write event to ring buffer
    if let Some(mut entry) = EVENTS.reserve::<SlabAllocRingEvent>(0) {
        let event = SlabAllocRingEvent {
            event_type: 1,
            _pad: 0,
            timestamp_ns: ts,
            cpu,
            bytes_req,
            bytes_alloc,
            _pad2: 0,
            latency_ns,
        };
        unsafe {
            core::ptr::write_unaligned(entry.as_mut_ptr().cast(), event);
        }
        entry.submit(0);
    }

    Ok(0)
}

/// Tracepoint: kmem/kmem_cache_free
#[tracepoint]
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
