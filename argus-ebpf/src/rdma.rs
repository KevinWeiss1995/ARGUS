use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::tracepoint,
    programs::TracePointContext,
};

use super::EVENTS;

#[repr(C)]
struct CqCompletionRingEvent {
    event_type: u32,
    _pad: u32,
    timestamp_ns: u64,
    cpu: u32,
    queue_pair_num: u32,
    latency_ns: u64,
    is_error: u32,
    opcode: u32,
}

/// Tracepoint: ib/ib_cq_poll
/// Fires on InfiniBand completion queue polling (when available).
/// Falls back to mlx5-specific tracepoints on Mellanox hardware.
#[tracepoint(category = "ib", name = "ib_cq_poll")]
pub fn trace_cq_completion(ctx: TracePointContext) -> u32 {
    match try_trace_cq(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_cq(ctx: &TracePointContext) -> Result<u32, i64> {
    let ts = unsafe { bpf_ktime_get_ns() };
    let cpu = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };

    // Read tracepoint fields - offsets are kernel-version dependent.
    // These are typical for RDMA CQ completion tracepoints.
    let qp_num: u32 = unsafe { ctx.read_at(8).unwrap_or(0) };
    let opcode: u32 = unsafe { ctx.read_at(12).unwrap_or(0) };
    let status: u32 = unsafe { ctx.read_at(16).unwrap_or(0) };

    if let Some(mut entry) = EVENTS.reserve::<CqCompletionRingEvent>(0) {
        let event = CqCompletionRingEvent {
            event_type: 6,
            _pad: 0,
            timestamp_ns: ts,
            cpu,
            queue_pair_num: qp_num,
            latency_ns: 0, // Latency computed in userspace via start/end tracking
            is_error: if status != 0 { 1 } else { 0 },
            opcode,
        };
        unsafe {
            core::ptr::write_unaligned(entry.as_mut_ptr().cast(), event);
        }
        entry.submit(0);
    }

    Ok(0)
}
