use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::tracepoint,
    programs::TracePointContext,
};

use super::EVENTS;

#[repr(C)]
struct IrqEntryRingEvent {
    event_type: u32,
    _pad: u32,
    timestamp_ns: u64,
    cpu: u32,
    irq: u32,
}

#[repr(C)]
struct NapiPollRingEvent {
    event_type: u32,
    _pad: u32,
    timestamp_ns: u64,
    cpu: u32,
    budget: u32,
    work_done: u32,
    _pad2: u32,
}

/// Tracepoint: irq/irq_handler_entry
/// Fires on every hardware interrupt.
#[tracepoint]
pub fn trace_irq_handler_entry(ctx: TracePointContext) -> u32 {
    match try_trace_irq_entry(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_irq_entry(ctx: &TracePointContext) -> Result<u32, i64> {
    let ts = unsafe { bpf_ktime_get_ns() };
    let cpu = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };
    let irq: u32 = unsafe { ctx.read_at(8)? };

    if let Some(mut entry) = EVENTS.reserve::<IrqEntryRingEvent>(0) {
        let event = IrqEntryRingEvent {
            event_type: 3,
            _pad: 0,
            timestamp_ns: ts,
            cpu,
            irq,
        };
        unsafe {
            core::ptr::write_unaligned(entry.as_mut_ptr().cast(), event);
        }
        entry.submit(0);
    }

    Ok(0)
}

/// Tracepoint: napi/napi_poll
/// Fires when NAPI polling processes network packets.
#[tracepoint]
pub fn trace_napi_poll(ctx: TracePointContext) -> u32 {
    match try_trace_napi_poll(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_napi_poll(ctx: &TracePointContext) -> Result<u32, i64> {
    let ts = unsafe { bpf_ktime_get_ns() };
    let cpu = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };
    let budget: u32 = unsafe { ctx.read_at(8)? };
    let work_done: u32 = unsafe { ctx.read_at(12)? };

    if let Some(mut entry) = EVENTS.reserve::<NapiPollRingEvent>(0) {
        let event = NapiPollRingEvent {
            event_type: 4,
            _pad: 0,
            timestamp_ns: ts,
            cpu,
            budget,
            work_done,
            _pad2: 0,
        };
        unsafe {
            core::ptr::write_unaligned(entry.as_mut_ptr().cast(), event);
        }
        entry.submit(0);
    }

    Ok(0)
}
