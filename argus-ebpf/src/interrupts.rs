use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::tracepoint,
    programs::TracePointContext,
};

use super::{EVENTS, OFFSETS};

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
#[tracepoint(category = "irq", name = "irq_handler_entry")]
pub fn trace_irq_handler_entry(ctx: TracePointContext) -> u32 {
    match try_trace_irq_entry(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_irq_entry(ctx: &TracePointContext) -> Result<u32, i64> {
    // SAFETY: bpf_ktime_get_ns reads the kernel monotonic clock, always safe.
    let ts = unsafe { bpf_ktime_get_ns() };
    // SAFETY: bpf_get_smp_processor_id returns current CPU, always safe.
    let cpu = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };

    let irq_offset = match OFFSETS.get(0) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };
    // SAFETY: offset discovered from tracefs format file, populated by userspace.
    let irq: u32 = unsafe { ctx.read_at(irq_offset).unwrap_or(0) };

    if let Some(mut entry) = EVENTS.reserve::<IrqEntryRingEvent>(0) {
        let event = IrqEntryRingEvent {
            event_type: 3,
            _pad: 0,
            timestamp_ns: ts,
            cpu,
            irq,
        };
        // SAFETY: ring buffer slot is reserved for IrqEntryRingEvent size.
        unsafe {
            core::ptr::write_unaligned(entry.as_mut_ptr().cast(), event);
        }
        entry.submit(0);
    }

    Ok(0)
}

/// Tracepoint: napi/napi_poll
/// Fires when NAPI polling processes network packets.
#[tracepoint(category = "napi", name = "napi_poll")]
pub fn trace_napi_poll(ctx: TracePointContext) -> u32 {
    match try_trace_napi_poll(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_napi_poll(ctx: &TracePointContext) -> Result<u32, i64> {
    // SAFETY: see try_trace_irq_entry above.
    let ts = unsafe { bpf_ktime_get_ns() };
    let cpu = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };

    let work_offset = match OFFSETS.get(1) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };
    let budget_offset = match OFFSETS.get(2) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };

    // SAFETY: offsets discovered from tracefs format file, populated by userspace.
    let budget: u32 = unsafe { ctx.read_at(budget_offset).unwrap_or(0) };
    let work_done: u32 = unsafe { ctx.read_at(work_offset).unwrap_or(0) };

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
        // SAFETY: ring buffer slot is reserved for NapiPollRingEvent size.
        unsafe {
            core::ptr::write_unaligned(entry.as_mut_ptr().cast(), event);
        }
        entry.submit(0);
    }

    Ok(0)
}
