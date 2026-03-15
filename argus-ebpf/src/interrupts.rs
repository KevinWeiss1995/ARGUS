use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};

use super::{IRQ_COUNTS, NAPI_STATS, OFFSETS};

/// Tracepoint: irq/irq_handler_entry
/// Fires on every hardware interrupt. Increments per-CPU counter in BPF map.
#[tracepoint(category = "irq", name = "irq_handler_entry")]
pub fn trace_irq_handler_entry(ctx: TracePointContext) -> u32 {
    match try_trace_irq_entry(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_irq_entry(_ctx: &TracePointContext) -> Result<u32, i64> {
    let irq_offset = match OFFSETS.get(0) {
        Some(&off) if off > 0 => off,
        _ => return Ok(0),
    };
    // Validate offset is within a reasonable range for tracepoint args
    if irq_offset > 256 {
        return Ok(0);
    }

    // SAFETY: PerCpuArray lookup at index 0, pointer valid for this CPU's slot.
    if let Some(count) = IRQ_COUNTS.get_ptr_mut(0) {
        unsafe { *count += 1; }
    }

    Ok(0)
}

/// Tracepoint: napi/napi_poll
/// Fires when NAPI polling processes network packets. Accumulates in BPF map.
#[tracepoint(category = "napi", name = "napi_poll")]
pub fn trace_napi_poll(ctx: TracePointContext) -> u32 {
    match try_trace_napi_poll(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_napi_poll(ctx: &TracePointContext) -> Result<u32, i64> {
    let work_offset = match OFFSETS.get(1) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };
    let budget_offset = match OFFSETS.get(2) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };

    if work_offset > 256 || budget_offset > 256 {
        return Ok(0);
    }

    // SAFETY: offsets discovered from tracefs format file, populated by userspace.
    let work_done: u32 = unsafe { ctx.read_at(work_offset).unwrap_or(0) };
    let budget: u32 = unsafe { ctx.read_at(budget_offset).unwrap_or(0) };

    // SAFETY: PerCpuArray lookup at index 0, pointer valid for this CPU's slot.
    // Layout: [poll_count, total_work, total_budget]
    if let Some(stats) = NAPI_STATS.get_ptr_mut(0) {
        unsafe {
            (*stats)[0] += 1;
            (*stats)[1] += work_done as u64;
            (*stats)[2] += budget as u64;
        }
    }

    Ok(0)
}
