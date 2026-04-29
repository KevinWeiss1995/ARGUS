use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, kretprobe, tracepoint},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};

use super::{OFFSETS, SLAB_ALLOC_SCRATCH, SLAB_STATS};

// ---------------------------------------------------------------------------
// Tracepoint: kmem/kmem_cache_alloc — byte accounting (lightweight)
// ---------------------------------------------------------------------------

/// Fires when the kernel completes a slab allocation. Records allocation counts
/// and byte sizes. This tracepoint cannot measure latency because it fires once
/// (post-completion only), so latency is handled by the kprobe/kretprobe pair.
#[tracepoint(category = "kmem", name = "kmem_cache_alloc")]
pub fn trace_kmem_cache_alloc(ctx: TracePointContext) -> u32 {
    match try_trace_kmem_cache_alloc(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_kmem_cache_alloc(ctx: &TracePointContext) -> Result<u32, i64> {
    let bytes_req_offset = match OFFSETS.get(3) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };
    let bytes_alloc_offset = match OFFSETS.get(4) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };

    if bytes_req_offset > 256 || bytes_alloc_offset > 256 {
        return Ok(0);
    }

    let bytes_req: u64 = unsafe { ctx.read_at(bytes_req_offset).unwrap_or(0) };
    let bytes_alloc: u64 = unsafe { ctx.read_at(bytes_alloc_offset).unwrap_or(0) };

    // Layout: [alloc_count, free_count, total_bytes_req, total_bytes_alloc,
    //          total_latency_ns, max_latency_ns]
    if let Some(stats) = SLAB_STATS.get_ptr_mut(0) {
        unsafe {
            (*stats)[0] += 1;
            (*stats)[2] += bytes_req;
            (*stats)[3] += bytes_alloc;
        }
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
    if let Some(stats) = SLAB_STATS.get_ptr_mut(0) {
        unsafe {
            (*stats)[1] += 1;
        }
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// Kprobe/kretprobe pair on kmem_cache_alloc — latency measurement
// ---------------------------------------------------------------------------

/// Entry kprobe on `kmem_cache_alloc`. Records ktime_ns into scratch map
/// keyed by pid_tgid so the kretprobe can compute the elapsed time.
#[kprobe]
pub fn kprobe_slab_alloc_entry(ctx: ProbeContext) -> u32 {
    match try_kprobe_slab_alloc_entry(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_kprobe_slab_alloc_entry(_ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = SLAB_ALLOC_SCRATCH.insert(&pid_tgid, &ts, 0);
    Ok(0)
}

/// Return kretprobe on `kmem_cache_alloc`. Computes latency delta from the
/// entry timestamp and accumulates into SLAB_STATS[4] (total_latency_ns)
/// and SLAB_STATS[5] (max_latency_ns).
#[kretprobe]
pub fn kretprobe_slab_alloc(ctx: RetProbeContext) -> u32 {
    match try_kretprobe_slab_alloc(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_kretprobe_slab_alloc(_ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let entry_ts = match unsafe { SLAB_ALLOC_SCRATCH.get(&pid_tgid) } {
        Some(&ts) => ts,
        None => return Ok(0),
    };

    let _ = SLAB_ALLOC_SCRATCH.remove(&pid_tgid);

    let now = unsafe { bpf_ktime_get_ns() };
    let delta_ns = now.saturating_sub(entry_ts);

    // Layout: [alloc_count, free_count, total_bytes_req, total_bytes_alloc,
    //          total_latency_ns, max_latency_ns]
    if let Some(stats) = SLAB_STATS.get_ptr_mut(0) {
        unsafe {
            (*stats)[4] += delta_ns;
            if delta_ns > (*stats)[5] {
                (*stats)[5] = delta_ns;
            }
        }
    }

    Ok(0)
}
