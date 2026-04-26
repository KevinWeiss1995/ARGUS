use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};

use super::{OFFSETS, SLAB_STATS};

/// Tracepoint: kmem/kmem_cache_alloc
/// Fires when the kernel allocates from a slab cache. Accumulates in BPF map.
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

    // The kmem_cache_alloc tracepoint declares bytes_req/bytes_alloc as size_t
    // (8 bytes on 64-bit kernels). Reading only the low u32 silently truncates
    // allocations ≥ 4 GiB and is endian-dependent; read the full u64.
    // SAFETY: offsets discovered from tracefs format file, populated by userspace.
    let bytes_req: u64 = unsafe { ctx.read_at(bytes_req_offset).unwrap_or(0) };
    let bytes_alloc: u64 = unsafe { ctx.read_at(bytes_alloc_offset).unwrap_or(0) };

    // SAFETY: PerCpuArray lookup at index 0, pointer valid for this CPU's slot.
    // Layout: [alloc_count, free_count, total_bytes_req, total_bytes_alloc]
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
/// Fires when the kernel frees to a slab cache. Increments free count in BPF map.
#[tracepoint(category = "kmem", name = "kmem_cache_free")]
pub fn trace_kmem_cache_free(ctx: TracePointContext) -> u32 {
    match try_trace_kmem_cache_free(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_trace_kmem_cache_free(_ctx: &TracePointContext) -> Result<u32, i64> {
    // SAFETY: PerCpuArray lookup at index 0, pointer valid for this CPU's slot.
    if let Some(stats) = SLAB_STATS.get_ptr_mut(0) {
        unsafe {
            (*stats)[1] += 1;
        }
    }

    Ok(0)
}
