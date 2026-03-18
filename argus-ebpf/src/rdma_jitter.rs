use aya_ebpf::{macros::kprobe, programs::ProbeContext};

use super::{CQ_JITTER_STATS, QP_OWNERS, WR_TIMESTAMPS};

/// Kprobe on mlx5_ib_post_send (or rxe_post_send for Soft-RoCE).
/// Captures submit timestamp per QP for later delta computation in the CQ poll probe.
/// Also records QP → PID mapping for blast radius attribution.
#[kprobe]
pub fn kprobe_wr_submit(ctx: ProbeContext) -> u32 {
    match try_kprobe_wr_submit(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_kprobe_wr_submit(ctx: &ProbeContext) -> Result<u32, i64> {
    let qp_num: u32 = match ctx.arg(1) {
        Some(qp) => qp,
        None => return Ok(0),
    };

    let ts = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let key = qp_num as u64;

    let _ = WR_TIMESTAMPS.insert(&key, &ts, 0);

    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = QP_OWNERS.insert(&qp_num, &pid, 0);

    Ok(0)
}

/// Kprobe on mlx5_ib_poll_cq (or rxe_poll_cq for Soft-RoCE).
/// Reads the QP number, looks up submit timestamp, and computes latency delta.
/// Increments histogram buckets and jitter stats in PerCpuArray.
#[kprobe]
pub fn kprobe_cq_poll(ctx: ProbeContext) -> u32 {
    match try_kprobe_cq_poll(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_kprobe_cq_poll(ctx: &ProbeContext) -> Result<u32, i64> {
    let qp_num: u32 = match ctx.arg(1) {
        Some(qp) => qp,
        None => return Ok(0),
    };

    let key = qp_num as u64;
    let submit_ts = match unsafe { WR_TIMESTAMPS.get(&key) } {
        Some(ts) => *ts,
        None => return Ok(0),
    };

    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let delta_ns = now.saturating_sub(submit_ts);

    // SAFETY: PerCpuArray lookup at index 0, pointer valid for this CPU's slot.
    // Layout: [count, total_ns, max_ns, stall_count(>50us)]
    if let Some(stats) = CQ_JITTER_STATS.get_ptr_mut(0) {
        unsafe {
            (*stats)[0] += 1;
            (*stats)[1] += delta_ns;
            if delta_ns > (*stats)[2] {
                (*stats)[2] = delta_ns;
            }
            if delta_ns > 50_000 {
                (*stats)[3] += 1;
            }
        }
    }

    Ok(0)
}
