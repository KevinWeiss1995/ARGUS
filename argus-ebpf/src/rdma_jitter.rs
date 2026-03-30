use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel};
use aya_ebpf::macros::{kprobe, kretprobe};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};

use super::{CQ_JITTER_STATS, CQ_POLL_SCRATCH, OFFSETS, QP_OWNERS, WR_TIMESTAMPS};

/// OFFSETS map indices — must match tracepoint_format.rs constants.
const OFF_IB_QP_QP_NUM: u32 = 5;
const OFF_IB_WC_QP: u32 = 6;

// ---------------------------------------------------------------------------
// Work Request submission kprobe
// ---------------------------------------------------------------------------

/// Kprobe on `mlx5_ib_post_send(struct ib_qp *ibqp, ...)` or the rxe equivalent.
/// Reads `ibqp->qp_num` via `bpf_probe_read_kernel` at a BTF-discovered offset,
/// stores `(qp_num, timestamp)` for later delta computation, and records QP→PID.
#[kprobe]
pub fn kprobe_wr_submit(ctx: ProbeContext) -> u32 {
    match try_kprobe_wr_submit(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_kprobe_wr_submit(ctx: &ProbeContext) -> Result<u32, i64> {
    let ibqp_ptr: *const u8 = match ctx.arg(0) {
        Some(ptr) => ptr,
        None => return Ok(0),
    };

    let qp_num_offset = match OFFSETS.get(OFF_IB_QP_QP_NUM) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };

    let qp_num: u32 = unsafe {
        bpf_probe_read_kernel(ibqp_ptr.add(qp_num_offset) as *const u32).map_err(|e| e as i64)?
    };

    if qp_num == 0 {
        return Ok(0);
    }

    let ts = unsafe { bpf_ktime_get_ns() };
    let key = qp_num as u64;
    let _ = WR_TIMESTAMPS.insert(&key, &ts, 0);

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = QP_OWNERS.insert(&qp_num, &pid, 0);

    Ok(0)
}

// ---------------------------------------------------------------------------
// CQ poll: entry kprobe (saves wc pointer) + kretprobe (reads completions)
// ---------------------------------------------------------------------------

/// Entry kprobe on `mlx5_ib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)`.
/// Saves the `wc` pointer (arg 2) into the scratch map keyed by pid_tgid so the
/// kretprobe can read it after the function fills the wc array.
#[kprobe]
pub fn kprobe_cq_poll_entry(ctx: ProbeContext) -> u32 {
    match try_kprobe_cq_poll_entry(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_kprobe_cq_poll_entry(ctx: &ProbeContext) -> Result<u32, i64> {
    let wc_ptr: u64 = match ctx.arg::<u64>(2) {
        Some(ptr) => ptr,
        None => return Ok(0),
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = CQ_POLL_SCRATCH.insert(&pid_tgid, &wc_ptr, 0);
    Ok(0)
}

/// Kretprobe on `mlx5_ib_poll_cq` / `rxe_poll_cq`.
/// Fires after poll_cq returns. The return value is the number of completions
/// polled (or negative on error). We retrieve the saved `wc` pointer from
/// CQ_POLL_SCRATCH, then read `wc[i].qp` → `qp->qp_num` for each completion
/// to correlate with submit timestamps.
#[kretprobe]
pub fn kretprobe_cq_poll(ctx: RetProbeContext) -> u32 {
    match try_kretprobe_cq_poll(&ctx) {
        Ok(0) => 0,
        _ => 1,
    }
}

fn try_kretprobe_cq_poll(ctx: &RetProbeContext) -> Result<u32, i64> {
    let num_completions: i32 = match ctx.ret() {
        Some(n) => n,
        None => return Ok(0),
    };

    if num_completions <= 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let wc_base = match unsafe { CQ_POLL_SCRATCH.get(&pid_tgid) } {
        Some(&ptr) => ptr as *const u8,
        None => return Ok(0),
    };

    // Clean up scratch entry
    let _ = CQ_POLL_SCRATCH.remove(&pid_tgid);

    let wc_qp_offset = match OFFSETS.get(OFF_IB_WC_QP) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };

    let qp_num_offset = match OFFSETS.get(OFF_IB_QP_QP_NUM) {
        Some(&off) if off > 0 => off as usize,
        _ => return Ok(0),
    };

    let now = unsafe { bpf_ktime_get_ns() };

    // struct ib_wc is typically 72 bytes on 64-bit kernels. We use a conservative
    // estimate of 80 for safety. Cap iteration at 8 entries (verifier-friendly).
    const WC_STRIDE: usize = 80;
    const MAX_ENTRIES: usize = 8;

    let n = if (num_completions as usize) < MAX_ENTRIES {
        num_completions as usize
    } else {
        MAX_ENTRIES
    };

    let mut i: usize = 0;
    // Bounded loop for verifier
    while i < MAX_ENTRIES {
        if i >= n {
            break;
        }

        let wc_ptr = unsafe { wc_base.add(i * WC_STRIDE) };

        // Read wc[i].qp (struct ib_qp pointer) at wc_qp_offset
        let qp_ptr: *const u8 = match unsafe {
            bpf_probe_read_kernel(wc_ptr.add(wc_qp_offset) as *const *const u8)
        } {
            Ok(ptr) => ptr,
            Err(_) => {
                i += 1;
                continue;
            }
        };

        if qp_ptr.is_null() {
            i += 1;
            continue;
        }

        // Read qp->qp_num (u32)
        let qp_num: u32 =
            match unsafe { bpf_probe_read_kernel(qp_ptr.add(qp_num_offset) as *const u32) } {
                Ok(n) => n,
                Err(_) => {
                    i += 1;
                    continue;
                }
            };

        if qp_num == 0 {
            i += 1;
            continue;
        }

        let key = qp_num as u64;
        if let Some(&submit_ts) = unsafe { WR_TIMESTAMPS.get(&key) } {
            let delta_ns = now.saturating_sub(submit_ts);

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
        }

        i += 1;
    }

    Ok(0)
}
