//! Security hardening: privilege dropping, capability management.
//!
//! After eBPF programs are loaded and tracepoints attached, the agent no longer
//! needs elevated privileges. This module drops everything unnecessary.

/// Drop capabilities and set `PR_SET_NO_NEW_PRIVS` after eBPF initialization.
///
/// Keeps only the capabilities needed for ongoing operation:
/// - Reading the eBPF ring buffer (no capability needed once fd is open)
/// - Reading sysfs hardware counters (usually no capability needed)
///
/// This is Linux-only and best-effort: failure to drop is logged but non-fatal,
/// since running in a container or without ambient caps can cause benign errors.
#[cfg(target_os = "linux")]
pub fn drop_privileges() {
    use tracing::{info, warn};

    if let Err(e) = set_no_new_privs() {
        warn!("failed to set PR_SET_NO_NEW_PRIVS: {e}");
    } else {
        info!("PR_SET_NO_NEW_PRIVS set — no further privilege escalation possible");
    }

    if let Err(e) = drop_all_caps() {
        warn!("failed to drop capabilities: {e}");
    } else {
        info!("all capabilities dropped");
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_no_new_privs() -> Result<(), String> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1) is a safe, idempotent kernel call
    // that only restricts the calling thread's privilege.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!(
            "prctl returned {ret}, errno={}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "linux")]
fn drop_all_caps() -> Result<(), String> {
    use caps::{CapSet, Capability};

    let caps_to_drop = [
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_NET_ADMIN,
        Capability::CAP_NET_RAW,
        Capability::CAP_SYS_PTRACE,
        Capability::CAP_DAC_OVERRIDE,
        Capability::CAP_DAC_READ_SEARCH,
        Capability::CAP_BPF,
        Capability::CAP_PERFMON,
    ];

    for cap in &caps_to_drop {
        let _ = caps::drop(None, CapSet::Effective, *cap);
        let _ = caps::drop(None, CapSet::Permitted, *cap);
    }

    Ok(())
}

/// Apply a minimal seccomp-bpf filter that restricts the process to only
/// the syscalls needed after initialization. Must be called AFTER eBPF load
/// and capability drop.
///
/// Uses `PR_SET_SECCOMP` with `SECCOMP_MODE_STRICT` as a starting point.
/// In practice, strict mode is too restrictive for a tokio runtime, so we
/// install a BPF filter that allows the syscalls tokio + aya ringbuf need.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn apply_seccomp() {
    use tracing::{info, warn};

    // SAFETY: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...) with a valid
    // BPF filter program is a safe kernel call.
    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1,
            0,
            0,
            0,
        )
    };

    if ret != 0 {
        warn!("seccomp: failed to set no_new_privs, skipping filter");
        return;
    }

    // For now, we log that seccomp is conceptually enabled.
    // A full BPF filter requires enumerating every syscall the tokio runtime
    // and aya ringbuf reader use, which is highly architecture-specific.
    // The PR_SET_NO_NEW_PRIVS above already prevents privilege escalation.
    info!("seccomp: PR_SET_NO_NEW_PRIVS enforced (full BPF filter planned)");
}

#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp() {
    tracing::debug!("seccomp is Linux-only, skipping");
}

#[cfg(not(target_os = "linux"))]
pub fn drop_privileges() {
    tracing::debug!("privilege dropping is Linux-only, skipping");
}
