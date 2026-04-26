//! Security hardening: privilege dropping, capability management.
//!
//! After eBPF programs are loaded and tracepoints attached, the agent no longer
//! needs elevated privileges. This module drops everything unnecessary.

/// Drop capabilities and set `PR_SET_NO_NEW_PRIVS` after eBPF initialization.
///
/// Keeps only the capabilities needed for ongoing operation:
/// - `CAP_BPF`: required for `bpf(BPF_MAP_LOOKUP_ELEM)` on kernels < 5.19
/// - Reading sysfs hardware counters (no capability needed)
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

    match drop_all_caps() {
        Ok(dropped) => {
            info!(count = dropped, "capabilities dropped");
        }
        Err(errors) => {
            for err in &errors {
                warn!("capability drop error: {err}");
            }
            warn!(
                "dropped some capabilities but {} errors occurred — process may retain \
                 more privilege than intended",
                errors.len()
            );
        }
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
fn drop_all_caps() -> Result<usize, Vec<String>> {
    use caps::{CapSet, Capability};

    // CAP_BPF is retained: per-CPU BPF map reads use the bpf() syscall which
    // requires CAP_BPF on kernels < 5.19. The map FDs are already open, but
    // BPF_MAP_LOOKUP_ELEM still checks capabilities on older kernels.
    let caps_to_drop = [
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_NET_ADMIN,
        Capability::CAP_NET_RAW,
        Capability::CAP_SYS_PTRACE,
        Capability::CAP_DAC_OVERRIDE,
        Capability::CAP_DAC_READ_SEARCH,
        Capability::CAP_PERFMON,
    ];

    let mut dropped = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for cap in &caps_to_drop {
        // Not holding the cap is not an error — `caps::has_cap` returns false
        // and we skip. Only real drop failures are reported.
        let mut any_success = false;
        for set in [CapSet::Effective, CapSet::Permitted] {
            match caps::has_cap(None, set, *cap) {
                Ok(false) => continue,
                Ok(true) => match caps::drop(None, set, *cap) {
                    Ok(()) => any_success = true,
                    Err(e) => errors.push(format!("drop {cap:?} from {set:?}: {e}")),
                },
                Err(e) => errors.push(format!("has_cap {cap:?} in {set:?}: {e}")),
            }
        }
        if any_success {
            dropped += 1;
        }
    }

    if errors.is_empty() {
        Ok(dropped)
    } else {
        Err(errors)
    }
}

/// Harden against privilege escalation. NOTE: this does NOT install a seccomp
/// BPF syscall filter — the name is kept for CLI/API stability. A real filter
/// requires enumerating every syscall the tokio runtime, aya, and libc use,
/// which is architecture- and kernel-version-specific and has not been
/// implemented. Today this only ensures `PR_SET_NO_NEW_PRIVS`, which
/// `drop_privileges` also sets; calling both is harmless and idempotent.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn apply_seccomp() {
    use tracing::{info, warn};

    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1) is an idempotent, thread-scoped
    // kernel call that only restricts the caller.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

    if ret != 0 {
        warn!(
            errno = %std::io::Error::last_os_error(),
            "seccomp: failed to set no_new_privs"
        );
        return;
    }

    info!(
        "seccomp flag: PR_SET_NO_NEW_PRIVS enforced — note that no BPF syscall \
         filter is installed yet; this only blocks setuid/file-caps escalation"
    );
}

#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp() {
    tracing::debug!("seccomp is Linux-only, skipping");
}

#[cfg(not(target_os = "linux"))]
pub fn drop_privileges() {
    tracing::debug!("privilege dropping is Linux-only, skipping");
}
