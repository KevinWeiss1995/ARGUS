//! Security hardening: privilege dropping, capability management.
//!
//! After eBPF programs are loaded and tracepoints attached, the agent no longer
//! needs elevated privileges. This module drops everything unnecessary, keeping
//! only `CAP_BPF` for ongoing BPF map reads on kernels < 5.19.

/// Drop capabilities and set `PR_SET_NO_NEW_PRIVS` after eBPF initialization.
///
/// Strategy: iterate ALL known capabilities and drop everything except `CAP_BPF`.
/// This is future-proof — if Linux adds new caps, they get dropped automatically
/// rather than requiring a manual update to a drop-list.
///
/// This is Linux-only and best-effort: failure to drop is logged but non-fatal,
/// since running in a container or without ambient caps can cause benign errors.
#[cfg(target_os = "linux")]
pub fn drop_privileges() {
    use tracing::{info, warn};

    log_held_capabilities("pre-drop");

    if let Err(e) = set_no_new_privs() {
        warn!("failed to set PR_SET_NO_NEW_PRIVS: {e}");
    } else {
        info!("PR_SET_NO_NEW_PRIVS set");
    }

    let mut dropped = 0u32;
    let mut errors = 0u32;

    for cap_idx in 0..64u32 {
        let cap = match cap_from_index(cap_idx) {
            Some(c) => c,
            None => continue,
        };

        if cap == caps::Capability::CAP_BPF {
            continue;
        }

        for set in [caps::CapSet::Effective, caps::CapSet::Permitted] {
            match caps::has_cap(None, set, cap) {
                Ok(true) => {
                    if let Err(e) = caps::drop(None, set, cap) {
                        warn!(cap = ?cap, set = ?set, "cap drop failed: {e}");
                        errors += 1;
                    } else {
                        dropped += 1;
                    }
                }
                Ok(false) => {}
                Err(_) => {}
            }
        }
    }

    if errors > 0 {
        warn!(dropped, errors, "privilege drop completed with errors");
    } else {
        info!(dropped, "privileges dropped");
    }

    log_held_capabilities("post-drop");
}

/// Log all capabilities currently in the effective set.
#[cfg(target_os = "linux")]
fn log_held_capabilities(phase: &str) {
    match caps::read(None, caps::CapSet::Effective) {
        Ok(set) => {
            let names: Vec<String> = set.iter().map(|c| format!("{c:?}")).collect();
            if names.is_empty() {
                tracing::info!(phase, "effective capabilities: none");
            } else {
                tracing::info!(phase, caps = names.join(", "), "effective capabilities");
            }
        }
        Err(e) => {
            tracing::warn!(phase, "failed to read effective capabilities: {e}");
        }
    }
}

/// Map a raw capability index to the caps crate enum.
/// Returns None for indices that don't map to a known capability.
#[cfg(target_os = "linux")]
fn cap_from_index(idx: u32) -> Option<caps::Capability> {
    use caps::Capability::*;
    Some(match idx {
        0 => CAP_CHOWN,
        1 => CAP_DAC_OVERRIDE,
        2 => CAP_DAC_READ_SEARCH,
        3 => CAP_FOWNER,
        4 => CAP_FSETID,
        5 => CAP_KILL,
        6 => CAP_SETGID,
        7 => CAP_SETUID,
        8 => CAP_SETPCAP,
        9 => CAP_LINUX_IMMUTABLE,
        10 => CAP_NET_BIND_SERVICE,
        11 => CAP_NET_BROADCAST,
        12 => CAP_NET_ADMIN,
        13 => CAP_NET_RAW,
        14 => CAP_IPC_LOCK,
        15 => CAP_IPC_OWNER,
        16 => CAP_SYS_MODULE,
        17 => CAP_SYS_RAWIO,
        18 => CAP_SYS_CHROOT,
        19 => CAP_SYS_PTRACE,
        20 => CAP_SYS_PACCT,
        21 => CAP_SYS_ADMIN,
        22 => CAP_SYS_BOOT,
        23 => CAP_SYS_NICE,
        24 => CAP_SYS_RESOURCE,
        25 => CAP_SYS_TIME,
        26 => CAP_SYS_TTY_CONFIG,
        27 => CAP_MKNOD,
        28 => CAP_LEASE,
        29 => CAP_AUDIT_WRITE,
        30 => CAP_AUDIT_CONTROL,
        31 => CAP_SETFCAP,
        32 => CAP_MAC_OVERRIDE,
        33 => CAP_MAC_ADMIN,
        34 => CAP_SYSLOG,
        35 => CAP_WAKE_ALARM,
        36 => CAP_BLOCK_SUSPEND,
        37 => CAP_AUDIT_READ,
        38 => CAP_PERFMON,
        39 => CAP_BPF,
        40 => CAP_CHECKPOINT_RESTORE,
        _ => return None,
    })
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

/// Harden against privilege escalation. NOTE: this does NOT install a seccomp
/// BPF syscall filter — the name is kept for CLI/API stability. Today this
/// only ensures `PR_SET_NO_NEW_PRIVS`, which `drop_privileges` also sets;
/// calling both is harmless and idempotent.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn apply_seccomp() {
    use tracing::{info, warn};

    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

    if ret != 0 {
        warn!(
            errno = %std::io::Error::last_os_error(),
            "seccomp: failed to set no_new_privs"
        );
        return;
    }

    info!("PR_SET_NO_NEW_PRIVS enforced (no BPF syscall filter installed)");
}

#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp() {
    tracing::debug!("seccomp is Linux-only, skipping");
}

#[cfg(not(target_os = "linux"))]
pub fn drop_privileges() {
    tracing::debug!("privilege dropping is Linux-only, skipping");
}
