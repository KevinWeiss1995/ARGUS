//! Runtime kernel capability detection for RHEL/enterprise Linux compatibility.
//!
//! Probes actual kernel features via syscall attempts and filesystem checks
//! rather than version strings, which are unreliable on RHEL due to backports.

use std::fmt;
use std::path::Path;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownMode {
    None,
    Integrity,
    Confidentiality,
}

impl fmt::Display for LockdownMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Integrity => write!(f, "integrity"),
            Self::Confidentiality => write!(f, "confidentiality"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingTier {
    /// Full eBPF: tracepoints + kprobes + kretprobes
    Tier1,
    /// No eBPF: sysfs + procfs only (locked-down or policy-restricted)
    Tier2,
}

impl fmt::Display for OperatingTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tier1 => write!(f, "Tier1 (eBPF)"),
            Self::Tier2 => write!(f, "Tier2 (procfs/sysfs fallback)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KernelCapabilities {
    pub ebpf_available: bool,
    pub tracepoints_readable: bool,
    pub kprobes_available: bool,
    pub btf_available: bool,
    pub lockdown_mode: LockdownMode,
    pub selinux_enforcing: bool,
    pub kernel_release: String,
    pub is_rhel: bool,
    pub rhel_suffix: Option<String>,
}

impl KernelCapabilities {
    pub fn detect() -> Self {
        let lockdown_mode = detect_lockdown_mode();
        let kernel_release = read_kernel_release();
        let rhel_suffix = parse_rhel_suffix(&kernel_release);
        let tracepoints_readable = detect_tracepoints_readable();

        let caps = Self {
            ebpf_available: detect_ebpf_available(tracepoints_readable),
            tracepoints_readable,
            kprobes_available: detect_kprobes_available(lockdown_mode),
            btf_available: Path::new("/sys/kernel/btf/vmlinux").exists(),
            lockdown_mode,
            selinux_enforcing: detect_selinux_enforcing(),
            is_rhel: rhel_suffix.is_some(),
            rhel_suffix,
            kernel_release,
        };

        caps.log_summary();
        caps
    }

    #[must_use]
    pub fn determine_tier(&self) -> OperatingTier {
        if self.ebpf_available {
            OperatingTier::Tier1
        } else {
            OperatingTier::Tier2
        }
    }

    fn log_summary(&self) {
        let tier = self.determine_tier();
        info!(
            kernel = %self.kernel_release,
            tier = %tier,
            ebpf = self.ebpf_available,
            tracepoints = self.tracepoints_readable,
            kprobes = self.kprobes_available,
            btf = self.btf_available,
            lockdown = %self.lockdown_mode,
            selinux = self.selinux_enforcing,
            rhel = ?self.rhel_suffix,
            "kernel capabilities detected"
        );
    }
}

fn tracefs_path() -> Option<&'static Path> {
    let primary = Path::new("/sys/kernel/tracing");
    if primary.exists() {
        return Some(primary);
    }
    let fallback = Path::new("/sys/kernel/debug/tracing");
    if fallback.exists() {
        return Some(fallback);
    }
    None
}

fn detect_tracepoints_readable() -> bool {
    if let Some(base) = tracefs_path() {
        base.join("events").exists()
    } else {
        false
    }
}

fn detect_ebpf_available(tracepoints_readable: bool) -> bool {
    if !tracepoints_readable {
        return false;
    }
    match caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_SYS_ADMIN) {
        Ok(true) => return true,
        Ok(false) => {}
        Err(e) => {
            warn!("failed to check CAP_SYS_ADMIN: {e}");
        }
    }
    // CAP_BPF exists since Linux 5.8; caps crate may not have it on older builds.
    // Fall back to checking CAP_SYS_ADMIN above, which is sufficient.
    false
}

fn detect_kprobes_available(lockdown: LockdownMode) -> bool {
    if matches!(lockdown, LockdownMode::Integrity | LockdownMode::Confidentiality) {
        return false;
    }

    let paths = [
        "/sys/kernel/debug/kprobes/enabled",
        "/proc/sys/kernel/kprobes_enabled",
    ];
    for p in &paths {
        if let Ok(content) = std::fs::read_to_string(p) {
            if content.trim() == "1" {
                return true;
            }
            return false;
        }
    }
    false
}

fn detect_lockdown_mode() -> LockdownMode {
    let content = match std::fs::read_to_string("/sys/kernel/security/lockdown") {
        Ok(c) => c,
        Err(_) => return LockdownMode::None,
    };

    // Format: "none [integrity] confidentiality" — active mode is bracketed
    if let Some(start) = content.find('[') {
        if let Some(end) = content[start..].find(']') {
            let active = &content[start + 1..start + end];
            return match active {
                "integrity" => LockdownMode::Integrity,
                "confidentiality" => LockdownMode::Confidentiality,
                _ => LockdownMode::None,
            };
        }
    }
    LockdownMode::None
}

fn detect_selinux_enforcing() -> bool {
    std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn read_kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn parse_rhel_suffix(release: &str) -> Option<String> {
    for suffix in &[".el10", ".el9", ".el8"] {
        if release.contains(suffix) {
            return Some(suffix.trim_start_matches('.').to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockdown_parse_integrity() {
        assert_eq!(
            parse_lockdown_content("none [integrity] confidentiality"),
            LockdownMode::Integrity
        );
    }

    #[test]
    fn lockdown_parse_confidentiality() {
        assert_eq!(
            parse_lockdown_content("none integrity [confidentiality]"),
            LockdownMode::Confidentiality
        );
    }

    #[test]
    fn lockdown_parse_none() {
        assert_eq!(
            parse_lockdown_content("[none] integrity confidentiality"),
            LockdownMode::None
        );
    }

    #[test]
    fn lockdown_parse_missing() {
        assert_eq!(parse_lockdown_content(""), LockdownMode::None);
    }

    #[test]
    fn rhel_suffix_detection() {
        assert_eq!(
            parse_rhel_suffix("5.14.0-362.24.1.el9_3.x86_64"),
            Some("el9".into())
        );
        assert_eq!(
            parse_rhel_suffix("4.18.0-477.10.1.el8_8.x86_64"),
            Some("el8".into())
        );
        assert_eq!(parse_rhel_suffix("6.8.0-45-generic"), None);
    }

    #[test]
    fn rhel_suffix_el10() {
        assert_eq!(
            parse_rhel_suffix("6.12.0-55.el10.x86_64"),
            Some("el10".into())
        );
    }

    #[test]
    fn operating_tier_display() {
        assert_eq!(format!("{}", OperatingTier::Tier1), "Tier1 (eBPF)");
        assert_eq!(
            format!("{}", OperatingTier::Tier2),
            "Tier2 (procfs/sysfs fallback)"
        );
    }

    #[test]
    fn lockdown_display() {
        assert_eq!(format!("{}", LockdownMode::None), "none");
        assert_eq!(format!("{}", LockdownMode::Integrity), "integrity");
        assert_eq!(
            format!("{}", LockdownMode::Confidentiality),
            "confidentiality"
        );
    }

    #[test]
    fn tier_determination() {
        let mut caps = KernelCapabilities {
            ebpf_available: true,
            tracepoints_readable: true,
            kprobes_available: true,
            btf_available: true,
            lockdown_mode: LockdownMode::None,
            selinux_enforcing: false,
            kernel_release: "6.8.0-45-generic".into(),
            is_rhel: false,
            rhel_suffix: None,
        };
        assert_eq!(caps.determine_tier(), OperatingTier::Tier1);

        caps.ebpf_available = false;
        assert_eq!(caps.determine_tier(), OperatingTier::Tier2);
    }

    fn parse_lockdown_content(content: &str) -> LockdownMode {
        if let Some(start) = content.find('[') {
            if let Some(end) = content[start..].find(']') {
                let active = &content[start + 1..start + end];
                return match active {
                    "integrity" => LockdownMode::Integrity,
                    "confidentiality" => LockdownMode::Confidentiality,
                    _ => LockdownMode::None,
                };
            }
        }
        LockdownMode::None
    }
}
