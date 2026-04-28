//! Runtime fabric / driver / kernel detection.
//!
//! No hardcoded mlx5 or kernel symbol assumptions. We probe sysfs, kallsyms,
//! and capability-bit files to figure out:
//!   - which fabric type is present (IB / RoCEv1 / RoCEv2 / Soft-RoCE / none)
//!   - which RDMA driver (mlx5, mlx4, hfi1, qib, irdma, bnxt, rxe, siw, ...)
//!   - which kernel tracepoints/kprobes are available for our preferred backends
//!   - what capabilities the process holds (CAP_BPF, CAP_NET_ADMIN)

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use tracing::debug;

/// High-level fabric category.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FabricKind {
    /// Real InfiniBand (CBFC, MAD/SMP, no IP layer).
    InfiniBand,
    /// RoCEv1: IB transport over Ethernet L2 (rare).
    RoCEv1,
    /// RoCEv2: IB transport over UDP/IP — modern RoCE deployments.
    RoCEv2,
    /// Software RDMA (rxe, siw) over kernel UDP — testing and some prod.
    SoftRoCE,
    /// IWARP — distinct transport, almost always Chelsio.
    IWarp,
    /// Detected an RDMA device but couldn't classify.
    Unknown,
}

impl FabricKind {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::InfiniBand => "infiniband",
            Self::RoCEv1 => "rocev1",
            Self::RoCEv2 => "rocev2",
            Self::SoftRoCE => "softroce",
            Self::IWarp => "iwarp",
            Self::Unknown => "unknown",
        }
    }
}

/// Which RDMA driver is providing the device.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum DriverKind {
    Mlx5,
    Mlx4,
    Hfi1,
    Qib,
    Irdma,
    Bnxt,
    Erdma,
    Rxe,
    Siw,
    Other(String),
}

impl DriverKind {
    fn from_device_name(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("mlx5") {
            Self::Mlx5
        } else if lower.starts_with("mlx4") {
            Self::Mlx4
        } else if lower.starts_with("hfi1") {
            Self::Hfi1
        } else if lower.starts_with("qib") {
            Self::Qib
        } else if lower.starts_with("irdma") {
            Self::Irdma
        } else if lower.starts_with("bnxt") {
            Self::Bnxt
        } else if lower.starts_with("erdma") {
            Self::Erdma
        } else if lower.starts_with("rxe") {
            Self::Rxe
        } else if lower.starts_with("siw") {
            Self::Siw
        } else {
            Self::Other(name.to_string())
        }
    }
}

/// One discovered RDMA device.
#[derive(Clone, Debug)]
pub struct RdmaDevice {
    pub name: String,
    pub driver: DriverKind,
    pub fabric: FabricKind,
    /// Available counter file names under /sys/class/infiniband/<dev>/ports/<n>/counters.
    pub standard_counters: HashSet<String>,
    /// Available counter file names under .../hw_counters (driver-specific).
    pub hw_counters: HashSet<String>,
    pub port_count: u32,
}

/// Capability/permission flags for the running process.
#[derive(Clone, Debug, Default)]
pub struct PrivilegeProfile {
    pub has_cap_bpf: bool,
    pub has_cap_net_admin: bool,
    pub has_cap_perfmon: bool,
    pub uid_zero: bool,
}

impl PrivilegeProfile {
    /// Cheap heuristic: any of the relevant caps is enough for higher-quality backends.
    #[must_use]
    pub fn can_run_ebpf(&self) -> bool {
        self.has_cap_bpf || self.uid_zero
    }
}

/// Aggregate fabric environment — the input to every provider's `probe()`.
#[derive(Clone, Debug)]
pub struct FabricEnv {
    /// Dominant fabric across discovered devices.
    pub fabric: Option<FabricKind>,
    pub devices: Vec<RdmaDevice>,
    pub kernel_release: Option<String>,
    pub privileges: PrivilegeProfile,
    /// True if we detected we're running inside a synthetic/test environment.
    pub synthetic: bool,
}

impl FabricEnv {
    /// Detect the running environment. Never panics; returns an `Unknown`
    /// fabric on unexpected errors so providers can still probe.
    #[must_use]
    pub fn detect() -> Self {
        let devices = discover_devices().unwrap_or_default();

        let fabric = if devices.is_empty() {
            None
        } else if devices.iter().any(|d| d.fabric == FabricKind::SoftRoCE) {
            // If any device is rxe, we're in soft-RoCE mode (could coexist
            // with hardware but provider tier picks the right thing per-cap).
            Some(FabricKind::SoftRoCE)
        } else if devices.iter().any(|d| d.fabric == FabricKind::RoCEv2) {
            Some(FabricKind::RoCEv2)
        } else if devices.iter().any(|d| d.fabric == FabricKind::InfiniBand) {
            Some(FabricKind::InfiniBand)
        } else {
            Some(FabricKind::Unknown)
        };

        let kernel_release = read_kernel_release();
        let privileges = detect_privileges();

        Self {
            fabric,
            devices,
            kernel_release,
            privileges,
            synthetic: false,
        }
    }

    /// Produce a synthetic env for tests. Looks like a softroce host with
    /// no privileges and no devices; providers should treat it as a unit-test surface.
    #[must_use]
    pub fn synthetic() -> Self {
        Self {
            fabric: Some(FabricKind::SoftRoCE),
            devices: vec![],
            kernel_release: Some("test".to_string()),
            privileges: PrivilegeProfile::default(),
            synthetic: true,
        }
    }

    /// True if any discovered device uses the named driver.
    #[must_use]
    pub fn has_driver(&self, drv: &DriverKind) -> bool {
        self.devices.iter().any(|d| std::mem::discriminant(&d.driver) == std::mem::discriminant(drv))
    }

    /// True if any discovered device exposes a counter file name matching
    /// `pattern`. Matching is case-sensitive substring; callers can expand
    /// to globbing if needed.
    #[must_use]
    pub fn any_device_has_hw_counter(&self, pattern: &str) -> bool {
        self.devices
            .iter()
            .any(|d| d.hw_counters.iter().any(|c| c.contains(pattern)))
    }

    #[must_use]
    pub fn any_device_has_std_counter(&self, pattern: &str) -> bool {
        self.devices
            .iter()
            .any(|d| d.standard_counters.iter().any(|c| c.contains(pattern)))
    }
}

fn discover_devices() -> io::Result<Vec<RdmaDevice>> {
    let ib_path = Path::new("/sys/class/infiniband");
    if !ib_path.exists() {
        return Ok(vec![]);
    }

    let mut out = Vec::new();
    for entry in fs::read_dir(ib_path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let driver = DriverKind::from_device_name(&name);
        let ports_dir = entry.path().join("ports");
        let mut ports = Vec::new();

        if let Ok(rd) = fs::read_dir(&ports_dir) {
            for p in rd.flatten() {
                if let Ok(port_num) = p.file_name().to_string_lossy().parse::<u32>() {
                    ports.push((port_num, p.path()));
                }
            }
        }

        let mut standard_counters = HashSet::new();
        let mut hw_counters = HashSet::new();

        for (_, port_dir) in &ports {
            scan_counter_dir(&port_dir.join("counters"), &mut standard_counters);
            scan_counter_dir(&port_dir.join("hw_counters"), &mut hw_counters);
        }

        let fabric = classify_fabric(&driver, &entry.path());
        let port_count = ports.len() as u32;
        debug!(device = %name, ?driver, ?fabric, ports = port_count, "discovered RDMA device");

        out.push(RdmaDevice {
            name,
            driver,
            fabric,
            standard_counters,
            hw_counters,
            port_count,
        });
    }

    Ok(out)
}

fn scan_counter_dir(path: &Path, out: &mut HashSet<String>) {
    if let Ok(rd) = fs::read_dir(path) {
        for entry in rd.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                out.insert(name.to_string());
            }
        }
    }
}

fn classify_fabric(driver: &DriverKind, dev_path: &Path) -> FabricKind {
    // rxe/siw are always softroce
    if matches!(driver, DriverKind::Rxe | DriverKind::Siw) {
        return FabricKind::SoftRoCE;
    }

    // Try to detect link layer from the first port: "InfiniBand" or "Ethernet".
    let mut ports_dir = dev_path.to_path_buf();
    ports_dir.push("ports");
    if let Ok(rd) = fs::read_dir(&ports_dir) {
        for entry in rd.flatten() {
            let mut p = entry.path();
            p.push("link_layer");
            if let Ok(s) = fs::read_to_string(&p) {
                let s = s.trim().to_ascii_lowercase();
                if s == "infiniband" {
                    return FabricKind::InfiniBand;
                }
                if s == "ethernet" {
                    // Could be RoCEv1 or v2 — RoCEv2 is overwhelmingly more
                    // common today. Without parsing GID type, default to v2.
                    // (Consumers can refine via `roce_v2_only` cap probe.)
                    return FabricKind::RoCEv2;
                }
            }
        }
    }

    match driver {
        DriverKind::Mlx5 | DriverKind::Mlx4 | DriverKind::Hfi1 | DriverKind::Qib => {
            FabricKind::InfiniBand
        }
        DriverKind::Irdma | DriverKind::Bnxt | DriverKind::Erdma => FabricKind::RoCEv2,
        _ => FabricKind::Unknown,
    }
}

fn read_kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "linux")]
fn detect_privileges() -> PrivilegeProfile {
    let uid_zero = unsafe { libc::geteuid() } == 0;
    let mut profile = PrivilegeProfile {
        uid_zero,
        ..Default::default()
    };
    if let Ok(set) = caps::read(None, caps::CapSet::Effective) {
        profile.has_cap_bpf = set.contains(&caps::Capability::CAP_BPF);
        profile.has_cap_net_admin = set.contains(&caps::Capability::CAP_NET_ADMIN);
        profile.has_cap_perfmon = set.contains(&caps::Capability::CAP_PERFMON);
    }
    profile
}

#[cfg(not(target_os = "linux"))]
fn detect_privileges() -> PrivilegeProfile {
    PrivilegeProfile::default()
}

// ---------------------------------------------------------------------------
// KallsymsCache — cheap availability lookup for kernel symbols.
// ---------------------------------------------------------------------------

/// Cached set of kernel symbol names. Used by eBPF backends to decide whether
/// a kprobe target is even attachable on the current kernel — much cheaper
/// than blindly attaching and getting `ENOENT`.
#[derive(Default)]
pub struct KallsymsCache {
    symbols: HashSet<String>,
    loaded: bool,
}

impl KallsymsCache {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load `/proc/kallsyms` once. Subsequent calls are no-ops.
    /// Returns `false` if reading failed (e.g., kptr_restrict without privilege).
    pub fn load(&mut self) -> bool {
        if self.loaded {
            return true;
        }
        let Ok(content) = fs::read_to_string("/proc/kallsyms") else {
            return false;
        };
        for line in content.lines() {
            // Format: <addr> <type> <name> [<module>]
            let mut parts = line.split_whitespace();
            if let (Some(_addr), Some(_typ), Some(name)) = (parts.next(), parts.next(), parts.next()) {
                // Strip kallsyms suffix variants like `.cold`, `.constprop.0`.
                let base = name.split('.').next().unwrap_or(name);
                self.symbols.insert(base.to_string());
            }
        }
        self.loaded = true;
        true
    }

    /// True if the named symbol exists. Returns `false` if cache wasn't loaded.
    #[must_use]
    pub fn contains(&self, sym: &str) -> bool {
        self.symbols.contains(sym)
    }

    /// True if any symbol in `candidates` exists. Used for kernel-version-fan-out
    /// resolution: e.g., `["mlx5_ib_post_send", "mlx5_ib_post_send_v2"]`.
    #[must_use]
    pub fn contains_any(&self, candidates: &[&str]) -> bool {
        candidates.iter().any(|s| self.contains(*s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_kind_classifies_known_prefixes() {
        assert!(matches!(DriverKind::from_device_name("mlx5_0"), DriverKind::Mlx5));
        assert!(matches!(DriverKind::from_device_name("rxe0"), DriverKind::Rxe));
        assert!(matches!(DriverKind::from_device_name("hfi1_1"), DriverKind::Hfi1));
        match DriverKind::from_device_name("foobar0") {
            DriverKind::Other(s) => assert_eq!(s, "foobar0"),
            _ => panic!("expected Other"),
        }
    }

    #[test]
    fn fabric_env_synthetic_is_softroce() {
        let env = FabricEnv::synthetic();
        assert_eq!(env.fabric, Some(FabricKind::SoftRoCE));
        assert!(env.synthetic);
    }

    #[test]
    fn kallsyms_cache_starts_empty() {
        let c = KallsymsCache::empty();
        assert!(!c.contains("anything"));
    }
}
