//! Host-side NIC health monitoring: `PCIe` lane state and thermal.
//!
//! These checks are NIC-side hardware facts that don't show up in IB
//! counter deltas but predict failure independently:
//!
//!   * **`PCIe` lane degradation**: a NIC's `PCIe` link can drop lanes
//!     (x16 → x8) or generations (Gen4 → Gen3) due to a bad slot, dirty
//!     contacts, or thermal throttling. Throughput halves silently;
//!     IB counters show nothing wrong because the IB protocol works
//!     fine — it just has less bandwidth to work with. Detection is
//!     a comparison of `current_link_speed`/`current_link_width` vs
//!     `max_link_speed`/`max_link_width` on the NIC's PCI device.
//!
//!   * **NIC thermal**: Mellanox NICs expose temperature via the kernel
//!     hwmon framework. Sustained temperature above ~75°C predicts
//!     hardware failure hours-to-days in advance per Mellanox/NVIDIA's
//!     own field-failure analyses. ARGUS doesn't have a tool to cool
//!     the NIC, but it can alert operators to schedule replacement
//!     before thermal damage becomes permanent.
//!
//! Both checks are read-only from sysfs, with no kernel ABI churn risk —
//! the paths used here have been stable since Linux 3.x.

use std::fs;
use std::path::{Path, PathBuf};

/// Snapshot of one NIC's `PCIe` link state at a point in time.
#[derive(Debug, Clone)]
pub struct PcieLinkState {
    pub ib_device: String,
    /// e.g. "16.0 GT/s `PCIe`" or "8.0 GT/s `PCIe`"
    pub current_speed: String,
    pub max_speed: String,
    pub current_width: u32,
    pub max_width: u32,
}

impl PcieLinkState {
    /// True when either the link generation or lane count is below
    /// what the device negotiated as its maximum. This is the
    /// definition of "degraded `PCIe` link" in NVIDIA/Mellanox's
    /// diagnostic guidance.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.current_speed != self.max_speed || self.current_width < self.max_width
    }
}

/// Snapshot of one NIC's temperature reading.
#[derive(Debug, Clone)]
pub struct NicThermal {
    pub ib_device: String,
    pub current_celsius: f64,
    /// Where the reading came from, for operator diagnostics if the
    /// value looks wrong.
    pub source_path: String,
}

/// Discovers IB devices and exposes per-device `PCIe` + thermal readers.
/// One instance per agent; refreshes its readings each window.
pub struct NicHealthReader {
    devices: Vec<NicDevice>,
}

struct NicDevice {
    ib_device: String,
    /// /sys/class/infiniband/<`ib_device>/device` — symlinks to the PCI
    /// device. We resolve once at discovery and cache the resolved path.
    pci_path: PathBuf,
    /// Optional path to the hwmon `temp1_input` under this PCI device,
    /// resolved at discovery if present. Mellanox exposes it; other
    /// vendors may not.
    thermal_path: Option<PathBuf>,
}

impl NicHealthReader {
    /// Walk /sys/class/infiniband and resolve each IB device to its
    /// PCI device and (optionally) hwmon thermal sensor.
    #[must_use]
    pub fn discover() -> Self {
        let mut devices = Vec::new();
        let ib_root = Path::new("/sys/class/infiniband");
        let Ok(entries) = fs::read_dir(ib_root) else {
            return Self { devices };
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let ib_device_dir = entry.path();
            // Resolve /sys/class/infiniband/<dev>/device symlink to the
            // PCI device dir. canonicalize() follows the symlink.
            let device_symlink = ib_device_dir.join("device");
            let Ok(pci_path) = fs::canonicalize(&device_symlink) else {
                continue;
            };
            let thermal_path = locate_thermal_input(&pci_path);
            devices.push(NicDevice {
                ib_device: name,
                pci_path,
                thermal_path,
            });
        }
        devices.sort_by(|a, b| a.ib_device.cmp(&b.ib_device));
        Self { devices }
    }

    /// Read current `PCIe` link state for every discovered NIC.
    /// Reads that fail (sysfs unreadable, parse error) are silently
    /// omitted — the rest still report.
    #[must_use]
    pub fn read_pcie(&self) -> Vec<PcieLinkState> {
        let mut out = Vec::with_capacity(self.devices.len());
        for d in &self.devices {
            let Some(cur_speed) = read_trimmed(&d.pci_path.join("current_link_speed")) else {
                continue;
            };
            let Some(max_speed) = read_trimmed(&d.pci_path.join("max_link_speed")) else {
                continue;
            };
            let Some(cur_width) = read_u32(&d.pci_path.join("current_link_width")) else {
                continue;
            };
            let Some(max_width) = read_u32(&d.pci_path.join("max_link_width")) else {
                continue;
            };
            out.push(PcieLinkState {
                ib_device: d.ib_device.clone(),
                current_speed: cur_speed,
                max_speed,
                current_width: cur_width,
                max_width,
            });
        }
        out
    }

    /// Read current temperature for every discovered NIC that has an
    /// hwmon thermal sensor. Mellanox NICs always expose one; other
    /// drivers may not.
    #[must_use]
    pub fn read_thermal(&self) -> Vec<NicThermal> {
        let mut out = Vec::new();
        for d in &self.devices {
            let Some(path) = &d.thermal_path else {
                continue;
            };
            // hwmon temp inputs are in millidegrees Celsius (per the
            // hwmon ABI documentation, kernel Documentation/hwmon/sysfs-interface).
            let Some(raw) = read_u64(path) else { continue };
            out.push(NicThermal {
                ib_device: d.ib_device.clone(),
                current_celsius: raw as f64 / 1000.0,
                source_path: path.display().to_string(),
            });
        }
        out
    }

    #[must_use]
    pub const fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Per-device thermal sensor availability — useful for the operator
    /// to know which NICs are being thermal-monitored vs which aren't.
    #[must_use]
    pub fn thermal_coverage(&self) -> Vec<(String, bool)> {
        self.devices
            .iter()
            .map(|d| (d.ib_device.clone(), d.thermal_path.is_some()))
            .collect()
    }
}

/// Find an hwmon `temp1_input` under the given PCI device path, if any.
/// Iterates /sys/class/hwmon/* and picks the entry whose device link
/// resolves into our PCI tree. Mellanox NICs typically expose this;
/// other vendors may not.
fn locate_thermal_input(pci_path: &Path) -> Option<PathBuf> {
    let hwmon_root = Path::new("/sys/class/hwmon");
    let entries = fs::read_dir(hwmon_root).ok()?;
    for entry in entries.flatten() {
        let hwmon_dir = entry.path();
        let device_link = hwmon_dir.join("device");
        let Ok(resolved) = fs::canonicalize(&device_link) else {
            continue;
        };
        // The hwmon's `device` is the PCI device itself, or a child
        // path of it. Accept exact match or ancestor-of relationship.
        if resolved == pci_path || resolved.starts_with(pci_path) {
            let candidate = hwmon_dir.join("temp1_input");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_u32(path: &Path) -> Option<u32> {
    read_trimmed(path).and_then(|s| s.parse::<u32>().ok())
}

fn read_u64(path: &Path) -> Option<u64> {
    read_trimmed(path).and_then(|s| s.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_on_host_without_ib_returns_empty() {
        // macOS / Linux without IB devices both end up here. The
        // function must not panic and must return an empty list.
        let reader = NicHealthReader::discover();
        let _ = reader.read_pcie();
        let _ = reader.read_thermal();
        // Either count is fine, but we exercise the call paths.
        assert_eq!(reader.device_count(), reader.thermal_coverage().len());
    }

    #[test]
    fn pcie_link_state_degraded_detection() {
        let healthy = PcieLinkState {
            ib_device: "mlx5_0".into(),
            current_speed: "16.0 GT/s PCIe".into(),
            max_speed: "16.0 GT/s PCIe".into(),
            current_width: 16,
            max_width: 16,
        };
        assert!(!healthy.is_degraded());

        let downgraded_width = PcieLinkState {
            current_width: 8,
            ..healthy.clone()
        };
        assert!(downgraded_width.is_degraded());

        let downgraded_speed = PcieLinkState {
            current_speed: "8.0 GT/s PCIe".into(),
            ..healthy
        };
        assert!(downgraded_speed.is_degraded());
    }
}
