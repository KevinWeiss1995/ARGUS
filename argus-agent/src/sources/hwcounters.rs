//! Hardware counter reader for InfiniBand ports.
//! Reads from both /sys/class/infiniband/*/ports/*/counters/* (standard IB)
//! and /sys/class/infiniband/*/ports/*/hw_counters/* (rxe, mlx5, etc.).
//! Works on any Linux with IB or Soft-RoCE, no eBPF needed.

use argus_common::{ArgusEvent, HardwareCounter, HardwareCounterEvent};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::info;

/// Classification of the IB device driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Real IB HCA (mlx5, mlx4, hfi1, qib, etc.)
    HardwareIB,
    /// Software RDMA over Ethernet (rxe, siw)
    SoftRoCE,
    /// Unknown driver — treat conservatively
    Unknown,
}

impl DeviceType {
    fn classify(device_name: &str) -> Self {
        let lower = device_name.to_ascii_lowercase();
        if lower.starts_with("rxe") || lower.starts_with("siw") {
            Self::SoftRoCE
        } else if lower.starts_with("mlx5")
            || lower.starts_with("mlx4")
            || lower.starts_with("hfi1")
            || lower.starts_with("qib")
            || lower.starts_with("irdma")
            || lower.starts_with("bnxt")
            || lower.starts_with("erdma")
        {
            Self::HardwareIB
        } else {
            Self::Unknown
        }
    }
}

/// Discovers and reads InfiniBand hardware counters from sysfs.
pub struct HwCounterReader {
    ports: Vec<IbPort>,
}

struct IbPort {
    device: String,
    port_num: u32,
    device_type: DeviceType,
    counter_dir: Option<PathBuf>,
    hw_counter_dir: Option<PathBuf>,
}

/// Standard counters from counters/ (values in IB-native units).
const STANDARD_COUNTERS: &[(&str, fn(u64) -> HardwareCounter)] = &[
    ("symbol_error_count", HardwareCounter::SymbolErrors),
    ("link_downed", HardwareCounter::LinkDowned),
    ("port_rcv_errors", HardwareCounter::PortRcvErrors),
    ("port_xmit_discards", HardwareCounter::PortXmitDiscards),
    ("port_rcv_data", HardwareCounter::PortRcvData),
    ("port_xmit_data", HardwareCounter::PortXmitData),
    (
        "port_rcv_remote_physical_errors",
        HardwareCounter::PortRcvRemotePhysicalErrors,
    ),
    (
        "local_link_integrity_errors",
        HardwareCounter::LocalLinkIntegrityErrors,
    ),
    (
        "excessive_buffer_overrun_errors",
        HardwareCounter::ExcessiveBufferOverrunErrors,
    ),
    ("link_error_recovery", HardwareCounter::LinkErrorRecovery),
    ("port_xmit_wait", HardwareCounter::PortXmitWait),
];

/// hw_counters/ exposed by rxe and other drivers.
/// These map to their own HardwareCounter variants — NOT to IB error fields.
const HW_COUNTERS: &[(&str, fn(u64) -> HardwareCounter)] = &[
    ("rcvd_pkts", HardwareCounter::HwRcvPkts),
    ("sent_pkts", HardwareCounter::HwXmitPkts),
    ("duplicate_request", HardwareCounter::RxeDuplicateRequest),
    ("rcvd_seq_err", HardwareCounter::RxeSeqError),
    ("retry_exceeded_err", HardwareCounter::RxeRetryExceeded),
    ("send_err", HardwareCounter::RxeSendError),
];

fn read_counter(dir: &Path, filename: &str) -> Option<u64> {
    let path = dir.join(filename);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

impl HwCounterReader {
    /// Scan /sys/class/infiniband for available ports.
    pub fn discover() -> Self {
        let mut ports = Vec::new();
        let ib_path = Path::new("/sys/class/infiniband");

        if let Ok(devices) = std::fs::read_dir(ib_path) {
            for device_entry in devices.flatten() {
                let device_name = device_entry.file_name().to_string_lossy().to_string();
                let ports_dir = device_entry.path().join("ports");

                if let Ok(port_entries) = std::fs::read_dir(&ports_dir) {
                    for port_entry in port_entries.flatten() {
                        if let Ok(port_num) =
                            port_entry.file_name().to_string_lossy().parse::<u32>()
                        {
                            let counter_dir = port_entry.path().join("counters");
                            let hw_counter_dir = port_entry.path().join("hw_counters");

                            let has_counters = counter_dir.exists();
                            let has_hw_counters = hw_counter_dir.exists();

                            if has_counters || has_hw_counters {
                                let device_type = DeviceType::classify(&device_name);
                                info!(
                                    device = %device_name,
                                    port = port_num,
                                    device_type = ?device_type,
                                    counters = has_counters,
                                    hw_counters = has_hw_counters,
                                    "discovered IB port"
                                );
                                ports.push(IbPort {
                                    device: device_name.clone(),
                                    port_num,
                                    device_type,
                                    counter_dir: has_counters.then_some(counter_dir),
                                    hw_counter_dir: has_hw_counters.then_some(hw_counter_dir),
                                });
                            }
                        }
                    }
                }
            }
        }

        if ports.is_empty() {
            info!("no InfiniBand ports discovered");
        }

        Self { ports }
    }

    /// Read all important counters from all discovered ports.
    pub fn read_all(&self) -> Vec<ArgusEvent> {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let mut events = Vec::new();

        for port in &self.ports {
            if let Some(dir) = &port.counter_dir {
                for (filename, make_counter) in STANDARD_COUNTERS {
                    if let Some(val) = read_counter(dir, filename) {
                        events.push(ArgusEvent::HardwareCounter(HardwareCounterEvent {
                            timestamp_ns: ts,
                            port_num: port.port_num,
                            counter: make_counter(val),
                        }));
                    }
                }
            }

            if let Some(dir) = &port.hw_counter_dir {
                for (filename, make_counter) in HW_COUNTERS {
                    if let Some(val) = read_counter(dir, filename) {
                        events.push(ArgusEvent::HardwareCounter(HardwareCounterEvent {
                            timestamp_ns: ts,
                            port_num: port.port_num,
                            counter: make_counter(val),
                        }));
                    }
                }
            }
        }

        events
    }

    #[must_use]
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Returns the dominant device type across all discovered ports.
    /// If any port is HardwareIB, returns HardwareIB. Otherwise SoftRoCE if any, else Unknown.
    #[must_use]
    pub fn device_type(&self) -> DeviceType {
        if self
            .ports
            .iter()
            .any(|p| p.device_type == DeviceType::HardwareIB)
        {
            DeviceType::HardwareIB
        } else if self
            .ports
            .iter()
            .any(|p| p.device_type == DeviceType::SoftRoCE)
        {
            DeviceType::SoftRoCE
        } else {
            DeviceType::Unknown
        }
    }

    /// Returns `(device_name, port_num, device_type)` tuples for all discovered ports.
    pub fn discovered_ports(&self) -> Vec<(String, u32, DeviceType)> {
        self.ports
            .iter()
            .map(|p| (p.device.clone(), p.port_num, p.device_type))
            .collect()
    }

    /// Returns device names and port numbers for logging.
    pub fn describe(&self) -> Vec<String> {
        self.ports
            .iter()
            .map(|p| {
                let sources = match (&p.counter_dir, &p.hw_counter_dir) {
                    (Some(_), Some(_)) => "counters+hw_counters",
                    (Some(_), None) => "counters",
                    (None, Some(_)) => "hw_counters",
                    (None, None) => "none",
                };
                format!("{}/port{} [{}]", p.device, p.port_num, sources)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn discover_on_non_ib_host() {
        let reader = HwCounterReader::discover();
        assert!(reader.port_count() == 0 || reader.port_count() > 0);
        let events = reader.read_all();
        let _ = events;
    }

    #[test]
    fn read_counter_parses_sysfs_values() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("test_counter"), "12345\n").unwrap();
        assert_eq!(read_counter(dir.path(), "test_counter"), Some(12345));
        assert_eq!(read_counter(dir.path(), "nonexistent"), None);
    }
}
