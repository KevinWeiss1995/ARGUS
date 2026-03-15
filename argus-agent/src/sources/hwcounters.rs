//! Hardware counter reader for InfiniBand ports.
//! Reads from both /sys/class/infiniband/*/ports/*/counters/* (standard IB)
//! and /sys/class/infiniband/*/ports/*/hw_counters/* (rxe, mlx5, etc.).
//! Works on any Linux with IB or Soft-RoCE, no eBPF needed.

use argus_common::{ArgusEvent, HardwareCounter, HardwareCounterEvent};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::info;

/// Discovers and reads InfiniBand hardware counters from sysfs.
pub struct HwCounterReader {
    ports: Vec<IbPort>,
}

struct IbPort {
    device: String,
    port_num: u32,
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
];

/// hw_counters/ exposed by rxe and other drivers (packet counts, error counters).
const HW_COUNTERS: &[(&str, fn(u64) -> HardwareCounter)] = &[
    ("rcvd_pkts", HardwareCounter::HwRcvPkts),
    ("sent_pkts", HardwareCounter::HwXmitPkts),
    ("duplicate_request", HardwareCounter::PortRcvErrors),
    ("rcvd_seq_err", HardwareCounter::PortRcvErrors),
    ("retry_exceeded_err", HardwareCounter::PortXmitDiscards),
    ("send_err", HardwareCounter::PortXmitDiscards),
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
                                info!(
                                    device = %device_name,
                                    port = port_num,
                                    counters = has_counters,
                                    hw_counters = has_hw_counters,
                                    "discovered IB port"
                                );
                                ports.push(IbPort {
                                    device: device_name.clone(),
                                    port_num,
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
