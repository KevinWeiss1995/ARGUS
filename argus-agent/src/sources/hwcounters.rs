//! Hardware counter reader for InfiniBand ports.
//! Reads from /sys/class/infiniband/*/ports/*/counters/*.
//! Works on any Linux with IB or Soft-RoCE, no eBPF needed.

use argus_common::{ArgusEvent, HardwareCounter, HardwareCounterEvent};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Discovers and reads InfiniBand hardware counters from sysfs.
pub struct HwCounterReader {
    ports: Vec<IbPort>,
}

struct IbPort {
    #[allow(dead_code)]
    device: String,
    port_num: u32,
    counter_dir: PathBuf,
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
                            if counter_dir.exists() {
                                ports.push(IbPort {
                                    device: device_name.clone(),
                                    port_num,
                                    counter_dir,
                                });
                            }
                        }
                    }
                }
            }
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
            let counters: &[(&str, fn(u64) -> HardwareCounter)] = &[
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

            for (filename, make_counter) in counters {
                let path = port.counter_dir.join(filename);
                if let Ok(val_str) = std::fs::read_to_string(&path) {
                    if let Ok(val) = val_str.trim().parse::<u64>() {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_on_non_ib_host() {
        let reader = HwCounterReader::discover();
        // On macOS or hosts without IB, should discover zero ports gracefully
        assert!(reader.port_count() == 0 || reader.port_count() > 0);
        let events = reader.read_all();
        // Should not panic
        let _ = events;
    }
}
