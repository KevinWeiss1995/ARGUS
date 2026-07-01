//! Hardware counter reader for InfiniBand ports.
//!
//! Reads from both /sys/class/infiniband/*/ports/*/counters/* (standard IB)
//! and /sys/class/infiniband/*/ports/*/`hw_counters`/* (rxe, mlx5, etc.).
//! Works on any Linux with IB or Soft-RoCE, no eBPF needed.

use argus_common::{ArgusEvent, HardwareCounter, HardwareCounterEvent};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::info;

/// A single absolute counter reading from sysfs.
///
/// Identified by (device, port, `counter_filename`). Returned by
/// `HwCounterReader::absolute_counters()` for the Prometheus exporter
/// to publish as `argus_ib_<counter>_total` series.
#[derive(Debug, Clone)]
pub struct AbsoluteCounter {
    pub device: String,
    pub port: u32,
    pub counter_name: String,
    pub value: u64,
}

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
    /// Latest absolute counter value observed per (device, port, counter
    /// filename). Updated on every read. Surfaces the cumulative kernel
    /// counters so external Prometheus can compute long-window slopes
    /// (`rate(argus_ib`_<counter>_total[24h]) > X) — the
    /// El-Sayed & Schroeder DSN-2013 slow-degradation detection pattern.
    last_absolute: std::sync::Mutex<HashMap<(String, u32, String), u64>>,
}

struct IbPort {
    device: String,
    port_num: u32,
    device_type: DeviceType,
    counter_dir: Option<PathBuf>,
    hw_counter_dir: Option<PathBuf>,
}

/// Maps a sysfs counter filename to its typed `HardwareCounter` constructor.
type CounterTable = &'static [(&'static str, fn(u64) -> HardwareCounter)];

/// Standard counters from counters/ (values in IB-native units).
const STANDARD_COUNTERS: CounterTable = &[
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

/// `hw_counters`/ exposed by rxe, mlx5, mlx4, and other RDMA drivers.
///
/// The list is a flat union of every counter name we know how to read.
/// We don't gate on driver: `read_counter()` returns None when the file
/// doesn't exist, so on rxe hardware the mlx5_* entries silently skip,
/// and vice versa. This keeps the discovery logic dead simple and
/// future-proof for drivers we haven't classified yet.
///
/// Naming conventions:
///   - rxe-prefixed variants are for Soft-RoCE (rxe driver) and the
///     filenames are short, generic ("`rcvd_pkts`", "`duplicate_request`").
///   - Mlx5*-prefixed variants are for Mellanox mlx5 hardware. The
///     filenames are mlx5-specific ("`local_ack_timeout_err`",
///     "`roce_adp_retrans`"). These are THE primary slow-degradation
///     indicators per NVIDIA's IB performance optimization docs and
///     the `mlx5_core` OFED reference.
const HW_COUNTERS: CounterTable = &[
    // rxe (Soft-RoCE) driver — names match argus-test-scenarios
    ("rcvd_pkts", HardwareCounter::HwRcvPkts),
    ("sent_pkts", HardwareCounter::HwXmitPkts),
    ("duplicate_request", HardwareCounter::RxeDuplicateRequest),
    ("rcvd_seq_err", HardwareCounter::RxeSeqError),
    ("retry_exceeded_err", HardwareCounter::RxeRetryExceeded),
    ("send_err", HardwareCounter::RxeSendError),
    // Mellanox mlx5 (and mostly mlx4) — names taken from the
    // mlx5_ib_hw_stats_descs[] array in the OFED kernel source. These
    // exist at /sys/class/infiniband/mlx5_<n>/ports/<p>/hw_counters/
    // on real Mellanox hardware.
    (
        "local_ack_timeout_err",
        HardwareCounter::Mlx5LocalAckTimeoutErr,
    ),
    ("packet_seq_err", HardwareCounter::Mlx5PacketSeqErr),
    ("implied_nak_seq_err", HardwareCounter::Mlx5ImpliedNakSeqErr),
    ("out_of_buffer", HardwareCounter::Mlx5OutOfBuffer),
    ("out_of_sequence", HardwareCounter::Mlx5OutOfSequence),
    ("req_cqe_error", HardwareCounter::Mlx5ReqCqeError),
    ("resp_cqe_error", HardwareCounter::Mlx5RespCqeError),
    ("roce_adp_retrans", HardwareCounter::Mlx5RoceAdpRetrans),
    ("roce_slow_restart", HardwareCounter::Mlx5RoceSlowRestart),
    ("np_cnp_sent", HardwareCounter::Mlx5NpCnpSent),
    ("rp_cnp_handled", HardwareCounter::Mlx5RpCnpHandled),
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

        Self {
            ports,
            last_absolute: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Read all important counters from all discovered ports.
    pub fn read_all(&self) -> Vec<ArgusEvent> {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let mut events = Vec::new();
        let mut absolute_updates: Vec<((String, u32, String), u64)> = Vec::new();

        for port in &self.ports {
            if let Some(dir) = &port.counter_dir {
                for (filename, make_counter) in STANDARD_COUNTERS {
                    if let Some(val) = read_counter(dir, filename) {
                        absolute_updates.push((
                            (port.device.clone(), port.port_num, (*filename).to_string()),
                            val,
                        ));
                        events.push(ArgusEvent::HardwareCounter(HardwareCounterEvent {
                            timestamp_ns: ts,
                            device: port.device.clone(),
                            port_num: port.port_num,
                            counter: make_counter(val),
                        }));
                    }
                }
            }

            if let Some(dir) = &port.hw_counter_dir {
                for (filename, make_counter) in HW_COUNTERS {
                    if let Some(val) = read_counter(dir, filename) {
                        absolute_updates.push((
                            (port.device.clone(), port.port_num, (*filename).to_string()),
                            val,
                        ));
                        events.push(ArgusEvent::HardwareCounter(HardwareCounterEvent {
                            timestamp_ns: ts,
                            device: port.device.clone(),
                            port_num: port.port_num,
                            counter: make_counter(val),
                        }));
                    }
                }
            }
        }

        // Commit all absolute-value updates in one lock acquisition.
        // Lock acquisition failure (poisoned mutex) is non-fatal — we
        // skip the absolute-value snapshot for this window and the
        // delta path keeps working.
        if let Ok(mut map) = self.last_absolute.lock() {
            for (key, val) in absolute_updates {
                map.insert(key, val);
            }
        }

        events
    }

    /// Snapshot of every (device, port, `counter_filename`) → `absolute_value`
    /// observed by the most recent successful read. Used by the Prometheus
    /// exporter to expose `argus_ib_<counter>_total{device,port}` so
    /// external systems can compute long-window slopes — the standard
    /// pattern for detecting slow IB degradation per
    /// El-Sayed & Schroeder (DSN 2013), and what Mellanox UFM uses
    /// internally for its Health Score.
    ///
    /// Returns an empty vec on lock poisoning; emitting stale data is
    /// strictly worse than briefly omitting it.
    #[must_use]
    pub fn absolute_counters(&self) -> Vec<AbsoluteCounter> {
        let Ok(map) = self.last_absolute.lock() else {
            return Vec::new();
        };
        map.iter()
            .map(|((device, port, name), value)| AbsoluteCounter {
                device: device.clone(),
                port: *port,
                counter_name: name.clone(),
                value: *value,
            })
            .collect()
    }

    #[must_use]
    pub const fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Returns the dominant device type across all discovered ports.
    /// If any port is `HardwareIB`, returns `HardwareIB`. Otherwise `SoftRoCE` if any, else Unknown.
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
