//! Discover available kernel functions for kprobe attachment via /proc/kallsyms,
//! and resolve struct field offsets from BTF for safe kernel memory reads.
//!
//! The RDMA CQ jitter probe needs to kprobe driver-specific functions (mlx5 or rxe).
//! This module scans kallsyms at startup to determine which functions are available,
//! allowing graceful degradation when neither is present.
//!
//! It also discovers byte offsets for `struct ib_qp.qp_num` and `struct ib_wc.qp`
//! needed by the kprobe programs to read QP identity from kernel pointers.

use std::collections::HashSet;

/// Resolved kprobe targets for CQ jitter measurement.
#[derive(Debug, Clone)]
pub struct KprobeTargets {
    /// Function to kprobe for WR submission (captures submit timestamp).
    pub wr_submit: Option<String>,
    /// Function to kprobe for CQ poll (computes completion latency).
    pub cq_poll: Option<String>,
}

impl KprobeTargets {
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.wr_submit.is_some() && self.cq_poll.is_some()
    }

    #[must_use]
    pub fn driver_name(&self) -> &str {
        if let Some(ref f) = self.cq_poll {
            if f.starts_with("mlx5") {
                return "mlx5";
            }
            if f.starts_with("rxe") {
                return "rxe";
            }
        }
        "unknown"
    }
}

/// Preferred kprobe targets, ordered by priority (mlx5 first, rxe fallback).
const SUBMIT_CANDIDATES: &[&str] = &["mlx5_ib_post_send", "rxe_post_send"];
const POLL_CANDIDATES: &[&str] = &["mlx5_ib_poll_cq", "rxe_poll_cq"];

/// Scan /proc/kallsyms and resolve kprobe targets.
/// Returns targets with the highest-priority available functions.
pub fn discover_kprobe_targets() -> KprobeTargets {
    let available = read_kallsyms_functions();

    let wr_submit = SUBMIT_CANDIDATES
        .iter()
        .find(|&&f| available.contains(f))
        .map(|&s| s.to_string());

    let cq_poll = POLL_CANDIDATES
        .iter()
        .find(|&&f| available.contains(f))
        .map(|&s| s.to_string());

    if let (Some(ref submit), Some(ref poll)) = (&wr_submit, &cq_poll) {
        tracing::info!(submit, poll, "CQ jitter kprobe targets resolved");
    } else {
        tracing::info!(
            ?wr_submit,
            ?cq_poll,
            "CQ jitter kprobes not fully available — micro-stall detection disabled"
        );
    }

    KprobeTargets { wr_submit, cq_poll }
}

fn read_kallsyms_functions() -> HashSet<String> {
    let mut funcs = HashSet::new();

    let content = match std::fs::read_to_string("/proc/kallsyms") {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cannot read /proc/kallsyms: {e}");
            return funcs;
        }
    };

    for line in content.lines() {
        // Format: "address type name [module]"
        let mut parts = line.split_whitespace();
        let _addr = parts.next();
        let sym_type = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("");

        // Only consider text (function) symbols
        if matches!(sym_type, "t" | "T") && !name.is_empty() {
            funcs.insert(name.to_string());
        }
    }

    funcs
}

/// Resolved struct field offsets for kprobe kernel memory reads.
#[derive(Debug, Clone)]
pub struct KprobeFieldOffsets {
    /// Byte offset of `qp_num` (u32) within `struct ib_qp`.
    pub ib_qp_qp_num: Option<u32>,
    /// Byte offset of `qp` (struct ib_qp *) within `struct ib_wc`.
    pub ib_wc_qp: Option<u32>,
    /// Byte offset of `qp_num` (u32) within `struct ib_qp`, accessed via
    /// the `wc->qp` pointer chain. Equal to `ib_qp_qp_num`.
    pub ib_wc_qp_num_via_qp: Option<u32>,
}

/// Discover struct field offsets needed by CQ jitter kprobes.
///
/// Tries BTF first (`/sys/kernel/btf/vmlinux`), then falls back to a table
/// of known offsets indexed by kernel version. Returns None for fields that
/// can't be resolved — the eBPF probes will gracefully skip those reads.
pub fn discover_kprobe_field_offsets() -> KprobeFieldOffsets {
    // Try pahole/BTF-style discovery via /sys/kernel/btf/vmlinux
    if let Some(offsets) = try_btf_discovery() {
        return offsets;
    }

    // Fallback: use kernel version to pick known offsets
    if let Some(offsets) = try_kernel_version_fallback() {
        return offsets;
    }

    tracing::warn!(
        "could not discover ib_qp/ib_wc field offsets from BTF or kernel version — \
         CQ jitter kprobes will not extract QP numbers"
    );
    KprobeFieldOffsets {
        ib_qp_qp_num: None,
        ib_wc_qp: None,
        ib_wc_qp_num_via_qp: None,
    }
}

/// Parse BTF from /sys/kernel/btf/vmlinux using `pahole` if available,
/// or read raw BTF structs. For robustness we shell out to `pahole` which
/// is commonly installed on IB-capable systems.
fn try_btf_discovery() -> Option<KprobeFieldOffsets> {
    let qp_num_off = run_pahole_field_offset("ib_qp", "qp_num")?;
    let wc_qp_off = run_pahole_field_offset("ib_wc", "qp");

    tracing::info!(
        ib_qp_qp_num = qp_num_off,
        ib_wc_qp = ?wc_qp_off,
        "BTF field offsets discovered via pahole"
    );

    Some(KprobeFieldOffsets {
        ib_qp_qp_num: Some(qp_num_off),
        ib_wc_qp: wc_qp_off,
        ib_wc_qp_num_via_qp: Some(qp_num_off),
    })
}

/// Run `pahole -C <struct_name> /sys/kernel/btf/vmlinux` and parse the offset
/// of a specific field. Returns the byte offset or None if not found.
fn run_pahole_field_offset(struct_name: &str, field_name: &str) -> Option<u32> {
    let output = std::process::Command::new("pahole")
        .args(["-C", struct_name, "/sys/kernel/btf/vmlinux"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // pahole output lines look like:
    //   u32  qp_num;     /*   200     4 */
    //   struct ib_qp *     qp;     /*    40     8 */
    // We want the number after "/*" which is the byte offset.
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.contains(field_name) {
            continue;
        }
        // Check this is actually the field declaration (contains the field name
        // as a discrete token before the semicolon)
        if let Some(before_semi) = trimmed.split(';').next() {
            let tokens: Vec<&str> = before_semi.split_whitespace().collect();
            if tokens.last().map_or(false, |&t| t == field_name) {
                // Parse offset from the /* offset  size */ comment
                if let Some(comment_start) = trimmed.find("/*") {
                    let after = &trimmed[comment_start + 2..];
                    let offset_str = after.trim().split_whitespace().next()?;
                    if let Ok(off) = offset_str.parse::<u32>() {
                        return Some(off);
                    }
                }
            }
        }
    }
    None
}

/// Fallback offset table indexed by kernel version.
///
/// Tries RHEL-specific detection first (parsing the `.el8`/`.el9`/`.el10` suffix
/// and build number from osrelease), then falls back to upstream major.minor.
/// RHEL kernels ship heavily backported code under old version numbers, so
/// upstream offsets are wrong — e.g. RHEL 8's `4.18.0-305` has different struct
/// layouts than upstream `4.18`.
fn try_kernel_version_fallback() -> Option<KprobeFieldOffsets> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let release = release.trim();

    if let Some(offsets) = try_rhel_offsets(release) {
        return Some(offsets);
    }

    let (major, minor) = parse_kernel_version(release)?;

    tracing::info!(
        kernel = release,
        major,
        minor,
        "using upstream kernel version fallback for struct offsets"
    );

    // struct ib_qp.qp_num offset by upstream kernel version:
    //   5.15: 200   (Tegra, Ubuntu 22.04 HWE)
    //   6.1:  208   (Amazon Linux 2023)
    //   6.5+: 216   (Ubuntu 23.10+, upstream)
    //   6.8+: 224   (Ubuntu 24.04)
    //
    // struct ib_wc.qp offset:
    //   Stable across all versions at offset 40 (pointer, 8 bytes on 64-bit).
    let qp_num_off = match (major, minor) {
        (5, 0..=15) => 200,
        (5, 16..=19) => 200,
        (6, 0..=1) => 208,
        (6, 2..=4) => 208,
        (6, 5..=7) => 216,
        (6, 8..) => 224,
        _ => {
            tracing::warn!(
                major,
                minor,
                "unknown kernel version for ib_qp.qp_num offset"
            );
            return None;
        }
    };

    Some(KprobeFieldOffsets {
        ib_qp_qp_num: Some(qp_num_off),
        ib_wc_qp: Some(40),
        ib_wc_qp_num_via_qp: Some(qp_num_off),
    })
}

/// RHEL-specific offset resolution from kernel release string.
///
/// RHEL kernels encode the distro release in the osrelease string:
///   `4.18.0-305.el8.x86_64`  → RHEL 8.4  (build 305)
///   `4.18.0-553.el8.x86_64`  → RHEL 8.10 (build 553)
///   `5.14.0-70.el9.x86_64`   → RHEL 9.0  (build 70)
///   `5.14.0-503.el9.x86_64`  → RHEL 9.5  (build 503)
///   `6.x.0-*.el10.x86_64`    → RHEL 10
///
/// The struct layout depends on the backport set, not the base kernel version.
fn try_rhel_offsets(release: &str) -> Option<KprobeFieldOffsets> {
    let rhel_ver = parse_rhel_suffix(release)?;
    let build = parse_rhel_build_number(release).unwrap_or(0);

    tracing::info!(
        kernel = release,
        rhel = rhel_ver,
        build,
        "using RHEL-specific kernel offset table"
    );

    // RHEL struct ib_qp.qp_num offsets (derived from RHEL kernel source RPMs).
    // RHEL backports struct changes across minor releases, so the offset
    // varies by build number even though the base version stays at 4.18/5.14.
    //
    // struct ib_wc.qp is stable at 40 across all RHEL versions.
    let qp_num_off = match rhel_ver {
        8 => {
            // RHEL 8 base kernel: 4.18.0
            // 8.0-8.3 (builds < 305): pre-backport layout
            // 8.4+    (builds >= 305): backported from 5.x
            if build < 305 { 192 } else { 200 }
        }
        9 => {
            // RHEL 9 base kernel: 5.14.0
            // 9.0 (build 70) through 9.2 (build 162): initial layout
            // 9.3+ (build >= 362): aligned with upstream 6.1 changes
            if build < 362 { 200 } else { 208 }
        }
        10 => {
            // RHEL 10 base kernel: 6.x — use upstream 6.8+ offsets
            224
        }
        _ => {
            tracing::warn!(rhel = rhel_ver, "unknown RHEL version for struct offsets");
            return None;
        }
    };

    Some(KprobeFieldOffsets {
        ib_qp_qp_num: Some(qp_num_off),
        ib_wc_qp: Some(40),
        ib_wc_qp_num_via_qp: Some(qp_num_off),
    })
}

/// Extract RHEL version number from kernel release (e.g. "el8" → 8, "el9" → 9).
fn parse_rhel_suffix(release: &str) -> Option<u32> {
    let idx = release.find(".el")?;
    let after = &release[idx + 3..];
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Extract the RHEL build number from kernel release.
/// e.g. "4.18.0-305.el8.x86_64" → 305, "5.14.0-70.22.1.el9_0.x86_64" → 70
fn parse_rhel_build_number(release: &str) -> Option<u32> {
    let dash_idx = release.find('-')?;
    let after_dash = &release[dash_idx + 1..];
    let digits: String = after_dash
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_str = parts.next()?;
    // minor might be "15" or "15-tegra" — take only digits
    let minor_digits: String = minor_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let minor: u32 = minor_digits.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_available_when_both_present() {
        let t = KprobeTargets {
            wr_submit: Some("mlx5_ib_post_send".into()),
            cq_poll: Some("mlx5_ib_poll_cq".into()),
        };
        assert!(t.is_available());
        assert_eq!(t.driver_name(), "mlx5");
    }

    #[test]
    fn targets_unavailable_when_partial() {
        let t = KprobeTargets {
            wr_submit: Some("mlx5_ib_post_send".into()),
            cq_poll: None,
        };
        assert!(!t.is_available());
    }

    #[test]
    fn rxe_driver_detected() {
        let t = KprobeTargets {
            wr_submit: Some("rxe_post_send".into()),
            cq_poll: Some("rxe_poll_cq".into()),
        };
        assert_eq!(t.driver_name(), "rxe");
    }

    #[test]
    fn parse_kernel_version_standard() {
        assert_eq!(parse_kernel_version("5.15.148-tegra"), Some((5, 15)));
        assert_eq!(parse_kernel_version("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_version("6.1.0"), Some((6, 1)));
    }

    #[test]
    fn parse_kernel_version_invalid() {
        assert_eq!(parse_kernel_version("not-a-version"), None);
        assert_eq!(parse_kernel_version(""), None);
    }

    #[test]
    fn rhel_suffix_extraction() {
        assert_eq!(parse_rhel_suffix("4.18.0-305.el8.x86_64"), Some(8));
        assert_eq!(parse_rhel_suffix("5.14.0-70.22.1.el9_0.x86_64"), Some(9));
        assert_eq!(parse_rhel_suffix("6.2.0-100.el10.x86_64"), Some(10));
        assert_eq!(parse_rhel_suffix("5.15.148-tegra"), None);
        assert_eq!(parse_rhel_suffix("6.8.0-45-generic"), None);
    }

    #[test]
    fn rhel_build_number_extraction() {
        assert_eq!(
            parse_rhel_build_number("4.18.0-305.el8.x86_64"),
            Some(305)
        );
        assert_eq!(
            parse_rhel_build_number("4.18.0-553.el8.x86_64"),
            Some(553)
        );
        assert_eq!(
            parse_rhel_build_number("5.14.0-70.22.1.el9_0.x86_64"),
            Some(70)
        );
        assert_eq!(
            parse_rhel_build_number("5.14.0-503.el9.x86_64"),
            Some(503)
        );
        assert_eq!(parse_rhel_build_number("5.15.148-tegra"), Some(148));
    }

    #[test]
    fn rhel8_offsets() {
        let off = try_rhel_offsets("4.18.0-240.el8.x86_64");
        assert!(off.is_some());
        assert_eq!(off.unwrap().ib_qp_qp_num, Some(192));

        let off = try_rhel_offsets("4.18.0-305.el8.x86_64");
        assert!(off.is_some());
        assert_eq!(off.unwrap().ib_qp_qp_num, Some(200));

        let off = try_rhel_offsets("4.18.0-553.el8.x86_64");
        assert!(off.is_some());
        assert_eq!(off.unwrap().ib_qp_qp_num, Some(200));
    }

    #[test]
    fn rhel9_offsets() {
        let off = try_rhel_offsets("5.14.0-70.el9.x86_64");
        assert!(off.is_some());
        assert_eq!(off.unwrap().ib_qp_qp_num, Some(200));

        let off = try_rhel_offsets("5.14.0-362.el9.x86_64");
        assert!(off.is_some());
        assert_eq!(off.unwrap().ib_qp_qp_num, Some(208));
    }

    #[test]
    fn non_rhel_skips() {
        assert!(try_rhel_offsets("6.8.0-45-generic").is_none());
        assert!(try_rhel_offsets("5.15.148-tegra").is_none());
    }
}
