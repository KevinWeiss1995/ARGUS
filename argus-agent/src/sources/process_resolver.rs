//! Resolve PID → process name, job ID, and cgroup for blast radius attribution.
//!
//! When ARGUS detects degradation, it answers "who is affected?" by mapping
//! QP numbers → PIDs (from BPF) → process metadata (from /proc).
//! Results are cached and refreshed periodically to avoid per-event /proc reads.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Metadata about a process using RDMA.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String,
    pub slurm_job_id: Option<String>,
    pub k8s_pod: Option<String>,
    pub gpu_devices: Option<String>,
}

/// Blast radius summary attached to alerts.
#[derive(Debug, Clone, Default)]
pub struct BlastRadius {
    pub affected: Vec<ProcessInfo>,
}

impl BlastRadius {
    #[must_use]
    pub fn summary(&self) -> String {
        if self.affected.is_empty() {
            return "no affected processes identified".into();
        }
        self.affected
            .iter()
            .map(|p| {
                let mut desc = format!("PID {} ({})", p.pid, p.comm);
                if let Some(ref job) = p.slurm_job_id {
                    desc.push_str(&format!(" — SLURM #{job}"));
                }
                if let Some(ref pod) = p.k8s_pod {
                    desc.push_str(&format!(" — k8s {pod}"));
                }
                desc
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.affected.is_empty()
    }
}

/// Resolves PIDs to process metadata, with a TTL-based cache.
pub struct ProcessResolver {
    cache: HashMap<u32, CachedProcess>,
    cache_ttl: Duration,
}

struct CachedProcess {
    info: ProcessInfo,
    fetched_at: Instant,
}

impl ProcessResolver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            cache_ttl: Duration::from_secs(30),
        }
    }

    /// Given a QP→PID map (from BPF), resolve all unique PIDs and return
    /// a blast radius summary.
    pub fn resolve_blast_radius(&mut self, qp_owners: &HashMap<u32, u32>) -> BlastRadius {
        let now = Instant::now();
        let unique_pids: std::collections::HashSet<u32> = qp_owners.values().copied().collect();
        let mut affected = Vec::new();

        for &pid in &unique_pids {
            let info = self.resolve_pid(pid, now);
            if let Some(info) = info {
                affected.push(info);
            }
        }

        BlastRadius { affected }
    }

    fn resolve_pid(&mut self, pid: u32, now: Instant) -> Option<ProcessInfo> {
        if let Some(cached) = self.cache.get(&pid) {
            if now.duration_since(cached.fetched_at) < self.cache_ttl {
                return Some(cached.info.clone());
            }
        }

        let info = read_process_info(pid)?;
        self.cache.insert(
            pid,
            CachedProcess {
                info: info.clone(),
                fetched_at: now,
            },
        );
        Some(info)
    }

    /// Evict stale entries to prevent unbounded growth.
    pub fn gc(&mut self) {
        let now = Instant::now();
        self.cache
            .retain(|_, v| now.duration_since(v.fetched_at) < self.cache_ttl * 3);
    }
}

impl Default for ProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

fn read_process_info(pid: u32) -> Option<ProcessInfo> {
    let proc_dir = format!("/proc/{pid}");
    if !std::path::Path::new(&proc_dir).exists() {
        return None;
    }

    let comm = std::fs::read_to_string(format!("{proc_dir}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "<unknown>".into());

    let cgroup_content = std::fs::read_to_string(format!("{proc_dir}/cgroup")).unwrap_or_default();
    let slurm_job_id = extract_slurm_job_id(&cgroup_content);
    let k8s_pod = extract_k8s_pod(&cgroup_content);

    let environ = std::fs::read_to_string(format!("{proc_dir}/environ")).unwrap_or_default();
    let gpu_devices = extract_env_var(&environ, "CUDA_VISIBLE_DEVICES");

    // Also check environ for SLURM_JOB_ID as a fallback
    let slurm_job_id = slurm_job_id.or_else(|| extract_env_var(&environ, "SLURM_JOB_ID"));

    Some(ProcessInfo {
        pid,
        comm,
        slurm_job_id,
        k8s_pod,
        gpu_devices,
    })
}

fn extract_slurm_job_id(cgroup: &str) -> Option<String> {
    // Look for /slurm/uid_*/job_NNN or similar patterns
    for line in cgroup.lines() {
        if let Some(pos) = line.find("job_") {
            let rest = &line[pos + 4..];
            let id: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !id.is_empty() {
                return Some(id);
            }
        }
    }
    None
}

fn extract_k8s_pod(cgroup: &str) -> Option<String> {
    // Look for /kubepods/ or /pod<uuid> patterns
    for line in cgroup.lines() {
        if let Some(pos) = line.find("/pod") {
            let rest = &line[pos + 4..];
            let pod_id: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !pod_id.is_empty() {
                return Some(pod_id);
            }
        }
    }
    None
}

fn extract_env_var(environ: &str, key: &str) -> Option<String> {
    // /proc/*/environ uses \0 as separator
    let prefix = format!("{key}=");
    for entry in environ.split('\0') {
        if let Some(val) = entry.strip_prefix(&prefix) {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blast_radius_summary_empty() {
        let br = BlastRadius::default();
        assert!(br.is_empty());
        assert_eq!(br.summary(), "no affected processes identified");
    }

    #[test]
    fn blast_radius_summary_with_processes() {
        let br = BlastRadius {
            affected: vec![
                ProcessInfo {
                    pid: 1234,
                    comm: "python3".into(),
                    slurm_job_id: Some("402".into()),
                    k8s_pod: None,
                    gpu_devices: Some("0,1".into()),
                },
                ProcessInfo {
                    pid: 5678,
                    comm: "nccl_test".into(),
                    slurm_job_id: None,
                    k8s_pod: Some("training-pod-abc".into()),
                    gpu_devices: None,
                },
            ],
        };
        let s = br.summary();
        assert!(s.contains("PID 1234"));
        assert!(s.contains("SLURM #402"));
        assert!(s.contains("k8s training-pod-abc"));
    }

    #[test]
    fn extract_slurm_from_cgroup() {
        let cgroup = "12:memory:/slurm/uid_1000/job_12345/step_0\n";
        assert_eq!(extract_slurm_job_id(cgroup), Some("12345".into()));
    }

    #[test]
    fn extract_slurm_missing() {
        assert_eq!(extract_slurm_job_id("0::/user.slice\n"), None);
    }

    #[test]
    fn extract_k8s_pod_from_cgroup() {
        let cgroup = "0::/kubepods/burstable/podabc-def-123/container\n";
        assert_eq!(extract_k8s_pod(cgroup), Some("abc-def-123".into()));
    }

    #[test]
    fn extract_env() {
        let environ = "PATH=/usr/bin\0CUDA_VISIBLE_DEVICES=0,1\0HOME=/root\0";
        assert_eq!(
            extract_env_var(environ, "CUDA_VISIBLE_DEVICES"),
            Some("0,1".into())
        );
        assert_eq!(extract_env_var(environ, "NONEXISTENT"), None);
    }
}
