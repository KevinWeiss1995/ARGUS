//! `argus-probe`: lightweight peer-liveness prober.
//!
//! Pingmesh-style: connects to a configured list of peers over TCP and
//! records the connect-time RTT. Writes a JSON snapshot to `--out` so the
//! main agent's `PeerLivenessProvider` can consume it.
//!
//! Why TCP, not RDMA? Doing real RDMA UD pings requires linking
//! `libibverbs` and creating QPs at runtime — an order-of-magnitude bigger
//! commit than this scaffold warrants. TCP RTT to the peer's argus-agent
//! port is a reasonable proxy: the agent runs on the same kernel, and a
//! sudden RTT increase to a peer almost always co-occurs with RDMA fabric
//! issues. For RDMA-direct probing this binary can be extended later.

#![deny(unsafe_code)]
#![warn(clippy::pedantic)]

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "argus-probe", about = "Pingmesh-style peer-liveness prober for ARGUS")]
struct Cli {
    /// Comma-separated list of peer addresses (host:port).
    #[arg(long)]
    peers: String,

    /// Output JSON path (atomic write).
    #[arg(long, default_value = "/var/run/argus/probe.json")]
    out: PathBuf,

    /// Per-probe timeout in milliseconds.
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,

    /// Loop interval. 0 = single-shot probe and exit.
    #[arg(long, default_value_t = 30)]
    interval_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeResult {
    pub peer: String,
    pub rtt_us: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeSnapshot {
    pub timestamp_unix: u64,
    pub interval_secs: u64,
    pub results: Vec<ProbeResult>,
}

fn probe_peer(peer: &str, timeout: Duration) -> ProbeResult {
    let addr = match peer.to_socket_addrs().ok().and_then(|mut it| it.next()) {
        Some(a) => a,
        None => {
            return ProbeResult {
                peer: peer.into(),
                rtt_us: None,
                error: Some("address resolution failed".into()),
            };
        }
    };
    let started = Instant::now();
    match std::net::TcpStream::connect_timeout(&addr, timeout) {
        Ok(_stream) => {
            let elapsed = started.elapsed().as_micros() as u64;
            ProbeResult {
                peer: peer.into(),
                rtt_us: Some(elapsed),
                error: None,
            }
        }
        Err(e) => ProbeResult {
            peer: peer.into(),
            rtt_us: None,
            error: Some(e.to_string()),
        },
    }
}

fn write_atomic(path: &std::path::Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let timeout = Duration::from_millis(cli.timeout_ms);
    let peers: Vec<String> = cli
        .peers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if peers.is_empty() {
        eprintln!("no peers configured");
        std::process::exit(1);
    }

    loop {
        let mut results = Vec::with_capacity(peers.len());
        for peer in &peers {
            results.push(probe_peer(peer, timeout));
        }
        let snap = ProbeSnapshot {
            timestamp_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            interval_secs: cli.interval_secs,
            results,
        };
        let body = serde_json::to_vec_pretty(&snap)?;
        if let Err(e) = write_atomic(&cli.out, &body) {
            eprintln!("warn: failed to write probe snapshot: {e}");
        }

        if cli.interval_secs == 0 {
            // Print to stdout for one-shot use.
            println!("{}", String::from_utf8_lossy(&body));
            break;
        }
        std::thread::sleep(Duration::from_secs(cli.interval_secs));
    }
    Ok(())
}
