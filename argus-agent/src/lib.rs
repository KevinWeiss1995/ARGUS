#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

// ---------------------------------------------------------------------------
// Structured logging convention
// ---------------------------------------------------------------------------
// All `tracing::{info,warn,error}!` calls should include a `component` field
// at module entry points to enable operators to filter logs by subsystem.
//
// Standard component values:
//   "agent"     — main daemon lifecycle (startup, shutdown, PID lock)
//   "detection" — health scoring, state machine, rules
//   "ebpf"      — eBPF probe loading, attachment, ring buffer
//   "metrics"   — Prometheus exporter, HTTP server, /health, /status
//   "scheduler" — Slurm/noop backend, drain/resume, reconciliation
//   "actions"   — webhook, port-disable, autonomous actions
//   "security"  — seccomp, capabilities, TLS
//   "tui"       — terminal dashboard

pub mod actions;
pub mod capabilities;
pub mod config;
pub mod detection;
pub mod pipeline;
pub mod scheduler;
pub mod security;
pub mod sources;
pub mod telemetry;
pub mod tui;
