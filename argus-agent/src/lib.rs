#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// Telemetry code converts between counter (u64), gauge (i64), and ratio (f64)
// domains constantly; values stay far below the lossy ranges (2^52 for f64
// mantissa, 2^63 for i64), so the numeric-conversion pedantic lints are noise
// here rather than signal.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
// Internal daemon crate — exhaustive `# Errors`/`# Panics` doc sections and
// 100-line function limits are not enforced; this is not a published API.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
// Nursery lint with poor readability trade-offs in this codebase.
#![allow(clippy::option_if_let_else)]

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
