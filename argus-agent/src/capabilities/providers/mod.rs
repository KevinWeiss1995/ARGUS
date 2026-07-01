//! Concrete capability providers.
//!
//! Each module implements one or more `CapabilityProvider`s. Selection is
//! handled by `CapabilityRegistry`; this module is essentially a registry
//! of factory functions that wire defaults for each fabric.

pub mod completion_latency;
pub mod link_errors;
pub mod peer_liveness;
pub mod pfc_ecn;
pub mod qp_attribution;
pub mod retransmit;
pub mod throughput;

use crate::capabilities::{CapabilityProvider, FabricEnv};

/// Default candidate set: every provider this build supports, in arbitrary
/// order. The registry probes and picks the best per capability.
#[must_use]
pub fn default_candidates(_env: &FabricEnv) -> Vec<Box<dyn CapabilityProvider>> {
    vec![
        // LinkErrors: sysfs (universal) + inferred fallback.
        Box::new(link_errors::SysfsLinkErrorsProvider::new()),
        Box::new(link_errors::InferredLinkErrorsProvider::new()),
        // Throughput: sysfs (universal).
        Box::new(throughput::SysfsThroughputProvider::new()),
        // CompletionLatency: ebpf (high) → sysfs proxy (low).
        Box::new(completion_latency::EbpfCqLatencyProvider::new()),
        Box::new(completion_latency::ThroughputProxyLatencyProvider::new()),
        // RetransmitSignal: ebpf (high) → MAD/IB (medium) → sysfs (medium) → inferred (low).
        Box::new(retransmit::EbpfRetransmitProvider::new()),
        Box::new(retransmit::MadRetransmitProvider::new()),
        Box::new(retransmit::SysfsRetransmitProvider::new()),
        Box::new(retransmit::InferredRetransmitProvider::new()),
        // QpAttribution: ebpf (high) → rdma-core netlink (medium) → sysfs/rxe (medium).
        Box::new(qp_attribution::EbpfQpAttributionProvider::new()),
        Box::new(qp_attribution::RdmaCoreQpAttributionProvider::new()),
        Box::new(qp_attribution::SysfsRxeQpAttributionProvider::new()),
        // PfcPause / EcnMarks / CnpRate: ethtool (high) → inferred (low) on softroce/IB.
        Box::new(pfc_ecn::EthtoolPfcProvider::new()),
        Box::new(pfc_ecn::InferredPfcProvider::new()),
        Box::new(pfc_ecn::EthtoolEcnProvider::new()),
        Box::new(pfc_ecn::EthtoolCnpProvider::new()),
        // PeerLiveness: optional, requires argus-probe to be running and writing snapshots.
        Box::new(peer_liveness::PeerLivenessProvider::new()),
    ]
}
