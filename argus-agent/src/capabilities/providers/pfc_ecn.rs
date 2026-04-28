//! PfcPause / EcnMarks / CnpRate capabilities.
//!
//! These are **RoCE-only** in their meaningful form:
//!   - InfiniBand uses CBFC, not PFC; PFC samples report Quality::Absent.
//!   - rxe (Soft-RoCE) doesn't run a PFC layer; PFC samples Absent there too.
//!   - On RoCEv2, ethtool exposes `prio[0..7]_*_xoff` and ECN-related keys
//!     in driver-private stats.
//!
//! Because this build doesn't yet link `ethtool-rs` or call the IOCTLs
//! directly, the ethtool providers probe `Unavailable` and we fall through
//! to the inferred provider. The structure is in place to swap real
//! implementations in without touching the registry.

use crate::capabilities::{
    CapabilityProvider, DetectionContext, FabricEnv, FabricKind, ProbeOutcome,
};
use argus_common::{BackendId, Capability, Quality, Sample};

pub struct EthtoolPfcProvider;

impl EthtoolPfcProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for EthtoolPfcProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for EthtoolPfcProvider {
    fn id(&self) -> BackendId {
        BackendId::EthtoolPfc
    }
    fn capability(&self) -> Capability {
        Capability::PfcPause
    }
    fn declared_quality(&self) -> Quality {
        Quality::High
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        // PFC is meaningless on IB / softroce; declare Unavailable so the
        // capability ends up Absent on those fabrics rather than picking
        // up the inferred fallback (which itself probes Unavailable on IB).
        if matches!(env.fabric, Some(FabricKind::InfiniBand) | Some(FabricKind::SoftRoCE)) {
            return ProbeOutcome::Unavailable {
                reason: "PFC not applicable to IB/softroce".into(),
            };
        }
        // ethtool integration not yet wired.
        ProbeOutcome::Unavailable {
            reason: "ethtool PFC backend not implemented (scaffold)".into(),
        }
    }
    fn collect(&mut self, _ctx: &DetectionContext<'_>) -> Vec<Sample> {
        vec![]
    }
}

pub struct InferredPfcProvider;

impl InferredPfcProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for InferredPfcProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for InferredPfcProvider {
    fn id(&self) -> BackendId {
        BackendId::PfcInference
    }
    fn capability(&self) -> Capability {
        Capability::PfcPause
    }
    fn declared_quality(&self) -> Quality {
        Quality::Low
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        // Only meaningful when PFC could exist. On IB/softroce, PFC is
        // structurally absent — don't pretend to infer it.
        if matches!(env.fabric, Some(FabricKind::InfiniBand) | Some(FabricKind::SoftRoCE)) {
            return ProbeOutcome::Unavailable {
                reason: "PFC structurally absent on IB/softroce".into(),
            };
        }
        ProbeOutcome::Available {
            quality: Quality::Low,
        }
    }
    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        // Inference signal: high port_xmit_wait with low error count
        // suggests pause-frame backpressure rather than corruption.
        let d = &ctx.metrics.ib_counter_deltas;
        let wait = d.port_xmit_wait_delta as f64;
        let err = d.total_hard_error_delta() as f64;
        if wait < 1.0 {
            return vec![];
        }
        let value = if err < 1.0 { wait } else { 0.0 };
        let conf = if value > 0.0 { 0.3 } else { 0.05 };
        vec![Sample {
            capability: Capability::PfcPause,
            value,
            confidence: conf,
            quality: Quality::Low,
            origin: BackendId::PfcInference,
            timestamp_ns: ctx.timestamp_ns,
            qp_num: None,
            port: None,
            priority: None,
            device: None,
        }]
    }
}

pub struct EthtoolEcnProvider;

impl EthtoolEcnProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for EthtoolEcnProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for EthtoolEcnProvider {
    fn id(&self) -> BackendId {
        BackendId::EthtoolEcn
    }
    fn capability(&self) -> Capability {
        Capability::EcnMarks
    }
    fn declared_quality(&self) -> Quality {
        Quality::High
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        if matches!(env.fabric, Some(FabricKind::InfiniBand) | Some(FabricKind::SoftRoCE)) {
            return ProbeOutcome::Unavailable {
                reason: "ECN/CNP not applicable to IB/softroce".into(),
            };
        }
        ProbeOutcome::Unavailable {
            reason: "ethtool ECN backend not implemented (scaffold)".into(),
        }
    }
    fn collect(&mut self, _ctx: &DetectionContext<'_>) -> Vec<Sample> {
        vec![]
    }
}

pub struct EthtoolCnpProvider;

impl EthtoolCnpProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for EthtoolCnpProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for EthtoolCnpProvider {
    fn id(&self) -> BackendId {
        BackendId::EthtoolCnp
    }
    fn capability(&self) -> Capability {
        Capability::CnpRate
    }
    fn declared_quality(&self) -> Quality {
        Quality::High
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        if matches!(env.fabric, Some(FabricKind::InfiniBand) | Some(FabricKind::SoftRoCE)) {
            return ProbeOutcome::Unavailable {
                reason: "ECN/CNP not applicable to IB/softroce".into(),
            };
        }
        ProbeOutcome::Unavailable {
            reason: "ethtool CNP backend not implemented (scaffold)".into(),
        }
    }
    fn collect(&mut self, _ctx: &DetectionContext<'_>) -> Vec<Sample> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::FabricEnv;

    #[test]
    fn pfc_unavailable_on_infiniband() {
        let mut env = FabricEnv::synthetic();
        env.fabric = Some(FabricKind::InfiniBand);
        let mut p = EthtoolPfcProvider::new();
        match p.probe(&env) {
            ProbeOutcome::Unavailable { .. } => (),
            _ => panic!("PFC must be unavailable on InfiniBand"),
        }
    }

    #[test]
    fn inferred_pfc_unavailable_on_softroce() {
        let env = FabricEnv::synthetic();
        let mut p = InferredPfcProvider::new();
        match p.probe(&env) {
            ProbeOutcome::Unavailable { .. } => (),
            _ => panic!("inferred PFC must be unavailable on softroce"),
        }
    }

    #[test]
    fn ecn_unavailable_on_infiniband() {
        let mut env = FabricEnv::synthetic();
        env.fabric = Some(FabricKind::InfiniBand);
        let mut p = EthtoolEcnProvider::new();
        match p.probe(&env) {
            ProbeOutcome::Unavailable { .. } => (),
            _ => panic!("ECN must be unavailable on InfiniBand"),
        }
    }
}
