//! Parsers for raw ring buffer bytes from eBPF probes.
//!
//! These are extracted from the eBPF event source so they can be unit-tested
//! and fuzz-tested without a Linux kernel or eBPF programs.

use argus_common::*;

pub const EVENT_TYPE_SLAB_ALLOC: u32 = 1;
pub const EVENT_TYPE_SLAB_FREE: u32 = 2;
pub const EVENT_TYPE_IRQ_ENTRY: u32 = 3;
pub const EVENT_TYPE_NAPI_POLL: u32 = 4;

pub fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)
        .map(|b| u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Parse a slab alloc event from raw ring buffer bytes.
/// Layout: event_type(4) + pad(4) + timestamp(8) + cpu(4) + bytes_req(4) + bytes_alloc(4) + pad2(4) + latency(8) = 40 bytes
pub fn parse_slab_alloc(data: &[u8]) -> Option<ArgusEvent> {
    if data.len() < 40 {
        return None;
    }
    Some(ArgusEvent::SlabAlloc(SlabAllocEvent {
        timestamp_ns: read_u64(data, 8)?,
        cpu: read_u32(data, 16)?,
        bytes_req: read_u32(data, 20)?,
        bytes_alloc: read_u32(data, 24)?,
        latency_ns: read_u64(data, 32)?,
        numa_node: 0,
    }))
}

/// Layout: event_type(4) + pad(4) + timestamp(8) + cpu(4) + bytes_freed(4) = 24 bytes
pub fn parse_slab_free(data: &[u8]) -> Option<ArgusEvent> {
    if data.len() < 24 {
        return None;
    }
    Some(ArgusEvent::SlabFree(SlabFreeEvent {
        timestamp_ns: read_u64(data, 8)?,
        cpu: read_u32(data, 16)?,
        bytes_freed: read_u32(data, 20)?,
    }))
}

/// Layout: event_type(4) + pad(4) + timestamp(8) + cpu(4) + irq(4) = 24 bytes
pub fn parse_irq_entry(data: &[u8]) -> Option<ArgusEvent> {
    if data.len() < 24 {
        return None;
    }
    Some(ArgusEvent::IrqEntry(IrqEntryEvent {
        timestamp_ns: read_u64(data, 8)?,
        cpu: read_u32(data, 16)?,
        irq: read_u32(data, 20)?,
        handler_name_hash: 0,
    }))
}

/// Layout: event_type(4) + pad(4) + timestamp(8) + cpu(4) + budget(4) + work_done(4) + pad2(4) = 32 bytes
pub fn parse_napi_poll(data: &[u8]) -> Option<ArgusEvent> {
    if data.len() < 32 {
        return None;
    }
    Some(ArgusEvent::NapiPoll(NapiPollEvent {
        timestamp_ns: read_u64(data, 8)?,
        cpu: read_u32(data, 16)?,
        budget: read_u32(data, 20)?,
        work_done: read_u32(data, 24)?,
        dev_name_hash: 0,
    }))
}

/// Dispatch raw ring buffer data to the appropriate parser based on event type.
pub fn parse_event(data: &[u8]) -> Option<ArgusEvent> {
    if data.len() < 8 {
        return None;
    }
    let event_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    match event_type {
        EVENT_TYPE_SLAB_ALLOC => parse_slab_alloc(data),
        EVENT_TYPE_SLAB_FREE => parse_slab_free(data),
        EVENT_TYPE_IRQ_ENTRY => parse_irq_entry(data),
        EVENT_TYPE_NAPI_POLL => parse_napi_poll(data),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_slab_alloc_bytes(
        ts: u64,
        cpu: u32,
        bytes_req: u32,
        bytes_alloc: u32,
        latency: u64,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        buf[0..4].copy_from_slice(&EVENT_TYPE_SLAB_ALLOC.to_ne_bytes());
        buf[8..16].copy_from_slice(&ts.to_ne_bytes());
        buf[16..20].copy_from_slice(&cpu.to_ne_bytes());
        buf[20..24].copy_from_slice(&bytes_req.to_ne_bytes());
        buf[24..28].copy_from_slice(&bytes_alloc.to_ne_bytes());
        buf[32..40].copy_from_slice(&latency.to_ne_bytes());
        buf
    }

    fn make_irq_entry_bytes(ts: u64, cpu: u32, irq: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&EVENT_TYPE_IRQ_ENTRY.to_ne_bytes());
        buf[8..16].copy_from_slice(&ts.to_ne_bytes());
        buf[16..20].copy_from_slice(&cpu.to_ne_bytes());
        buf[20..24].copy_from_slice(&irq.to_ne_bytes());
        buf
    }

    fn make_napi_poll_bytes(ts: u64, cpu: u32, budget: u32, work_done: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&EVENT_TYPE_NAPI_POLL.to_ne_bytes());
        buf[8..16].copy_from_slice(&ts.to_ne_bytes());
        buf[16..20].copy_from_slice(&cpu.to_ne_bytes());
        buf[20..24].copy_from_slice(&budget.to_ne_bytes());
        buf[24..28].copy_from_slice(&work_done.to_ne_bytes());
        buf
    }

    fn make_slab_free_bytes(ts: u64, cpu: u32, bytes_freed: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&EVENT_TYPE_SLAB_FREE.to_ne_bytes());
        buf[8..16].copy_from_slice(&ts.to_ne_bytes());
        buf[16..20].copy_from_slice(&cpu.to_ne_bytes());
        buf[20..24].copy_from_slice(&bytes_freed.to_ne_bytes());
        buf
    }

    #[test]
    fn parse_slab_alloc_valid() {
        let data = make_slab_alloc_bytes(1000, 2, 64, 128, 500);
        let event = parse_event(&data).unwrap();
        if let ArgusEvent::SlabAlloc(e) = event {
            assert_eq!(e.timestamp_ns, 1000);
            assert_eq!(e.cpu, 2);
            assert_eq!(e.bytes_req, 64);
            assert_eq!(e.bytes_alloc, 128);
            assert_eq!(e.latency_ns, 500);
        } else {
            panic!("expected SlabAlloc");
        }
    }

    #[test]
    fn parse_slab_alloc_truncated() {
        let data = vec![0u8; 20]; // too short
        assert!(parse_slab_alloc(&data).is_none());
    }

    #[test]
    fn parse_irq_entry_valid() {
        let data = make_irq_entry_bytes(2000, 3, 42);
        let event = parse_event(&data).unwrap();
        if let ArgusEvent::IrqEntry(e) = event {
            assert_eq!(e.timestamp_ns, 2000);
            assert_eq!(e.cpu, 3);
            assert_eq!(e.irq, 42);
        } else {
            panic!("expected IrqEntry");
        }
    }

    #[test]
    fn parse_napi_poll_valid() {
        let data = make_napi_poll_bytes(3000, 0, 256, 128);
        let event = parse_event(&data).unwrap();
        if let ArgusEvent::NapiPoll(e) = event {
            assert_eq!(e.timestamp_ns, 3000);
            assert_eq!(e.budget, 256);
            assert_eq!(e.work_done, 128);
        } else {
            panic!("expected NapiPoll");
        }
    }

    #[test]
    fn parse_slab_free_valid() {
        let data = make_slab_free_bytes(4000, 1, 512);
        let event = parse_event(&data).unwrap();
        if let ArgusEvent::SlabFree(e) = event {
            assert_eq!(e.timestamp_ns, 4000);
            assert_eq!(e.cpu, 1);
            assert_eq!(e.bytes_freed, 512);
        } else {
            panic!("expected SlabFree");
        }
    }

    #[test]
    fn parse_unknown_event_type() {
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(&99u32.to_ne_bytes());
        assert!(parse_event(&data).is_none());
    }

    #[test]
    fn parse_empty_data() {
        assert!(parse_event(&[]).is_none());
        assert!(parse_event(&[0]).is_none());
        assert!(parse_event(&[0, 0, 0]).is_none());
    }

    #[test]
    fn parse_minimum_size_boundary() {
        // Exact minimum size for slab alloc = 40
        let data = make_slab_alloc_bytes(0, 0, 0, 0, 0);
        assert!(parse_event(&data).is_some());

        // One byte short
        let short = &data[..39];
        assert!(parse_slab_alloc(short).is_none());
    }

    #[test]
    fn read_u32_out_of_bounds() {
        let data = [1u8, 2, 3];
        assert!(read_u32(&data, 0).is_none());
        assert!(read_u32(&data, 1).is_none());
    }

    #[test]
    fn read_u64_out_of_bounds() {
        let data = [1u8, 2, 3, 4, 5, 6, 7];
        assert!(read_u64(&data, 0).is_none());
    }
}
