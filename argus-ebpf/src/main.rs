#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod slab;
mod interrupts;
mod rdma;

use aya_ebpf::{macros::map, maps::RingBuf};

/// Shared ring buffer for all event types. Userspace reads events tagged by type.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
