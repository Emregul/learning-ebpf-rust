#![no_std]
#![no_main]

use aya_bpf::{macros::xdp, programs::XdpContext, bindings::xdp_action::XDP_PASS};
use aya_log_ebpf::info;

static mut COUNTER: u32 = 0;

#[xdp(name = "hello")]
pub fn hello(ctx: XdpContext) -> u32 {
    unsafe {
        info!(&ctx, "Hello world {}",  COUNTER);
        COUNTER += 1;
    }

    XDP_PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

